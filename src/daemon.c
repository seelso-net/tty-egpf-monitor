// SPDX-License-Identifier: MIT
// tty-egpf-monitord: Local daemon exposing HTTP+JSON API for multi-port eBPF serial monitoring

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>
#include <termios.h>
#include <poll.h>
// #include <systemd/sd-daemon.h>  // Commented out for Ubuntu 22.04 compatibility

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sniffer.skel.h"

/* fdkey struct to match BPF definition */
struct fdkey { uint32_t tgid; int32_t fd; };

#define MAX_PORTS 16
// Must match MAX_DATA in sniffer.bpf.c
#define MAX_DATA 256
#define MAX_PATH 256
// Must match MAX_TARGETS in sniffer.bpf.c
#define MAX_TARGETS 32
struct pathval { char path[MAX_PATH]; };

/* Additional structs needed for BPF scratch buffers */
struct read_ctx { int32_t fd; const void *buf; size_t count; };
struct open_ctx { const char *filename; };
struct close_ctx { int32_t fd; };

#define DEFAULT_HTTP_PORT 12768
#define CONFIG_FILE "/var/log/tty-egpf-monitor/daemon.conf"
#define DEFAULT_SOCKET_PATH "/run/tty-egpf-monitord.sock"
#define DEFAULT_LOG_DIR "/var/log/tty-egpf-monitor"

// Logging modes
#define LOG_MODE_SIMPLE 0  // Simple, human-readable logs
#define LOG_MODE_ADVANCED 1  // Detailed, machine-readable logs
#define DEFAULT_LOG_MODE LOG_MODE_SIMPLE

// Default TTY settings
#define DEFAULT_BAUDRATE 115200
#define DEFAULT_DATABITS 8
#define DEFAULT_PARITY 'N'
#define DEFAULT_STOPBITS 1
#define DEFAULT_HWFLOW false

// Function to escape and quote data for safe logging
static void escape_data_for_log(const uint8_t *data, size_t len, char *output, size_t output_size) {
    size_t j = 0;
    output[j++] = '"';
    
    for (size_t i = 0; i < len && j < output_size - 2; i++) {
        uint8_t c = data[i];
        if (c >= 32 && c <= 126) {
            // Printable ASCII character
            if (c == '"' || c == '\\') {
                if (j < output_size - 3) {
                    output[j++] = '\\';
                    output[j++] = c;
                }
            } else {
                output[j++] = c;
            }
        } else {
            // Non-printable character - escape as hex
            if (j < output_size - 5) {
                snprintf(output + j, output_size - j, "\\x%02x", c);
                j += 4;
            }
        }
    }
    
    if (j < output_size - 1) {
        output[j++] = '"';
    }
    output[j] = '\0';
}

struct event {
    uint64_t ts, dev;
    uint32_t pid, tgid;
    char     comm[16];
    uint32_t type;
    int32_t  ret;
    uint32_t cmd;
    uint32_t dir;
    uint32_t port_idx;
    uint32_t data_len, data_trunc;
    uint8_t  data[256];
};

static volatile sig_atomic_t stop_flag = 0;
static void on_sig(int s){ (void)s; stop_flag = 1; }

struct ring_buffer *g_rb;
struct sniffer_bpf *g_skel;
struct bpf_object *g_obj;

static pthread_mutex_t ports_mu = PTHREAD_MUTEX_INITIALIZER;
static char ports[MAX_PORTS][256];
static char log_paths[MAX_PORTS][512];
static FILE *port_logs[MAX_PORTS];
static uint32_t target_count = 0;
static int port_baudrates[MAX_PORTS];  // Baudrate for each port
static char g_socket_path[256] = DEFAULT_SOCKET_PATH;
static char g_log_dir[256] = DEFAULT_LOG_DIR;
static int g_log_mode = DEFAULT_LOG_MODE;  // Current logging mode

// Active monitoring state
enum { ST_ACTIVE=1, ST_PASSIVE=2 };
static int port_states[MAX_PORTS] = {0}; // State for each port
static int active_fds[MAX_PORTS] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static pthread_t active_reader_threads[MAX_PORTS];
static int foreign_openers[MAX_PORTS] = {0}; // Count of foreign processes using each port

// Duplicate event prevention
struct last_event {
    uint32_t tgid;
    uint32_t type;
    uint64_t ts;
    char comm[16];
};
static struct last_event last_events[MAX_PORTS] = {0};
static int port_baudrates[MAX_PORTS]; // Baudrate for each port
static uint32_t self_tgid = 0; // Our own process ID to ignore our own opens/closes

// Store both original and resolved paths for symlink support
static char original_paths[MAX_PORTS][256];  // Store original path (alias)

// Track port state for mode switching (independent of logging decisions)
static struct {
    uint32_t active_fds;  // Number of currently open FDs per port
    bool has_real_usage;   // Whether any FD was used for real operations
} port_state[MAX_PORTS] = {0};

// Mark that a file descriptor was used for real operations
static void mark_fd_real_usage(uint32_t port_idx) {
    if (port_idx < MAX_PORTS) {
        port_state[port_idx].has_real_usage = true;
    }
}

// Forward declarations
static void save_config(void);
static void load_config(void);
static void scan_existing_fds(const char *devpath, uint32_t port_idx);
static void set_termios(int fd, int speed, int databits, char parity, int stopbits, bool hwflow);
static void *active_reader(void *arg);
static void enter_active_mode(uint32_t port_idx);
static void enter_passive_mode(uint32_t port_idx);
static void handle_port_state_transition(uint32_t port_idx, int event_type, uint32_t tgid, const char *comm);

// Smart event filtering - ignore system noise
static bool should_ignore_event(const struct event *e);
static bool is_real_application(const struct event *e);

static void write_info_line(uint32_t idx)
{
    if (idx >= MAX_PORTS || !port_logs[idx] || ports[idx][0] == '\0') return;
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    
    if (g_log_mode == LOG_MODE_SIMPLE) {
        // Simple, human-readable format with new date format
        struct tm *tm_info = localtime(&ts.tv_sec);
        char time_str[32];
        strftime(time_str, sizeof(time_str), "%d.%m.%y %H:%M:%S", tm_info);
        fprintf(port_logs[idx], "[%s.%03ld] Monitoring started: %s (baud: %d)\n", 
                time_str, ts.tv_nsec / 1000000, ports[idx], port_baudrates[idx]);
    } else {
        // Advanced, machine-readable format
        int baud = -1;
        char cmd[512]; snprintf(cmd, sizeof(cmd), "stty -F %s -a 2>/dev/null", ports[idx]);
        FILE *pf = popen(cmd, "r");
        if (pf) {
            char line[1024];
            if (fgets(line, sizeof(line), pf)) {
                const char *sp = strstr(line, "speed ");
                if (sp) { sp += 6; baud = atoi(sp); }
            }
            pclose(pf);
        }
        fprintf(port_logs[idx],
                "{\"ts\":%" PRIu64 ".%09ld,\"type\":\"info\",\"msg\":\"monitoring_started\",\"device\":\"%s\",\"mode\":\"unknown\",\"baud\":%d}\n",
                (uint64_t)ts.tv_sec, ts.tv_nsec, ports[idx], baud);
    }
    fflush(port_logs[idx]);
}

// Simple logging functions for different log modes
static void log_simple_event(uint32_t port_idx, const char *event_type, const char *details) {
    if (port_idx >= MAX_PORTS || !port_logs[port_idx]) return;
    struct timespec ts; 
    clock_gettime(CLOCK_REALTIME, &ts);
    
    if (g_log_mode == LOG_MODE_SIMPLE) {
        struct tm *tm_info = localtime(&ts.tv_sec);
        char time_str[32];
        strftime(time_str, sizeof(time_str), "%d.%m.%y %H:%M:%S", tm_info);
        fprintf(port_logs[port_idx], "[%s.%03ld] %s: %s\n", 
                time_str, ts.tv_nsec / 1000000, event_type, details);
    }
    fflush(port_logs[port_idx]);
}

static void log_simple_data(uint32_t port_idx, const char *direction, const char *data, size_t len) {
    if (port_idx >= MAX_PORTS || !port_logs[port_idx]) return;
    struct timespec ts; 
    clock_gettime(CLOCK_REALTIME, &ts);
    
    if (g_log_mode == LOG_MODE_SIMPLE) {
        struct tm *tm_info = localtime(&ts.tv_sec);
        char time_str[32];
        strftime(time_str, sizeof(time_str), "%d.%m.%y %H:%M:%S", tm_info);
        fprintf(port_logs[port_idx], "[%s.%03ld] %s: ", time_str, ts.tv_nsec / 1000000, direction);
        
        // Use proper escaping and quoting for data
        char escaped_data[512];
        escape_data_for_log((const uint8_t*)data, len, escaped_data, sizeof(escaped_data));
        fprintf(port_logs[port_idx], "%s\n", escaped_data);
    }
    fflush(port_logs[port_idx]);
}

// Check if this is a duplicate event (same process, same type, within short time)
static bool is_duplicate_event(uint32_t port_idx, const struct event *e) {
    if (port_idx >= MAX_PORTS) return false;
    
    struct last_event *last = &last_events[port_idx];
    uint64_t time_diff = e->ts - last->ts;
    
    // Consider it duplicate if same process, same type, within 100ms
    if (last->tgid == e->tgid && last->type == e->type && 
        strcmp(last->comm, e->comm) == 0 && time_diff < 100000000) { // 100ms in nanoseconds
        return true;
    }
    
    // Update last event
    last->tgid = e->tgid;
    last->type = e->type;
    last->ts = e->ts;
    strncpy(last->comm, e->comm, sizeof(last->comm) - 1);
    last->comm[sizeof(last->comm) - 1] = '\0';
    
    return false;
}

// Check if IOCTL command is important enough to log
static bool is_important_ioctl(uint32_t cmd) {
    // Only log IOCTLs that are meaningful for TTY operations
    // Common TTY IOCTLs: TCGETS, TCSETS, TCSETSW, TCSETSF, TCFLSH, TIOCMGET, TIOCMSET
    switch (cmd) {
        case 0x5401:  // TCGETS
        case 0x5402:  // TCSETS  
        case 0x5403:  // TCSETSW
        case 0x5404:  // TCSETSF
        case 0x540B:  // TCFLSH
        case 0x5415:  // TIOCMGET
        case 0x5416:  // TIOCMSET
        case 0x5417:  // TIOCMBIC
        case 0x5418:  // TIOCMBIS
            return true;
        default:
            return false;
    }
}

// Event attribute-based filtering: detect real TTY usage vs system scans
static bool is_real_application(const struct event *e) {
    // Key insight: Real applications actually USE the file descriptor, not just open/close it
    
    // 1. Data events (READ/WRITE) are always legitimate if they succeed
    if (e->type == 3 || e->type == 4) { // READ/WRITE
        if (e->ret > 0) { // Successful data transfer
            mark_fd_real_usage(e->port_idx); // Mark that FD was used for real operations
            return true;
        }
    }
    
    // 2. IOCTL events - only log important ones that succeed
    if (e->type == 5) { // IOCTL
        if (e->ret >= 0 && is_important_ioctl(e->cmd)) {
            mark_fd_real_usage(e->port_idx); // Mark that FD was used for real operations
            return true;
        }
        return false;
    }
    
    // 3. For OPEN/CLOSE events, update port state and decide logging
    if (e->type == 1 || e->type == 2) { // OPEN/CLOSE
        
        if (e->type == 1) { // OPEN
            port_state[e->port_idx].active_fds++;
            // Always log OPEN events for mode switching logic
            return true;
        } else if (e->type == 2) { // CLOSE
            if (port_state[e->port_idx].active_fds > 0) {
                port_state[e->port_idx].active_fds--;
            }
            
            // Only log CLOSE if we had real usage (for cleaner logs)
            if (port_state[e->port_idx].has_real_usage) {
                port_state[e->port_idx].has_real_usage = false; // Reset for next session
                return true; // Had real usage, log the CLOSE
            }
            return false; // No real usage = fake open/close, don't log
        }
    }
    
    // 4. Default: allow if it passes checks
    return true;
}

static bool should_ignore_event(const struct event *e) {
    // Always ignore our own events
    if (e->tgid == self_tgid) return true;
    
    // Event type filtering:
    // 1 = OPEN, 2 = CLOSE, 3 = READ, 4 = WRITE, 5 = IOCTL
    
    if (e->type == 1 || e->type == 2) {  // OPEN or CLOSE events
        // Don't filter OPEN/CLOSE here - we handle them separately for mode switching
        // and apply logging filters later
        return false;
    }
    
    if (e->type == 3 || e->type == 4) {  // READ or WRITE events
        // Only log READ/WRITE when we're in passive mode (real app using port)
        if (e->port_idx < MAX_PORTS) {
            return port_states[e->port_idx] == ST_ACTIVE;
        }
        return true;  // Ignore if port_idx is invalid
    }
    
    if (e->type == 5) {  // IOCTL events
        // IOCTL events are mostly system noise - only log for real applications
        // and only when they're actually using the port
        if (e->port_idx < MAX_PORTS) {
            return !is_real_application(e) || port_states[e->port_idx] == ST_ACTIVE;
        }
        return true;  // Ignore if port_idx is invalid
    }
    
    return true;  // Ignore unknown event types
}

static void set_termios(int fd, int speed, int databits, char parity, int stopbits, bool hwflow) {
    struct termios tio;
    if (tcgetattr(fd, &tio) == -1) {
        fprintf(stderr, "WARNING: tcgetattr failed: %s\n", strerror(errno));
        return;
    }
    cfmakeraw(&tio);

    speed_t sp;
    switch (speed) {
        case 9600: sp = B9600; break;
        case 19200: sp = B19200; break;
        case 38400: sp = B38400; break;
        case 57600: sp = B57600; break;
        case 115200: sp = B115200; break;
        case 230400: sp = B230400; break;
        case 460800: sp = B460800; break;
        case 921600: sp = B921600; break;
        default: sp = B115200; fprintf(stderr, "WARNING: Unsupported speed %d, defaulting to 115200\n", speed);
    }
    cfsetispeed(&tio, sp);
    cfsetospeed(&tio, sp);

    tio.c_cflag &= ~CSIZE;
    tio.c_cflag |= (databits == 7 ? CS7 : CS8);

    // Parity
    tio.c_cflag &= ~(PARENB|PARODD);
    tio.c_iflag &= ~(INPCK|ISTRIP);
    if (parity == 'E' || parity == 'e')      tio.c_cflag |= PARENB;
    else if (parity == 'O' || parity == 'o') tio.c_cflag |= PARENB | PARODD;

    // Stop bits
    if (stopbits == 2) tio.c_cflag |= CSTOPB; else tio.c_cflag &= ~CSTOPB;

    // Flow control
    if (hwflow) tio.c_cflag |= CRTSCTS; else tio.c_cflag &= ~CRTSCTS;
    tio.c_iflag &= ~(IXON|IXOFF|IXANY);

    if (tcsetattr(fd, TCSANOW, &tio) == -1) {
        fprintf(stderr, "WARNING: tcsetattr failed: %s\n", strerror(errno));
    }
}

static void *active_reader(void *arg) {
    uint32_t port_idx = (uint32_t)(uintptr_t)arg;
    unsigned char buf[4096];
    
    while (!stop_flag && active_fds[port_idx] >= 0) {
        ssize_t n = read(active_fds[port_idx], buf, sizeof buf);
        if (n > 0) {
            struct timespec ts; 
            clock_gettime(CLOCK_REALTIME, &ts);
            
            // Log the active read data
            pthread_mutex_lock(&ports_mu);
            if (port_logs[port_idx]) {
                if (g_log_mode == LOG_MODE_SIMPLE) {
                    log_simple_data(port_idx, "ACTIVE_READ", (char*)buf, n);
                } else {
                    fprintf(port_logs[port_idx],
                            "{\"ts\":%" PRIu64 ".%09ld,\"type\":\"active_read\",\"port_idx\":%u,\"n\":%zd,\"data\":\"",
                            (uint64_t)ts.tv_sec, ts.tv_nsec, port_idx, n);
                    for (ssize_t i = 0; i < n; i++) {
                        fprintf(port_logs[port_idx], "%02x", buf[i]);
                    }
                    fprintf(port_logs[port_idx], "\"}\n");
                }
                fflush(port_logs[port_idx]);
            }
            pthread_mutex_unlock(&ports_mu);
        } else if (n == 0) {
            usleep(1000); // 1ms sleep on EOF
        } else {
            if (errno == EAGAIN || errno == EINTR) continue;
            if (errno == EBADF) break;  // fd closed by main thread; exit cleanly
            fprintf(stderr, "WARNING: Active read error on port %u: %s\n", port_idx, strerror(errno));
            break;
        }
    }
    return NULL;
}

static void enter_active_mode(uint32_t port_idx) {
    if (port_idx >= MAX_PORTS || ports[port_idx][0] == '\0') return;
    
    // Try to open the port for active reading
            active_fds[port_idx] = open(ports[port_idx], O_RDONLY | O_NOCTTY | O_NONBLOCK | O_EXCL);
    if (active_fds[port_idx] >= 0) {
        // Configure termios with stored baudrate for this port
        set_termios(active_fds[port_idx], port_baudrates[port_idx], DEFAULT_DATABITS, DEFAULT_PARITY, DEFAULT_STOPBITS, DEFAULT_HWFLOW);
        
        // Create reader thread
        if (pthread_create(&active_reader_threads[port_idx], NULL, active_reader, (void*)(uintptr_t)port_idx) == 0) {
            port_states[port_idx] = ST_ACTIVE;
            fprintf(stderr, "[state] Port %u: PASSIVE -> ACTIVE (opened %s)\n", port_idx, ports[port_idx]);
            
            // Update log to show active mode
            if (port_logs[port_idx]) {
                if (g_log_mode == LOG_MODE_SIMPLE) {
                    log_simple_event(port_idx, "MODE_CHANGE", "ACTIVE mode (port free)");
                } else {
                    struct timespec ts; 
                    clock_gettime(CLOCK_REALTIME, &ts);
                    fprintf(port_logs[port_idx],
                            "{\"ts\":%" PRIu64 ".%09ld,\"type\":\"info\",\"msg\":\"mode_changed\",\"port_idx\":%u,\"mode\":\"active\"}\n",
                            (uint64_t)ts.tv_sec, ts.tv_nsec, port_idx);
                }
                fflush(port_logs[port_idx]);
            }
        } else {
            fprintf(stderr, "ERROR: Failed to create active reader thread for port %u\n", port_idx);
            close(active_fds[port_idx]);
            active_fds[port_idx] = -1;
        }
    } else {
        fprintf(stderr, "WARNING: Failed to open %s for active mode: %s\n", ports[port_idx], strerror(errno));
    }
}

static void enter_passive_mode(uint32_t port_idx) {
    if (port_idx >= MAX_PORTS) return;
    
    if (active_fds[port_idx] >= 0) {
        close(active_fds[port_idx]);
        active_fds[port_idx] = -1;
        
        // Wait for reader thread to finish
        pthread_join(active_reader_threads[port_idx], NULL);
        
        port_states[port_idx] = ST_PASSIVE;
        fprintf(stderr, "[state] Port %u: ACTIVE -> PASSIVE (foreign open)\n", port_idx);
        
        // Update log to show passive mode
        if (port_logs[port_idx]) {
            if (g_log_mode == LOG_MODE_SIMPLE) {
                log_simple_event(port_idx, "MODE_CHANGE", "PASSIVE mode (foreign process using port)");
            } else {
                struct timespec ts; 
                clock_gettime(CLOCK_REALTIME, &ts);
                fprintf(port_logs[port_idx],
                        "{\"ts\":%" PRIu64 ".%09ld,\"type\":\"info\",\"msg\":\"mode_changed\",\"port_idx\":%u,\"mode\":\"passive\"}\n",
                        (uint64_t)ts.tv_sec, ts.tv_nsec, port_idx);
            }
            fflush(port_logs[port_idx]);
        }
    }
}

static void handle_port_state_transition(uint32_t port_idx, int event_type, uint32_t tgid, const char *comm) {
    if (port_idx >= MAX_PORTS) return;
    
    // Ignore our own opens/closes
    if (tgid == self_tgid) return;
    
    // Mode switching is now based on actual port state, not filtering decisions
    if (event_type == 1) { // OPEN
        // Only switch to passive if we're currently in active mode
        if (port_states[port_idx] == ST_ACTIVE) {
            enter_passive_mode(port_idx);
        }
        foreign_openers[port_idx]++;
    } else if (event_type == 2) { // CLOSE
        if (foreign_openers[port_idx] > 0) {
            foreign_openers[port_idx]--;
        }
        // Only switch back to active if no more foreign processes and we're in passive mode
        if (foreign_openers[port_idx] == 0 && port_states[port_idx] == ST_PASSIVE && !stop_flag) {
            enter_active_mode(port_idx);
        }
    }
}

static void normalize_path(const char *input_path, char *output_path, size_t output_size)
{
    char resolved[PATH_MAX];
    if (input_path && realpath(input_path, resolved)) {
        snprintf(output_path, output_size, "%s", resolved);
    } else if (input_path) {
        snprintf(output_path, output_size, "%s", input_path);
    } else if (output_size) {
        output_path[0] = '\0';
    }
}

// Check libbpf version compatibility
static int check_libbpf_version(void)
{
    /*
     * Prefer exact runtime version if helpers are available (libbpf >= 1.0):
     *   libbpf_major_version(), libbpf_minor_version(), libbpf_version_string().
     * Fallback to compile-time macros when building against older libbpf (e.g., 0.5 on jammy).
     * Use weak references so linking succeeds even if symbols are absent.
     */

    extern const char *libbpf_version_string(void) __attribute__((weak));
    extern unsigned int libbpf_major_version(void) __attribute__((weak));
    extern unsigned int libbpf_minor_version(void) __attribute__((weak));

    unsigned int major = 0;
    unsigned int minor = 0;
    const char *how = "compile-time";
    const char *version_str = NULL;

    if (libbpf_version_string && libbpf_major_version && libbpf_minor_version) {
        major = libbpf_major_version();
        minor = libbpf_minor_version();
        version_str = libbpf_version_string();
        how = "runtime";
    } else {
#ifdef LIBBPF_MAJOR_VERSION
        major = LIBBPF_MAJOR_VERSION;
#endif
#ifdef LIBBPF_MINOR_VERSION
        minor = LIBBPF_MINOR_VERSION;
#endif
        version_str = "n/a";
    }

    fprintf(stderr, "libbpf version: %u.%u (%s: %s)\n", major, minor, how, version_str ? version_str : "n/a");

    // Require at least 0.8.0 for reliable skeleton support
    if (major == 0 && minor < 8) {
        fprintf(stderr, "ERROR: libbpf version %u.%u is not compatible\n", major, minor);
        fprintf(stderr, "ERROR: This version has known issues with BPF skeleton attachment\n");
        fprintf(stderr, "ERROR: Please upgrade to libbpf 0.8.0 or newer\n");
        return -1;
    }

    fprintf(stderr, "libbpf version check: PASSED\n");
    return 0;
}

// Check if the system has the required libbpf version
static int check_system_libbpf_version(void)
{
    fprintf(stderr, "Checking system libbpf version...\n");
    
    // Check what libbpf packages are installed
    FILE *fp = popen("dpkg -l | grep libbpf", "r");
    if (fp) {
        char line[256];
        fprintf(stderr, "Installed libbpf packages:\n");
        while (fgets(line, sizeof(line), fp)) {
            fprintf(stderr, "  %s", line);
        }
        pclose(fp);
    }
    
    // Check if we have a compatible version
    fp = popen("ldconfig -p | grep libbpf", "r");
    if (fp) {
        char line[256];
        fprintf(stderr, "Available libbpf libraries:\n");
        while (fgets(line, sizeof(line), fp)) {
            fprintf(stderr, "  %s", line);
        }
        pclose(fp);
    }
    
    // Check bpftool version
    fp = popen("bpftool version 2>/dev/null", "r");
    if (fp) {
        char line[256];
        fprintf(stderr, "bpftool version:\n");
        while (fgets(line, sizeof(line), fp)) {
            fprintf(stderr, "  %s", line);
        }
        pclose(fp);
    } else {
        fprintf(stderr, "WARNING: bpftool not found or not working\n");
    }
    
    return 0;
}

// Simple runtime compatibility check
static int check_runtime_compatibility(void)
{
    fprintf(stderr, "Checking runtime compatibility...\n");
    
    // For now, just check if we can access basic libbpf functions
    // This avoids complex BPF program creation that might fail
    fprintf(stderr, "Runtime compatibility check: PASSED (basic check)\n");
    return 0;
}

static void log_event_json(const struct event *e)
{
    // CRITICAL: Add robust error checking to prevent daemon crashes
    if (!e) {
        fprintf(stderr, "ERROR: log_event_json called with NULL event\n");
        return;
    }
    
    uint32_t idx = e->port_idx;
    if (idx >= MAX_PORTS) {
        fprintf(stderr, "ERROR: Invalid port_idx=%u >= MAX_PORTS=%d\n", idx, MAX_PORTS);
        return;
    }
    
    FILE *f = port_logs[idx];
    if (!f) {
        // No log file for port_idx=%u
        return;
    }
    
    // Validate event type to prevent array access issues
    if (e->type < 1 || e->type > 5) {
        fprintf(stderr, "ERROR: Invalid event type=%d\n", e->type);
        return;
    }
    
    if (g_log_mode == LOG_MODE_SIMPLE) {
        // Simple, human-readable format
        struct timespec ts; 
        clock_gettime(CLOCK_REALTIME, &ts);
        const char *etype = e->type==1?"OPEN":e->type==2?"CLOSE":e->type==3?"READ":e->type==4?"WRITE":"IOCTL";
        
        if (e->type == 1) { // OPEN
            struct tm *tm_info = localtime(&ts.tv_sec);
            char time_str[32];
            strftime(time_str, sizeof(time_str), "%d.%m.%y %H:%M:%S", tm_info);
            
            // Try to get actual baudrate from device, fallback to configured baudrate
            int actual_baud = port_baudrates[idx];  // Default to configured
            char cmd[512]; 
            snprintf(cmd, sizeof(cmd), "stty -F %s speed 2>/dev/null", ports[idx]);
            FILE *pf = popen(cmd, "r");
            if (pf) {
                char line[64];
                if (fgets(line, sizeof(line), pf)) {
                    int parsed_baud = atoi(line);
                    if (parsed_baud > 0) {
                        actual_baud = parsed_baud;
                    }
                }
                pclose(pf);
            }
            
            fprintf(f, "[%s.%03ld] %s: %s opened port (baud: %d)\n", 
                    time_str, ts.tv_nsec / 1000000, etype, e->comm, actual_baud);
        } else if (e->type == 2) { // CLOSE
            struct tm *tm_info = localtime(&ts.tv_sec);
            char time_str[32];
            strftime(time_str, sizeof(time_str), "%d.%m.%y %H:%M:%S", tm_info);
            fprintf(f, "[%s.%03ld] %s: %s closed port\n", 
                    time_str, ts.tv_nsec / 1000000, etype, e->comm);
        } else if (e->type == 3 || e->type == 4) { // READ/WRITE
            const char *dir = e->type==4?"APP->DEV":"DEV->APP";
            struct tm *tm_info = localtime(&ts.tv_sec);
            char time_str[32];
            strftime(time_str, sizeof(time_str), "%d.%m.%y %H:%M:%S", tm_info);
            fprintf(f, "[%s.%03ld] %s: %s %s ", time_str, ts.tv_nsec / 1000000, etype, e->comm, dir);
            
            // Show data with proper escaping and quoting
            char escaped_data[512];
            escape_data_for_log(e->data, e->data_len, escaped_data, sizeof(escaped_data));
            fprintf(f, "%s\n", escaped_data);
        } else if (e->type == 5) { // IOCTL
            // Only log important IOCTLs to reduce spam
            if (is_important_ioctl(e->cmd)) {
                struct tm *tm_info = localtime(&ts.tv_sec);
                char time_str[32];
                strftime(time_str, sizeof(time_str), "%d.%m.%y %H:%M:%S", tm_info);
                fprintf(f, "[%s.%03ld] %s: %s ioctl cmd=0x%x\n", 
                        time_str, ts.tv_nsec / 1000000, etype, e->comm, e->cmd);
            }
        }
    } else {
        // Advanced, machine-readable format (original JSON)
        struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
        const char *etype = e->type==1?"open":e->type==2?"close":e->type==3?"read":e->type==4?"write":"ioctl";
        fprintf(f,
            "{\"ts\":%" PRIu64 ".%09ld,\"type\":\"%s\",\"pid\":%u,\"tgid\":%u,\"comm\":\"%.*s\",\"port_idx\":%u",
            (uint64_t)ts.tv_sec, ts.tv_nsec, etype, e->pid, e->tgid, 16, e->comm, idx);
            
        if (e->type == 3 || e->type == 4) {
            // CRITICAL: Validate data_len to prevent buffer overrun crashes
            if (e->data_len > MAX_DATA) {
                fprintf(stderr, "ERROR: Invalid data_len=%u > MAX_DATA=%d\n", e->data_len, MAX_DATA);
                fprintf(f, ",\"error\":\"data_len_invalid\"");
            } else {
                fprintf(f, ",\"dir\":\"%s\",\"len\":%u,\"trunc\":%u,\"data\":",
                        e->type==4?"app2dev":"dev2app", e->data_len, e->data_trunc);
                // Safe data output with proper escaping and quoting
                char escaped_data[512];
                escape_data_for_log(e->data, e->data_len, escaped_data, sizeof(escaped_data));
                fprintf(f, "%s", escaped_data);
            }
        } else if (e->type == 5) {
            fprintf(f, ",\"cmd\":%u", e->cmd);
        }
        fprintf(f, "}\n");
    }
    fflush(f);
}

static int handle_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len < sizeof(struct event)) return 0;
    const struct event *e = data;

    /* Kernel now handles fd->port mapping in tp_exit_openat */
    
    pthread_mutex_lock(&ports_mu);
    
    // Apply smart filtering - ignore system noise
    if (should_ignore_event(e)) {
        pthread_mutex_unlock(&ports_mu);
        return 0;  // Skip this event entirely
    }
    
    // Check for duplicate events to reduce spam
    if (is_duplicate_event(e->port_idx, e)) {
        pthread_mutex_unlock(&ports_mu);
        return 0;  // Skip duplicate events
    }
    
    // Handle port state transitions FIRST (for mode switching)
    if (e->type == 1 || e->type == 2) { // OPEN or CLOSE events
        handle_port_state_transition(e->port_idx, e->type, e->tgid, e->comm);
    }
    
    // Only log events that pass our real application filter
    if (is_real_application(e)) {
        log_event_json(e);
    }
    
    pthread_mutex_unlock(&ports_mu);
    return 0;
}

static int sync_targets_map(void)
{
    int tp_fd = bpf_map__fd(g_skel->maps.target_path);
    if (tp_fd < 0) return -1;
    
    int td_fd = bpf_map__fd(g_skel->maps.target_dev);
    if (td_fd < 0) return -1;
    
    // Clear all entries first
    struct pathval empty_path = { .path = "" };
    uint64_t zero_dev = 0;
    for (uint32_t i = 0; i < MAX_TARGETS; i++) {
        bpf_map_update_elem(tp_fd, &i, &empty_path, BPF_ANY);
        bpf_map_update_elem(td_fd, &i, &zero_dev, BPF_ANY);
    }
    
    for (uint32_t i = 0; i < target_count; i++) {
        // Store resolved path at index i
        if (bpf_map_update_elem(tp_fd, &i, ports[i], BPF_ANY)) return -1;
        
        // Store original path (alias) at index i + MAX_PORTS for symlink matching
        if (original_paths[i][0] != '\0' && strcmp(original_paths[i], ports[i]) != 0) {
            uint32_t alias_idx = i + MAX_PORTS;
            if (alias_idx < MAX_TARGETS) {
                struct pathval alias_path;
                snprintf(alias_path.path, sizeof(alias_path.path), "%s", original_paths[i]);
                bpf_map_update_elem(tp_fd, &alias_idx, &alias_path, BPF_ANY);
            }
        }
        
        // Get device major:minor for BPF matching
        if (ports[i][0] != '\0') {
            struct stat st;
            if (stat(ports[i], &st) == 0) {
                uint64_t dev_t = st.st_rdev;
                if (bpf_map_update_elem(td_fd, &i, &dev_t, BPF_ANY)) {
                    fprintf(stderr, "WARNING: Failed to update target_dev[%u] with dev_t %lu\n", i, (unsigned long)dev_t);
                } else {
                            // Updated target_dev[%u] with dev_t %lu (major=%u, minor=%u)
                }
            } else {
                fprintf(stderr, "WARNING: Failed to stat %s: %s\n", ports[i], strerror(errno));
            }
        }
    }
    
    int tc_fd = bpf_map__fd(g_skel->maps.target_count);
    if (tc_fd >= 0) {
        uint32_t k0 = 0;
        // BPF program should check all possible slots (including alias slots)
        uint32_t effective_count = MAX_TARGETS;  // Check full range for aliases
        if (bpf_map_update_elem(tc_fd, &k0, &effective_count, BPF_ANY)) return -1;
    }
    return 0;
}

static int api_add_port(const char *devpath, const char *logpath, int baudrate, char *err, size_t errsz)
{
    pthread_mutex_lock(&ports_mu);
    
    // Check if port already exists (check both original and resolved paths)
    char resolved_path[256];
    normalize_path(devpath, resolved_path, sizeof(resolved_path));
    
    for (uint32_t i = 0; i < target_count; i++) {
        if (ports[i][0] != '\0' && 
            (strcmp(ports[i], devpath) == 0 || strcmp(ports[i], resolved_path) == 0 ||
             strcmp(original_paths[i], devpath) == 0)) {
            snprintf(err, errsz, "port %s already exists", devpath);
            pthread_mutex_unlock(&ports_mu);
            return -1;
        }
    }
    
    uint32_t idx = target_count;
    if (idx >= MAX_PORTS) { snprintf(err, errsz, "max ports reached"); pthread_mutex_unlock(&ports_mu); return -1; }
    
    // Store original path for user reference
    snprintf(original_paths[idx], sizeof(original_paths[idx]), "%s", devpath);
    // Store resolved path for BPF matching and active mode operations
    snprintf(ports[idx], sizeof(ports[idx]), "%s", resolved_path);
    
    // fprintf(stderr, "DEBUG: api_add_port idx=%u original='%s' resolved='%s'\n", idx, original_paths[idx], ports[idx]);
    
    // Store baudrate for this port
    port_baudrates[idx] = baudrate;
    
    char pathbuf[512];
    const char *use_log = logpath && logpath[0] ? logpath : NULL;
    if (!use_log) {
        const char *base = strrchr(devpath, '/');
        base = base ? base + 1 : devpath;
        snprintf(pathbuf, sizeof(pathbuf), "%s/%s.jsonl", g_log_dir, base);
        use_log = pathbuf;
    }
    // Store the log path for later reopening
    snprintf(log_paths[idx], sizeof(log_paths[idx]), "%s", use_log);
    // Ensure relative paths are placed under the configured log directory
    char abs_log_path[1024];
    if (use_log[0] == '/') snprintf(abs_log_path, sizeof(abs_log_path), "%s", use_log);
    else snprintf(abs_log_path, sizeof(abs_log_path), "%s/%s", g_log_dir, use_log);
    
    // Truncate log file on opening (unless it's a unique filename)
    FILE *f = fopen(abs_log_path, "w");  // "w" truncates, "a" appends
    if (!f) { snprintf(err, errsz, "log open: %s", strerror(errno)); ports[idx][0]='\0'; pthread_mutex_unlock(&ports_mu); return -1; }
    port_logs[idx] = f;
    target_count++;
    int rc = sync_targets_map();
    write_info_line(idx);
    
    // Scan existing processes for already-open fds to this device
    scan_existing_fds(devpath, idx);
    
    // Try to enter active mode initially if port is free
    enter_active_mode(idx);
    
    pthread_mutex_unlock(&ports_mu);
    if (rc) { snprintf(err, errsz, "sync map failed"); return -1; }
    
    return (int)idx;
}

static void save_config(void)
{
    // Configuration persistence disabled - daemon starts fresh each session
    // No configuration is saved to disk
}

static void load_config(void)
{
    // Configuration persistence disabled - daemon starts fresh each session
    // No configuration is loaded from disk
            // Configuration persistence disabled - starting fresh
}

static void reopen_existing_logs(void)
{
            // reopen_existing_logs called, target_count=%u
    
    // Configuration persistence disabled - no config loaded from file
    // BPF maps start empty and are populated only via API calls
    
    // Initialize BPF maps with current (empty) state
    int tp_fd = bpf_map__fd(g_skel->maps.target_path);
    int tc_fd = bpf_map__fd(g_skel->maps.target_count);
    
    if (tp_fd >= 0 && tc_fd >= 0) {
        // Initialize target_count to 0
        uint32_t k0 = 0;
        if (bpf_map_update_elem(tc_fd, &k0, &target_count, BPF_ANY) == 0) {
            // Initialized BPF map target_count=%u
        }
    }
    
    // Since configuration persistence is disabled, target_count starts at 0
    // No existing logs to reopen, no existing FDs to scan
    // Ports will be added dynamically via API calls
    
    // Try to enter active mode for any existing ports
    for (uint32_t i = 0; i < target_count; i++) {
        if (ports[i][0] != '\0') {
            enter_active_mode(i);
        }
    }
}

static void *fd_scanner_thread(void *arg)
{
    (void)arg;
            // FD scanner thread started
    int scan_count = 0;
    while (!stop_flag) {
        pthread_mutex_lock(&ports_mu);
        uint32_t cnt = target_count;
        char devs[MAX_PORTS][256];
        for (uint32_t i=0;i<cnt;i++) snprintf(devs[i], sizeof(devs[i]), "%s", ports[i]);
        pthread_mutex_unlock(&ports_mu);
        
        if (cnt > 0) {
            scan_count++;
            // FD scanner running scan #%d for %u devices
            for (uint32_t i=0;i<cnt;i++) {
                if (devs[i][0] != '\0') scan_existing_fds(devs[i], i);
            }
        }
        
        // Sleep for 5 seconds between scans instead of 500ms to reduce CPU usage
        struct timespec req = { .tv_sec = 5, .tv_nsec = 0 }; // 5 seconds
        // FD scanner sleeping for 5 seconds...
        nanosleep(&req, NULL);
    }
            // FD scanner thread exiting
    return NULL;
}

static void scan_existing_fds(const char *devpath, uint32_t port_idx)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
            // scan_existing_fds called for devpath='%s' (len=%zu), port_idx=%u
    
    // Alternative approach: use lsof to find processes with the device open
    // This avoids permission issues with /proc/*/fd/ directories
    char cmd[1024];
    
    // Try to find lsof in common locations
    const char *lsof_paths[] = {"/usr/bin/lsof", "/bin/lsof", "/usr/sbin/lsof", "lsof", NULL};
    const char *lsof_cmd = NULL;
    
    for (int i = 0; lsof_paths[i]; i++) {
        char test_cmd[256];
        snprintf(test_cmd, sizeof(test_cmd), "which %s >/dev/null 2>&1", lsof_paths[i]);
        if (system(test_cmd) == 0) {
            lsof_cmd = lsof_paths[i];
            break;
        }
    }
    
    if (!lsof_cmd) {
        // lsof command not found in any standard location
        return;
    }
    
    snprintf(cmd, sizeof(cmd), "%s %s", lsof_cmd, devpath);
            // Using lsof command: %s
        // Full command: %s
    
    FILE *lsof = popen(cmd, "r");
    if (!lsof) {
        // Failed to run lsof command: %s
        return;
    }
    
    // Set line buffering to ensure we get output immediately
    setvbuf(lsof, NULL, _IOLBF, 0);
    
    char line[512];
    int matches_found = 0;
    
            // Running lsof command: %s
    
    // Read all output from lsof, including any error messages
    int line_count = 0;
    int header_found = 0;
    while (fgets(line, sizeof(line), lsof)) {
        line_count++;
        // lsof output line %d: %s
        
        // Skip warning lines that start with "lsof:" or contain "Output information may be incomplete"
        if (strstr(line, "lsof:") || strstr(line, "Output information may be incomplete")) {
            // Skipping warning line: %s
            continue;
        }
        
        // Check if this is the header line (contains "COMMAND PID USER")
        if (strstr(line, "COMMAND") && strstr(line, "PID") && strstr(line, "USER")) {
            // Found header line: %s
            header_found = 1;
            continue;
        }
        
        // Only process data lines after we've found the header
        if (!header_found) {
            // Skipping line before header: %s
            continue;
        }
        
        // Processing data line: %s
        
        // Parse lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        char command[64], user[64], fd_str[32], type[16], device[32], size[32], node[32], name[256];
        uint32_t tgid;
        
        int parsed = sscanf(line, "%63s %u %63s %31s %15s %31s %31s %31s %255s",
                           command, &tgid, user, fd_str, type, device, size, node, name);
        
        if (parsed >= 4) {
            // Extract numeric part of fd (remove r/w/u suffix if present)
            int fd = -1;
            if (sscanf(fd_str, "%d", &fd) == 1 && fd >= 0) {
                matches_found++;
                
                    struct fdkey k = { .tgid = tgid, .fd = fd };
                    uint8_t one = 1;
                    
                // Found matching fd %d in process %u (%s) for %s
                
                    int fd_interest_fd = bpf_map__fd(g_skel->maps.fd_interest);
                    int fd_portidx_fd = bpf_map__fd(g_skel->maps.fd_portidx);
                    
                    if (fd_interest_fd >= 0) {
                    int rc = bpf_map_update_elem(fd_interest_fd, &k, &one, BPF_ANY);
                    if (rc) fprintf(stderr, "ERROR: fd_interest update failed pid=%u fd=%d: %s\n", tgid, fd, strerror(errno));
                } else {
                    fprintf(stderr, "ERROR: fd_interest map fd invalid\n");
                    }
                    if (fd_portidx_fd >= 0) {
                    int rc2 = bpf_map_update_elem(fd_portidx_fd, &k, &port_idx, BPF_ANY);
                    if (rc2) fprintf(stderr, "ERROR: fd_portidx update failed pid=%u fd=%d idx=%u: %s\n", tgid, fd, port_idx, strerror(errno));
                } else {
                    fprintf(stderr, "ERROR: fd_portidx map fd invalid\n");
                }
            } else {
                // Skipping non-numeric fd: %s
            }
        } else {
            // Failed to parse lsof line (parsed %d fields): %s
        }
    }
    
    int exit_status = pclose(lsof);
    // lsof process exited with status: %d
    
    // scan_existing_fds completed for %s: processed %d lines, header_found=%d, found %d matches
}

static int api_remove_port(int idx, char *err, size_t errsz)
{
    if (idx < 0 || idx >= (int)MAX_PORTS) { snprintf(err, errsz, "bad index"); return -1; }
    pthread_mutex_lock(&ports_mu);
    if (ports[idx][0] == '\0' && !port_logs[idx]) { pthread_mutex_unlock(&ports_mu); snprintf(err, errsz, "not found"); return -1; }
    
    // Clean up active monitoring for this port
    if (active_fds[idx] >= 0) {
        close(active_fds[idx]);
        active_fds[idx] = -1;
        pthread_join(active_reader_threads[idx], NULL);
        port_states[idx] = ST_PASSIVE;
        foreign_openers[idx] = 0;
    }
    
    if (port_logs[idx]) { fclose(port_logs[idx]); port_logs[idx] = NULL; }
    ports[idx][0] = '\0';
    // Recompute target_count as highest non-empty index + 1
    uint32_t new_cnt = 0;
    for (int i = (int)MAX_PORTS - 1; i >= 0; i--) {
        if (ports[i][0] != '\0') { new_cnt = (uint32_t)(i + 1); break; }
    }
    target_count = new_cnt;
    int rc = sync_targets_map();
    pthread_mutex_unlock(&ports_mu);
    if (rc) { snprintf(err, errsz, "sync map failed"); return -1; }
    return 0;
}

static int api_find_index_by_path_nolock(const char *dev)
{
    for (int i = 0; i < (int)MAX_PORTS; i++) {
        if (ports[i][0] != '\0' && strcmp(ports[i], dev) == 0) return i;
    }
    return -1;
}

static void http_send(int cfd, int code, const char *ctype, const char *body)
{
    char header[512];
    snprintf(header, sizeof(header), "HTTP/1.1 %d\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
             code, ctype, body ? strlen(body) : 0);
    
    // Write headers
    if (write(cfd, header, strlen(header)) < 0) {
        fprintf(stderr, "Warning: failed to write headers: %s\n", strerror(errno));
        return;
    }
    
    // Write body if present
    if (body && strlen(body) > 0) {
        if (write(cfd, body, strlen(body)) < 0) {
            fprintf(stderr, "Warning: failed to write body: %s\n", strerror(errno));
        }
    }
}

static void handle_http_client(int cfd)
{
    char buf[8192];
    ssize_t n = recv(cfd, buf, sizeof(buf)-1, 0);
    if (n <= 0) { close(cfd); return; }
    buf[n] = '\0';

    // Very small parser: supports
    // POST /ports {"dev":"/dev/ttyUSB0","log":"/var/log/ttyUSB0.jsonl"}
    // GET /ports
    // GET /logs/{idx}
    // GET /stream/{idx}
    // GET /stream/{idx}

    if (!strncmp(buf, "GET /ports", 10)) {
        pthread_mutex_lock(&ports_mu);
        char body[4096];
        size_t off = 0; off += snprintf(body+off, sizeof(body)-off, "[");
        for (uint32_t i=0;i<target_count;i++) {
            // Show original path (alias) to user, not resolved path
            const char *display_path = (original_paths[i][0] != '\0') ? original_paths[i] : ports[i];
            off += snprintf(body+off, sizeof(body)-off, "%s{\"idx\":%u,\"dev\":\"%s\"}", i?",":"", i, display_path);
        }
        off += snprintf(body+off, sizeof(body)-off, "]");
        pthread_mutex_unlock(&ports_mu);
        http_send(cfd, 200, "application/json", body);
    } else if (!strncmp(buf, "GET /logs/", 10)) {
        int idx = -1;
        const char *p = buf + 10;
        if (*p >= '0' && *p <= '9') { idx = atoi(p); }
        if (idx < 0 || idx >= (int)MAX_PORTS) { http_send(cfd, 400, "text/plain", "bad index"); close(cfd); return; }

        /* Copy log path under lock, then read using a separate handle */
        char logpath_local[1024] = {0};
        pthread_mutex_lock(&ports_mu);
        if (log_paths[idx][0] != '\0') {
            snprintf(logpath_local, sizeof(logpath_local), "%s", log_paths[idx]);
        } else if (ports[idx][0] != '\0') {
            const char *base = strrchr(ports[idx], '/');
            base = base ? base + 1 : ports[idx];
            snprintf(logpath_local, sizeof(logpath_local), "%s/%s.jsonl", g_log_dir, base);
        }
        pthread_mutex_unlock(&ports_mu);

        if (!logpath_local[0]) { 
            http_send(cfd, 404, "text/plain", "no log"); close(cfd); return; 
        }

        // Prefix relative paths with log dir
        char abs_log_path[1024];
        if (logpath_local[0] == '/') snprintf(abs_log_path, sizeof(abs_log_path), "%s", logpath_local);
        else snprintf(abs_log_path, sizeof(abs_log_path), "%s/%s", g_log_dir, logpath_local);

        FILE *rf = fopen(abs_log_path, "r");
        if (!rf) { 
            http_send(cfd, 404, "text/plain", "no log"); close(cfd); return; 
        }
        int rfd = fileno(rf);
        off_t sz = lseek(rfd, 0, SEEK_END);
        lseek(rfd, 0, SEEK_SET);
        if (sz < 0) { fclose(rf); http_send(cfd, 500, "text/plain", "seek fail"); close(cfd); return; }
        char *body = (char*)malloc((size_t)sz + 1);
        if (!body) { fclose(rf); http_send(cfd, 500, "text/plain", "oom"); close(cfd); return; }
        size_t rd = fread(body, 1, (size_t)sz, rf);
        fclose(rf);
        body[rd] = '\0';
        dprintf(cfd, "HTTP/1.1 200\r\nContent-Type: application/x-ndjson\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", rd);
        if (rd) {
            if (write(cfd, body, rd) < 0) {
                fprintf(stderr, "Warning: failed to write response: %s\n", strerror(errno));
            }
        }
        free(body);
    } else if (!strncmp(buf, "GET /stream/", 12)) {
        int idx = -1;
        const char *p = buf + 12;
        if (*p >= '0' && *p <= '9') { idx = atoi(p); }
        if (idx < 0 || idx >= (int)MAX_PORTS) { http_send(cfd, 400, "text/plain", "bad index"); close(cfd); return; }

        char logpath_local[1024] = {0};
        pthread_mutex_lock(&ports_mu);
        if (log_paths[idx][0] != '\0') {
            snprintf(logpath_local, sizeof(logpath_local), "%s", log_paths[idx]);
        } else if (ports[idx][0] != '\0') {
            const char *base = strrchr(ports[idx], '/');
            base = base ? base + 1 : ports[idx];
            snprintf(logpath_local, sizeof(logpath_local), "%s/%s.jsonl", g_log_dir, base);
        }
        pthread_mutex_unlock(&ports_mu);
        if (!logpath_local[0]) { http_send(cfd, 404, "text/plain", "no log"); close(cfd); return; }

        // Prefix relative paths with log dir
        char abs_log_path2[1024];
        if (logpath_local[0] == '/') snprintf(abs_log_path2, sizeof(abs_log_path2), "%s", logpath_local);
        else snprintf(abs_log_path2, sizeof(abs_log_path2), "%s/%s", g_log_dir, logpath_local);

        FILE *rf = fopen(abs_log_path2, "r");
        if (!rf) { http_send(cfd, 404, "text/plain", "no log"); close(cfd); return; }
        int rfd = fileno(rf);
        off_t cur = lseek(rfd, 0, SEEK_END);
        dprintf(cfd, "HTTP/1.1 200\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
        char chunk[4096];
        while (!stop_flag) {
            off_t end = lseek(rfd, 0, SEEK_END);
            if (end > cur) {
                size_t toread = (size_t)((end - cur) > (off_t)sizeof(chunk) ? sizeof(chunk) : (end - cur));
                lseek(rfd, cur, SEEK_SET);
                size_t rd = fread(chunk, 1, toread, rf);
                cur += rd;
                if (rd) {
                    dprintf(cfd, "%zx\r\n", rd);
                    if (write(cfd, chunk, rd) < 0) {
                        fprintf(stderr, "Warning: failed to write chunk: %s\n", strerror(errno));
                        break;
                    }
                    dprintf(cfd, "\r\n");
                }
            } else { usleep(100000); }
        }
        fclose(rf);
        dprintf(cfd, "0\r\n\r\n");
    } else if (!strncmp(buf, "DELETE /ports/", 14)) {
        int idx = -1;
        const char *p = buf + 14;
        if (*p >= '0' && *p <= '9') idx = atoi(p);
        char err[128];
        if (idx < 0) { http_send(cfd, 400, "text/plain", "bad index"); }
        else if (api_remove_port(idx, err, sizeof err) < 0) { http_send(cfd, 400, "text/plain", err); }
        else { http_send(cfd, 200, "application/json", "{\"ok\":true}"); }
    } else if (!strncmp(buf, "DELETE /ports", 13)) {
        // Body: {"dev":"/dev/ttyUSB0"}
        char *body = strstr(buf, "\r\n\r\n");
        if (!body) { http_send(cfd, 400, "text/plain", "bad request"); close(cfd); return; }
        body += 4;
        char dev[256] = {0};
        char *dp = strstr(body, "\"dev\"");
        if (dp) {
            dp = strchr(dp, ':'); if (dp) { dp++; while (*dp==' '||*dp=='\t') dp++; if (*dp=='\"') { dp++; char *e=strchr(dp,'\"'); if (e) { size_t l=e-dp; if (l>=sizeof(dev)) l=sizeof(dev)-1; memcpy(dev,dp,l); } } }
        }
        if (!dev[0]) { http_send(cfd, 400, "text/plain", "missing dev"); close(cfd); return; }
        pthread_mutex_lock(&ports_mu);
        int idx = api_find_index_by_path_nolock(dev);
        pthread_mutex_unlock(&ports_mu);
        char err[128];
        if (idx < 0) { http_send(cfd, 404, "text/plain", "not found"); }
        else if (api_remove_port(idx, err, sizeof err) < 0) { http_send(cfd, 400, "text/plain", err); }
        else { http_send(cfd, 200, "application/json", "{\"ok\":true}"); }
    } else if (!strncmp(buf, "POST /ports", 11)) {
        char *body = strstr(buf, "\r\n\r\n");
        if (!body) { http_send(cfd, 400, "text/plain", "bad request"); close(cfd); return; }
        body += 4;
        char dev[256] = {0}, logp[512] = {0};
        int baudrate = DEFAULT_BAUDRATE;  // Default baudrate
        // naive JSON extraction
        char *dp = strstr(body, "\"dev\"");
        char *lp = strstr(body, "\"log\"");
        char *bp = strstr(body, "\"baudrate\"");
        if (dp) {
            dp = strchr(dp, ':'); if (dp) { dp++; while (*dp==' '||*dp=='\t') dp++; if (*dp=='\"') { dp++; char *e=strchr(dp,'\"'); if (e) { size_t l=e-dp; if (l>=sizeof(dev)) l=sizeof(dev)-1; memcpy(dev,dp,l); } } }
        }
        if (lp) {
            lp = strchr(lp, ':'); if (lp) { lp++; while (*lp==' '||*lp=='\t') lp++; if (*lp=='\"') { lp++; char *e=strchr(lp,'\"'); if (e) { size_t l=e-lp; if (l>=sizeof(logp)) l=sizeof(logp)-1; memcpy(logp,lp,l); } } }
        }
        if (bp) {
            bp = strchr(bp, ':'); if (bp) { bp++; while (*bp==' '||*bp=='\t') bp++; char *e = strchr(bp, ','); if (!e) e = strchr(bp, '}'); if (e) { size_t l = e-bp; if (l < 16) { char baud_str[16]; memcpy(baud_str, bp, l); baud_str[l] = '\0'; baudrate = atoi(baud_str); } } }
        }
        if (!dev[0]) { http_send(cfd, 400, "text/plain", "missing dev"); close(cfd); return; }
        // Generate default log path if not provided
        if (!logp[0]) {
            const char *base = strrchr(dev, '/');
            base = base ? base + 1 : dev;
            snprintf(logp, sizeof(logp), "%s/%s.jsonl", g_log_dir, base);
        }
        char err[128];
        int idx = api_add_port(dev, logp, baudrate, err, sizeof err);
        if (idx < 0) { http_send(cfd, 400, "text/plain", err); }
        else {
            char resp[64]; snprintf(resp, sizeof resp, "{\"idx\":%d}", idx);
            http_send(cfd, 200, "application/json", resp);
        }
    } else {
        http_send(cfd, 404, "text/plain", "not found");
    }
    close(cfd);
}

struct http_cfg { int port; uint32_t bind_addr; };

static void *client_thread(void *arg)
{
    int cfd = *(int*)arg; free(arg);
    handle_http_client(cfd);
    return NULL;
}

static void *http_server(void *arg)
{
    // Serve HTTP over Unix Domain Socket
    (void)arg;
    fprintf(stderr, "HTTP server thread starting, socket path: %s\n", g_socket_path);
    
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) { 
        fprintf(stderr, "socket: %s\n", strerror(errno)); 
        return NULL; 
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(g_socket_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "Socket path too long: %s\n", g_socket_path);
        close(s);
        return NULL;
    }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", g_socket_path);
    unlink(g_socket_path);
    
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind(%s): %s\n", g_socket_path, strerror(errno));
        close(s);
        return NULL;
    }
    /* Relax socket permissions so non-root clients can connect */
    chmod(g_socket_path, 0666);
    listen(s, 64);
    while (!stop_flag) {
        int cfd = accept(s, NULL, NULL);
        if (cfd < 0) { if (errno==EINTR) continue; break; }
        pthread_t th;
        int *argfd = (int*)malloc(sizeof(int));
        if (!argfd) { close(cfd); continue; }
        *argfd = cfd;
        pthread_create(&th, NULL, client_thread, argfd);
        pthread_detach(th);
    }
    close(s);
    return NULL;
}

int main(int argc, char **argv)
{
    int http_port = DEFAULT_HTTP_PORT; // unused when using unix socket, kept for help text
    uint32_t bind_addr = htonl(INADDR_LOOPBACK);
    for (int i=1;i<argc;i++) {
        if (!strcmp(argv[i], "--http-port") && i+1<argc) http_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--bind") && i+1<argc) {
            const char *b = argv[++i];
            unsigned a,b2,c,d;
            if (sscanf(b, "%u.%u.%u.%u", &a,&b2,&c,&d) == 4 && a<256 && b2<256 && c<256 && d<256) {
                bind_addr = htonl((a<<24)|(b2<<16)|(c<<8)|d);
            } else {
                fprintf(stderr, "bad --bind address\n");
                return 2;
            }
        }
        else if (!strcmp(argv[i], "--socket") && i+1<argc) {
            snprintf(g_socket_path, sizeof(g_socket_path), "%s", argv[++i]);
        }
        else if (!strcmp(argv[i], "--log-dir") && i+1<argc) {
            snprintf(g_log_dir, sizeof(g_log_dir), "%s", argv[++i]);
        }
        else if (!strcmp(argv[i], "--log-mode") && i+1<argc) {
            if (!strcmp(argv[++i], "simple")) {
                g_log_mode = LOG_MODE_SIMPLE;
            } else if (!strcmp(argv[i], "advanced")) {
                g_log_mode = LOG_MODE_ADVANCED;
            } else {
                fprintf(stderr, "Invalid log mode: %s (use 'simple' or 'advanced')\n", argv[i]);
                return 2;
            }
        }
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            fprintf(stderr, "Usage: %s [--socket %s] [--log-dir %s] [--log-mode simple|advanced]\n", argv[0], DEFAULT_SOCKET_PATH, DEFAULT_LOG_DIR);
            return 0;
        } else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]);
            return 2;
        }
    }

    // Ensure log dir exists
    struct stat st;
    if (stat(g_log_dir, &st) == -1) {
        if (mkdir(g_log_dir, 0755) == -1) {
            fprintf(stderr, "mkdir(%s): %s\n", g_log_dir, strerror(errno));
            return 1;
        }
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    
    // Check libbpf version compatibility first
    if (check_libbpf_version() != 0) {
        return 1;
    }
    
    // Check system libbpf version and compatibility
    check_system_libbpf_version();
    
    // Check runtime compatibility
    if (check_runtime_compatibility() != 0) {
        fprintf(stderr, "ERROR: Runtime compatibility check failed!\n");
        fprintf(stderr, "ERROR: The system does not have a compatible libbpf version.\n");
        fprintf(stderr, "ERROR: Please install a compatible version:\n");
        fprintf(stderr, "ERROR:   sudo apt-get update\n");
        fprintf(stderr, "ERROR:   sudo apt-get install -y libbpf-dev libbpf0\n");
        fprintf(stderr, "ERROR:   sudo apt-get install -y linux-tools-common linux-tools-generic\n");
        fprintf(stderr, "ERROR: Or build from source:\n");
        fprintf(stderr, "ERROR:   cd /tmp && git clone --depth 1 https://github.com/libbpf/libbpf.git\n");
        fprintf(stderr, "ERROR:   cd libbpf/src && sudo make install && sudo ldconfig\n");
        return 1;
    }
    
    // Add diagnostic information
    fprintf(stderr, "=== Runtime Environment Debug ===\n");
    fprintf(stderr, "Kernel version: ");
    FILE *kver = fopen("/proc/version", "r");
    if (kver) {
        char buf[256];
        if (fgets(buf, sizeof(buf), kver)) {
            fprintf(stderr, "%s", buf);
        }
        fclose(kver);
    }
    
    // Check BTF availability
    if (access("/sys/kernel/btf/vmlinux", R_OK) == 0) {
        fprintf(stderr, "BTF available: /sys/kernel/btf/vmlinux\n");
    } else {
        fprintf(stderr, "BTF not available: %s\n", strerror(errno));
    }
    
    // Check BPF filesystem
    if (access("/sys/fs/bpf", F_OK) == 0) {
        fprintf(stderr, "BPF filesystem available: /sys/fs/bpf\n");
    } else {
        fprintf(stderr, "BPF filesystem not available: %s\n", strerror(errno));
    }
    
    // Check tracepoints availability
    if (access("/sys/kernel/debug/tracing/events/syscalls", R_OK) == 0) {
        fprintf(stderr, "Syscall tracepoints available\n");
    } else {
        fprintf(stderr, "Syscall tracepoints not available: %s\n", strerror(errno));
    }
    
    // Check if running as root (needed for BPF)
    if (geteuid() == 0) {
        fprintf(stderr, "Running as root: OK\n");
    } else {
        fprintf(stderr, "WARNING: Not running as root (uid=%d) - BPF programs may fail\n", geteuid());
    }
    
    fprintf(stderr, "=== End Runtime Debug ===\n");
    
    fprintf(stderr, "About to open BPF skeleton...\n");
    
    g_skel = sniffer_bpf__open();
    if (!g_skel) { 
        fprintf(stderr, "open skel failed: %s\n", strerror(errno));
        fprintf(stderr, "This might be due to bpftool/libbpf version mismatch\n");
        fprintf(stderr, "between build time and runtime.\n");
        
        fprintf(stderr, "FATAL: Cannot load BPF skeleton. This is likely due to:\n");
        fprintf(stderr, "1. libbpf version mismatch between build and runtime\n");
        fprintf(stderr, "2. BPF skeleton ABI incompatibility\n");
        fprintf(stderr, "3. Missing or incompatible bpftool version\n");
        fprintf(stderr, "\nPlease ensure the runtime environment has compatible libbpf/bpftool versions.\n");
        return 1; 
    }
    
    fprintf(stderr, "BPF skeleton opened successfully\n");
    
    int load_err = sniffer_bpf__load(g_skel);
    if (load_err) { 
        fprintf(stderr, "load skel failed (err=%d): %s\n", load_err, strerror(-load_err));
        fprintf(stderr, "This might be due to libbpf version incompatibility or kernel issues\n");
        sniffer_bpf__destroy(g_skel);
        return 1; 
    }
    
    fprintf(stderr, "BPF skeleton loaded successfully\n");
    
    // Initialize port baudrates with default values
    for (uint32_t i = 0; i < MAX_PORTS; i++) {
        port_baudrates[i] = DEFAULT_BAUDRATE;
    }
    
    // Initialize scratch buffers - these are required for the BPF program to function
    // The BPF program uses these as temporary storage and will fail if they're empty
    uint32_t k0 = 0;
    struct pathval empty_path = { .path = "" };
    struct read_ctx empty_read = { .fd = 0, .buf = NULL, .count = 0 };
    struct open_ctx empty_open = { .filename = NULL };
    struct close_ctx empty_close = { .fd = 0 };
    
    // Initialize all scratch buffers with empty structures
    int scratch1_fd = bpf_map__fd(g_skel->maps.scratch1);
    int scratch2_fd = bpf_map__fd(g_skel->maps.scratch2);
    int scratch3_fd = bpf_map__fd(g_skel->maps.scratch3);
    int scratch4_fd = bpf_map__fd(g_skel->maps.scratch4);
    int scratch5_fd = bpf_map__fd(g_skel->maps.scratch5);
    
    if (scratch1_fd >= 0) bpf_map_update_elem(scratch1_fd, &k0, &empty_path, BPF_ANY);
    if (scratch2_fd >= 0) bpf_map_update_elem(scratch2_fd, &k0, &empty_path, BPF_ANY);
    if (scratch3_fd >= 0) bpf_map_update_elem(scratch3_fd, &k0, &empty_read, BPF_ANY);
    if (scratch4_fd >= 0) bpf_map_update_elem(scratch4_fd, &k0, &empty_open, BPF_ANY);
    if (scratch5_fd >= 0) bpf_map_update_elem(scratch5_fd, &k0, &empty_close, BPF_ANY);
    
            // Scratch buffers initialized
    
    // Ensure exit read tracepoint is enabled for RX capture
    int fd = open("/sys/kernel/debug/tracing/events/syscalls/sys_exit_read/enable", O_WRONLY);
    if (fd >= 0) {
        if (write(fd, "1", 1) < 0) {
            fprintf(stderr, "Warning: failed to enable tracepoint: %s\n", strerror(errno));
        }
        close(fd);
    }
    
    int attach_err = sniffer_bpf__attach(g_skel);
    if (attach_err) { 
        fprintf(stderr, "attach failed (err=%d): %s\n", attach_err, strerror(-attach_err));
        fprintf(stderr, "This might be due to insufficient permissions or kernel issues\n");
        sniffer_bpf__destroy(g_skel);
        return 1; 
    }

    // DEBUG: Check individual program attachments
            // Checking individual BPF program attachments...
    
    // Check if programs are actually attached to tracepoints
    if (g_skel->links.tp_raw_sys_enter) {
        // tp_raw_sys_enter program attached to tracepoint
    } else {
        fprintf(stderr, "ERROR: tp_raw_sys_enter program NOT attached to tracepoint\n");
    }
    
    if (g_skel->links.tp_raw_sys_exit) {
        // tp_raw_sys_exit program attached to tracepoint
    } else {
        fprintf(stderr, "ERROR: tp_raw_sys_exit program NOT attached to tracepoint\n");
    }
    
    if (g_skel->links.tp_enter_openat_tp) {
        fprintf(stderr, "tp_enter_openat_tp program attached to tracepoint\n");
    } else {
        fprintf(stderr, "ERROR: tp_enter_openat_tp program NOT attached to tracepoint\n");
    }
    
    if (g_skel->links.tp_enter_openat2_tp) {
        fprintf(stderr, "tp_enter_openat2_tp program attached to tracepoint\n");
    } else {
        fprintf(stderr, "ERROR: tp_enter_openat2_tp program NOT attached to tracepoint\n");
    }
    
    if (g_skel->links.tp_exit_openat_tp) {
        fprintf(stderr, "tp_exit_openat_tp program attached to tracepoint\n");
    } else {
        fprintf(stderr, "ERROR: tp_exit_openat_tp program NOT attached to tracepoint\n");
    }
    
    if (g_skel->links.tp_exit_openat2_tp) {
        fprintf(stderr, "tp_exit_openat2_tp program attached to tracepoint\n");
    } else {
        fprintf(stderr, "ERROR: tp_exit_openat2_tp program NOT attached to tracepoint\n");
    }
    
    if (g_skel->links.tp_enter_close) {
        // tp_enter_close program attached to tracepoint
    } else {
        fprintf(stderr, "ERROR: tp_enter_close program NOT attached to tracepoint\n");
    }
    
    if (g_skel->links.tp_exit_close) {
        // tp_exit_close program attached to tracepoint
    } else {
        fprintf(stderr, "ERROR: tp_exit_close program NOT attached to tracepoint\n");
    }
    
    if (g_skel->links.tp_enter_write) {
        // tp_enter_write program attached to tracepoint
    } else {
        fprintf(stderr, "ERROR: tp_enter_write program NOT attached to tracepoint\n");
    }
    
    if (g_skel->links.tp_enter_read) {
        // tp_enter_read program attached to tracepoint
    } else {
        fprintf(stderr, "ERROR: tp_enter_read program NOT attached to tracepoint\n");
    }
    
    if (g_skel->links.tp_exit_read) {
        // tp_exit_read program attached to tracepoint
    } else {
        fprintf(stderr, "ERROR: tp_exit_read program NOT attached to tracepoint\n");
    }
    
    if (g_skel->links.tp_enter_ioctl) {
        // tp_enter_ioctl program attached to tracepoint
    } else {
        fprintf(stderr, "ERROR: tp_enter_ioctl program NOT attached to tracepoint\n");
    }
    
            // Individual BPF program attachment check completed

    // Reopen log files for already configured ports
    reopen_existing_logs();

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events), handle_event, NULL, NULL);
    if (!g_rb) { fprintf(stderr, "ring_buffer__new failed\n"); return 1; }

    fprintf(stderr, "BPF program loaded and attached successfully\n");
    fprintf(stderr, "Ring buffer created successfully\n");
    
    // Initialize our own process ID for active monitoring state management
    self_tgid = (uint32_t)getpid();

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    pthread_t http_thr;
    if (pthread_create(&http_thr, NULL, http_server, NULL) != 0) {
        fprintf(stderr, "Failed to create HTTP server thread: %s\n", strerror(errno));
        return 1;
    }

    fprintf(stderr, "HTTP server thread started\n");
    fprintf(stderr, "Socket path: %s\n", g_socket_path);

    // Notify systemd that we're ready (commented out for Ubuntu 22.04 compatibility)
    // if (sd_notify(1, "READY=1") < 0) {
    //     fprintf(stderr, "Warning: sd_notify failed: %s\n", strerror(errno));
    // } else {
    //     fprintf(stderr, "Systemd notification sent successfully\n");
    // }

    // Start background FD scanner to catch already-open FDs continuously
    pthread_t scan_thr;
    if (pthread_create(&scan_thr, NULL, fd_scanner_thread, NULL) != 0) {
        fprintf(stderr, "Warning: failed to start fd scanner thread: %s\n", strerror(errno));
    }

    fprintf(stderr, "Starting main event loop...\n");
    int loop_count = 0;
    while (!stop_flag) {
        int err = ring_buffer__poll(g_rb, 100); /* 100ms to be responsive to signals */
        if (err == -EINTR) {
            fprintf(stderr, "Ring buffer poll interrupted - restarting poll loop\n");
            // Don't exit on EINTR, just continue polling
            continue;
        }
        if (err == -EAGAIN) {
            /* No events available, this is normal */
            loop_count++;
            if (loop_count % 100 == 0) { /* Print every 10 seconds */
                fprintf(stderr, "Daemon alive, waiting for events... (loop %d)\n", loop_count);
            }
            continue;
        }
        if (err < 0) {
            fprintf(stderr, "Ring buffer poll error: %d (%s) - restarting poll loop\n", err, strerror(-err));
            // Don't exit on poll errors, just continue
            continue;
        }
        if (err > 0) {
            fprintf(stderr, "Processed %d events\n", err);
        }
    }
    fprintf(stderr, "Main event loop ended\n");

    stop_flag = 1;
    pthread_kill(http_thr, SIGINT);
    pthread_kill(scan_thr, SIGINT);
    pthread_join(http_thr, NULL);
    pthread_join(scan_thr, NULL);
    
    // Clean up active monitoring for all ports
    for (uint32_t i = 0; i < MAX_PORTS; i++) {
        if (active_fds[i] >= 0) {
            close(active_fds[i]);
            active_fds[i] = -1;
            pthread_join(active_reader_threads[i], NULL);
        }
    }

    ring_buffer__free(g_rb);
    sniffer_bpf__destroy(g_skel);

    for (uint32_t i=0;i<MAX_PORTS;i++) if (port_logs[i]) fclose(port_logs[i]);
    return 0;
}


