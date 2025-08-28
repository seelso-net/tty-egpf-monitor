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
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <systemd/sd-daemon.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sniffer.skel.h"

/* fdkey struct to match BPF definition */
struct fdkey { uint32_t tgid; int32_t fd; };

#define MAX_PORTS 16
#define MAX_PATH 256
struct pathval { char path[MAX_PATH]; };
#define DEFAULT_HTTP_PORT 12768
#define CONFIG_FILE "/var/log/tty-egpf-monitor/daemon.conf"
#define DEFAULT_SOCKET_PATH "/run/tty-egpf-monitord.sock"
#define DEFAULT_LOG_DIR "/var/log/tty-egpf-monitor"

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

static pthread_mutex_t ports_mu = PTHREAD_MUTEX_INITIALIZER;
static char ports[MAX_PORTS][256];
static char log_paths[MAX_PORTS][512];
static FILE *port_logs[MAX_PORTS];
static uint32_t target_count = 0;
static char g_socket_path[256] = DEFAULT_SOCKET_PATH;
static char g_log_dir[256] = DEFAULT_LOG_DIR;

// Forward declarations
static void save_config(void);
static void load_config(void);
static void scan_existing_fds(const char *devpath, uint32_t port_idx);

static void log_event_json(const struct event *e)
{
    uint32_t idx = e->port_idx;
    if (idx >= MAX_PORTS) return;
    FILE *f = port_logs[idx];
    if (!f) {
        fprintf(stderr, "DEBUG: No log file for port_idx=%u\n", idx);
        return;
    }
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    const char *etype = e->type==1?"open":e->type==2?"close":e->type==3?"read":e->type==4?"write":"ioctl";
    fprintf(f,
        "{\"ts\":%" PRIu64 ".%09ld,\"type\":\"%s\",\"pid\":%u,\"tgid\":%u,\"comm\":\"%.*s\",\"port_idx\":%u",
        (uint64_t)ts.tv_sec, ts.tv_nsec, etype, e->pid, e->tgid, 16, e->comm, idx);
    if (e->type == 3 || e->type == 4) {
        fprintf(f, ",\"dir\":\"%s\",\"len\":%u,\"trunc\":%u,\"data\":\"",
                e->type==4?"app2dev":"dev2app", e->data_len, e->data_trunc);
        for (unsigned i=0;i<e->data_len;i++) fprintf(f, "%02x", e->data[i]);
        fprintf(f, "\"");
    } else if (e->type == 5) {
        fprintf(f, ",\"cmd\":%u", e->cmd);
    }
    fprintf(f, "}\n");
    fflush(f);
}

static int handle_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len < sizeof(struct event)) return 0;
    const struct event *e = data;

    /* Kernel now handles fd->port mapping in tp_exit_openat */
    
    pthread_mutex_lock(&ports_mu);
    fprintf(stderr, "DEBUG: Event type=%d, port_idx=%u, comm=%.16s\n", e->type, e->port_idx, e->comm);
    log_event_json(e);
    pthread_mutex_unlock(&ports_mu);
    return 0;
}

static int sync_targets_map(void)
{
    int tp_fd = bpf_map__fd(g_skel->maps.target_path);
    if (tp_fd < 0) return -1;
    for (uint32_t i=0;i<MAX_PORTS;i++) {
        if (bpf_map_update_elem(tp_fd, &i, ports[i], BPF_ANY)) return -1;
        /* (removed device-id map updates) */
    }
    int tc_fd = bpf_map__fd(g_skel->maps.target_count);
    if (tc_fd >= 0) {
        uint32_t k0 = 0;
        if (bpf_map_update_elem(tc_fd, &k0, &target_count, BPF_ANY)) return -1;
    }
    return 0;
}

static int api_add_port(const char *devpath, const char *logpath, char *err, size_t errsz)
{
    pthread_mutex_lock(&ports_mu);
    uint32_t idx = target_count;
    if (idx >= MAX_PORTS) { snprintf(err, errsz, "max ports reached"); pthread_mutex_unlock(&ports_mu); return -1; }
    snprintf(ports[idx], sizeof(ports[idx]), "%s", devpath);
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
    FILE *f = fopen(use_log, "a");
    if (!f) { snprintf(err, errsz, "log open: %s", strerror(errno)); ports[idx][0]='\0'; pthread_mutex_unlock(&ports_mu); return -1; }
    port_logs[idx] = f;
    target_count++;
    int rc = sync_targets_map();
    pthread_mutex_unlock(&ports_mu);
    if (rc) { snprintf(err, errsz, "sync map failed"); return -1; }
    
    // Save configuration after adding port
    save_config();
    
    // Scan existing processes for already-open fds to this device
    scan_existing_fds(devpath, idx);
    
    return (int)idx;
}

static void save_config(void)
{
    FILE *f = fopen(CONFIG_FILE, "w");
    if (!f) {
        fprintf(stderr, "DEBUG: Failed to save config: %s\n", strerror(errno));
        return;
    }
    
    fprintf(f, "target_count=%u\n", target_count);
    for (uint32_t i = 0; i < target_count; i++) {
        fprintf(f, "port[%u]=%s\n", i, ports[i]);
        fprintf(f, "log_path[%u]=%s\n", i, log_paths[i]);
    }
    fclose(f);
    fprintf(stderr, "DEBUG: Configuration saved to %s\n", CONFIG_FILE);
}

static void load_config(void)
{
    FILE *f = fopen(CONFIG_FILE, "r");
    if (!f) {
        fprintf(stderr, "DEBUG: No config file found: %s\n", CONFIG_FILE);
        return;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0; // Remove newline
        
        if (strncmp(line, "target_count=", 13) == 0) {
            target_count = atoi(line + 13);
            fprintf(stderr, "DEBUG: Loaded target_count=%u\n", target_count);
        } else if (strncmp(line, "port[", 5) == 0) {
            int idx;
            char path[256];
            if (sscanf(line, "port[%d]=%s", &idx, path) == 2 && idx >= 0 && idx < MAX_PORTS) {
                snprintf(ports[idx], sizeof(ports[idx]), "%s", path);
                fprintf(stderr, "DEBUG: Loaded port[%d]=%s\n", idx, ports[idx]);
            }
        } else if (strncmp(line, "log_path[", 9) == 0) {
            int idx;
            char path[512];
            if (sscanf(line, "log_path[%d]=%s", &idx, path) == 2 && idx >= 0 && idx < MAX_PORTS) {
                snprintf(log_paths[idx], sizeof(log_paths[idx]), "%s", path);
                fprintf(stderr, "DEBUG: Loaded log_path[%d]=%s\n", idx, log_paths[idx]);
            }
        }
    }
    fclose(f);
    fprintf(stderr, "DEBUG: Configuration loaded from %s\n", CONFIG_FILE);
}

static void reopen_existing_logs(void)
{
    fprintf(stderr, "DEBUG: reopen_existing_logs called, target_count=%u\n", target_count);
    
    // Load configuration from file
    load_config();
    
    // Sync the loaded configuration to BPF maps
    int tp_fd = bpf_map__fd(g_skel->maps.target_path);
    int tc_fd = bpf_map__fd(g_skel->maps.target_count);
    
    if (tp_fd >= 0 && tc_fd >= 0) {
        // Update target_count in BPF map
        uint32_t k0 = 0;
        if (bpf_map_update_elem(tc_fd, &k0, &target_count, BPF_ANY) == 0) {
            fprintf(stderr, "DEBUG: Updated BPF map target_count=%u\n", target_count);
        }
        
        // Update port configurations in BPF map
        for (uint32_t i = 0; i < target_count; i++) {
            if (ports[i][0] != '\0') {
                struct pathval tp;
                snprintf(tp.path, sizeof(tp.path), "%s", ports[i]);
                if (bpf_map_update_elem(tp_fd, &i, &tp, BPF_ANY) == 0) {
                    fprintf(stderr, "DEBUG: Updated BPF map port[%u]='%s'\n", i, ports[i]);
                }
            }
        }
    }
    
    pthread_mutex_lock(&ports_mu);
    for (uint32_t i = 0; i < target_count; i++) {
        fprintf(stderr, "DEBUG: Checking port[%u]='%s', log_paths[%u]='%s', port_logs[%u]=%p\n", 
                i, ports[i], i, log_paths[i], i, port_logs[i]);
        if (ports[i][0] != '\0' && !port_logs[i]) {
            // Reopen log file for this port
            FILE *f = fopen(log_paths[i], "a");
            if (f) {
                port_logs[i] = f;
                fprintf(stderr, "DEBUG: Reopened log file for port %s\n", ports[i]);
            } else {
                fprintf(stderr, "DEBUG: Failed to reopen log file for port %s: %s\n", ports[i], strerror(errno));
            }
        }
    }
    pthread_mutex_unlock(&ports_mu);
    
    // Also scan for already-open fds
    for (uint32_t i = 0; i < target_count; i++) {
        if (ports[i][0] != '\0') {
            scan_existing_fds(ports[i], i);
        }
    }
}

static void scan_existing_fds(const char *devpath, uint32_t port_idx)
{
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return;
    
    struct dirent *pid_entry;
    char fd_path[512], link_path[512];
    
    while ((pid_entry = readdir(proc_dir))) {
        // Skip non-numeric entries (not PIDs)
        if (!isdigit(pid_entry->d_name[0])) continue;
        
        uint32_t tgid = atoi(pid_entry->d_name);
        snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", pid_entry->d_name);
        
        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) continue;
        
        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir))) {
            if (!isdigit(fd_entry->d_name[0])) continue;
            
            snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_entry->d_name);
            char target[256];
            ssize_t len = readlink(link_path, target, sizeof(target) - 1);
            if (len > 0) {
                target[len] = '\0';
                if (strcmp(target, devpath) == 0) {
                    // Found a match! Update BPF maps
                    int fd = atoi(fd_entry->d_name);
                    struct fdkey k = { .tgid = tgid, .fd = fd };
                    uint8_t one = 1;
                    
                    int fd_interest_fd = bpf_map__fd(g_skel->maps.fd_interest);
                    int fd_portidx_fd = bpf_map__fd(g_skel->maps.fd_portidx);
                    
                    if (fd_interest_fd >= 0) {
                        bpf_map_update_elem(fd_interest_fd, &k, &one, BPF_ANY);
                    }
                    if (fd_portidx_fd >= 0) {
                        bpf_map_update_elem(fd_portidx_fd, &k, &port_idx, BPF_ANY);
                    }
                    
                    fprintf(stderr, "DEBUG: Found existing fd %d in process %u for %s\n", 
                            fd, tgid, devpath);
                }
            }
        }
        closedir(fd_dir);
    }
    closedir(proc_dir);
}

static int api_remove_port(int idx, char *err, size_t errsz)
{
    if (idx < 0 || idx >= (int)MAX_PORTS) { snprintf(err, errsz, "bad index"); return -1; }
    pthread_mutex_lock(&ports_mu);
    if (ports[idx][0] == '\0' && !port_logs[idx]) { pthread_mutex_unlock(&ports_mu); snprintf(err, errsz, "not found"); return -1; }
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
    dprintf(cfd, "HTTP/1.1 %d\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            code, ctype, body?strlen(body):0, body?body:"");
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
            off += snprintf(body+off, sizeof(body)-off, "%s{\"idx\":%u,\"dev\":\"%s\"}", i?",":"", i, ports[i]);
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
        char logpath_local[512] = {0};
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

        FILE *rf = fopen(logpath_local, "r");
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

        char logpath_local[512] = {0};
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

        FILE *rf = fopen(logpath_local, "r");
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
        char dev[256] = {0}, logp[256] = {0};
        // naive JSON extraction
        char *dp = strstr(body, "\"dev\"");
        char *lp = strstr(body, "\"log\"");
        if (dp) {
            dp = strchr(dp, ':'); if (dp) { dp++; while (*dp==' '||*dp=='\t') dp++; if (*dp=='\"') { dp++; char *e=strchr(dp,'\"'); if (e) { size_t l=e-dp; if (l>=sizeof(dev)) l=sizeof(dev)-1; memcpy(dev,dp,l); } } }
        }
        if (lp) {
            lp = strchr(lp, ':'); if (lp) { lp++; while (*lp==' '||*lp=='\t') lp++; if (*lp=='\"') { lp++; char *e=strchr(lp,'\"'); if (e) { size_t l=e-lp; if (l>=sizeof(logp)) l=sizeof(logp)-1; memcpy(logp,lp,l); } } }
        }
        if (!dev[0]) { http_send(cfd, 400, "text/plain", "missing dev"); close(cfd); return; }
        // Generate default log path if not provided
        if (!logp[0]) {
            const char *base = strrchr(dev, '/');
            base = base ? base + 1 : dev;
            snprintf(logp, sizeof(logp), "%s/%s.jsonl", g_log_dir, base);
        }
        char err[128];
        int idx = api_add_port(dev, logp, err, sizeof err);
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
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            fprintf(stderr, "Usage: %s [--socket %s] [--log-dir %s]\n", argv[0], DEFAULT_SOCKET_PATH, DEFAULT_LOG_DIR);
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
    
    // Add diagnostic information
    fprintf(stderr, "libbpf version: %s\n", "checking...");
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
    
    g_skel = sniffer_bpf__open();
    if (!g_skel) { 
        fprintf(stderr, "open skel failed: %s\n", strerror(errno));
        return 1; 
    }
    
    int load_err = sniffer_bpf__load(g_skel);
    if (load_err) { 
        fprintf(stderr, "load skel failed (err=%d): %s\n", load_err, strerror(-load_err));
        return 1; 
    }
    
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
        return 1; 
    }

    // Reopen log files for already configured ports
    reopen_existing_logs();

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events), handle_event, NULL, NULL);
    if (!g_rb) { fprintf(stderr, "ring_buffer__new failed\n"); return 1; }

    fprintf(stderr, "BPF program loaded and attached successfully\n");
    fprintf(stderr, "Ring buffer created successfully\n");

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    pthread_t http_thr;
    if (pthread_create(&http_thr, NULL, http_server, NULL) != 0) {
        fprintf(stderr, "Failed to create HTTP server thread: %s\n", strerror(errno));
        return 1;
    }

    fprintf(stderr, "HTTP server thread started\n");
    fprintf(stderr, "Socket path: %s\n", g_socket_path);

    // Notify systemd that we're ready
    if (sd_notify(1, "READY=1") < 0) {
        fprintf(stderr, "Warning: sd_notify failed: %s\n", strerror(errno));
    } else {
        fprintf(stderr, "Systemd notification sent successfully\n");
    }

    fprintf(stderr, "Starting main event loop...\n");
    int loop_count = 0;
    while (!stop_flag) {
        int err = ring_buffer__poll(g_rb, 100); /* 100ms to be responsive to signals */
        if (err == -EINTR) {
            fprintf(stderr, "Ring buffer poll interrupted\n");
            break;
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
            fprintf(stderr, "Ring buffer poll error: %d (%s)\n", err, strerror(-err));
            break;
        }
        if (err > 0) {
            fprintf(stderr, "Processed %d events\n", err);
        }
    }
    fprintf(stderr, "Main event loop ended\n");

    stop_flag = 1;
    pthread_kill(http_thr, SIGINT);
    pthread_join(http_thr, NULL);

    ring_buffer__free(g_rb);
    sniffer_bpf__destroy(g_skel);

    for (uint32_t i=0;i<MAX_PORTS;i++) if (port_logs[i]) fclose(port_logs[i]);
    return 0;
}


