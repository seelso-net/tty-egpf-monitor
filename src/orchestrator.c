// SPDX-License-Identifier: MIT
// Orchestrator that:
//  - loads CO-RE eBPF sniffer (syscall-tracepoint backend)
//  - ACTIVE: opens port O_RDONLY, applies termios (baud/etc.), reads and logs
//  - on first foreign open(): closes port and switches to PASSIVE sniffing
//  - when foreign openers drop to zero: re-enters ACTIVE

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sniffer.skel.h"

/* Mirror of the ringbuf event from sniffer.bpf.c (keep in sync!) */
struct event {
    uint64_t ts, dev;      /* dev is 0 in syscall backend; kept for ABI */
    uint32_t pid, tgid;
    char     comm[16];
    uint32_t type;         // 1=open,2=close,3=read,4=write,5=ioctl
    int32_t  ret;          // read/ioctl return
    uint32_t cmd;          // ioctl cmd
    uint32_t dir;          // 1=write, 0=read
    uint32_t data_len;
    uint32_t data_trunc;
    uint8_t  data[256];    // MAX_DATA
};

static volatile sig_atomic_t stop_flag = 0;
static void on_sigint(int s){ (void)s; stop_flag = 1; }

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr); exit(1);
}

static void set_termios(int fd, int speed, int databits, char parity, int stopbits, bool hwflow) {
    struct termios tio;
    if (tcgetattr(fd, &tio) == -1) die("tcgetattr: %s", strerror(errno));
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
        default: sp = B115200; fprintf(stderr, "Unsupported speed %d, defaulting to 115200\n", speed);
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

    if (tcsetattr(fd, TCSANOW, &tio) == -1) die("tcsetattr: %s", strerror(errno));
}

static FILE *logf;
static const char *devpath;
static int  cfg_speed = 115200, cfg_databits = 8, cfg_stopbits = 1;
static char cfg_parity = 'N';
static bool cfg_hwflow = false;

static int active_fd = -1;
static pthread_t active_reader_thr;

static void *active_reader(void *arg) {
    (void)arg;
    unsigned char buf[4096];
    while (!stop_flag && active_fd >= 0) {
        ssize_t n = read(active_fd, buf, sizeof buf);
        if (n > 0) {
            struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
            fprintf(logf,
                    "{\"ts\":%" PRIu64 ".%09ld,\"event\":\"active_read\",\"n\":%zd,\"data\":\"",
                    (uint64_t)ts.tv_sec, ts.tv_nsec, n);
            for (ssize_t i = 0; i < n; i++) fprintf(logf, "%02x", buf[i]);
            fprintf(logf, "\"}\n");
            fflush(logf);
        } else if (n == 0) {
            usleep(1000);
        } else {
            if (errno == EAGAIN || errno == EINTR) continue;
            if (errno == EBADF) break;  // fd closed by main thread; exit cleanly
            fprintf(stderr, "active read error: %s\n", strerror(errno));
            break;
        }
    }
    return NULL;
}

enum { ST_ACTIVE=1, ST_PASSIVE=2 };
static int state = ST_PASSIVE; // start passive; switch to ACTIVE after BPF up

static int      foreign_openers = 0;
static uint32_t self_tgid = 0;

// Map some common ioctl names for readability
static const char *ioctl_name(unsigned int cmd) {
    switch (cmd) {
        case 0x5401: return "TCGETS";
        case 0x5402: return "TCSETS";
        case 0x5403: return "TCSETSW";
        case 0x5404: return "TCSETSF";
        case 0x5415: return "TCSBRK";
        case 0x5416: return "TCSBRKP";
        case 0x5418: return "TCFLSH";
        case 0x5419: return "TCGETS2";
        case 0x540B: return "TIOCMGET";
        case 0x541F: return "TIOCMSET";
        case 0x5420: return "TIOCMBIS";
        case 0x5421: return "TIOCMBIC";
        default: return NULL;
    }
}

static int handle_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len < sizeof(struct event)) return 0;
    const struct event *e = data;

    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    const char *etype =
        e->type == 1 ? "open" :
        e->type == 2 ? "close" :
        e->type == 3 ? "read" :
        e->type == 4 ? "write" : "ioctl";

    fprintf(logf,
        "{\"ts\":%" PRIu64 ".%09ld,"
        "\"type\":\"%s\",\"pid\":%u,\"tgid\":%u,\"comm\":\"%.*s\"",
        (uint64_t)ts.tv_sec, ts.tv_nsec, etype, e->pid, e->tgid, 16, e->comm);

    if (e->type == 3 || e->type == 4) {
        fprintf(logf, ",\"dir\":\"%s\",\"len\":%u,\"trunc\":%u,\"data\":\"",
                e->type==4?"app2dev":"dev2app", e->data_len, e->data_trunc);
        for (unsigned i=0;i<e->data_len;i++) fprintf(logf, "%02x", e->data[i]);
        fprintf(logf, "\"");
    } else if (e->type == 5) {
        const char *nm = ioctl_name(e->cmd);
        if (nm) fprintf(logf, ",\"ioctl\":\"%s\",\"cmd\":%u", nm, e->cmd);
        else    fprintf(logf, ",\"ioctl\":\"0x%x\",\"cmd\":%u", e->cmd, e->cmd);
    }
    fprintf(logf, "}\n");
    fflush(logf);

    // State transitions based on open/close
    if (e->type == 1 /*OPEN*/) {
        if (e->tgid != self_tgid) {
            if (foreign_openers == 0 && state == ST_ACTIVE) {
                if (active_fd >= 0) {
                    close(active_fd);
                    active_fd = -1;
                    pthread_join(active_reader_thr, NULL);  // ensure reader stopped
                }
                state = ST_PASSIVE;
                fprintf(stderr, "[state] ACTIVE -> PASSIVE (foreign open)\n");
            }
            foreign_openers++;
        }
    } else if (e->type == 2 /*CLOSE*/) {
        if (e->tgid != self_tgid) {
            if (foreign_openers > 0) foreign_openers--;
            if (foreign_openers == 0 && state == ST_PASSIVE && !stop_flag) {
                active_fd = open(devpath, O_RDONLY | O_NOCTTY | O_NONBLOCK);
                if (active_fd >= 0) {
                    set_termios(active_fd, cfg_speed, cfg_databits, cfg_parity, cfg_stopbits, cfg_hwflow);
                    pthread_create(&active_reader_thr, NULL, active_reader, NULL);
                    state = ST_ACTIVE;
                    fprintf(stderr, "[state] PASSIVE -> ACTIVE (port free)\n");
                } else {
                    fprintf(stderr, "open(%s) failed: %s\n", devpath, strerror(errno));
                }
            }
        }
    }
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -d /dev/ttyUSBAPP0 [-l logfile.jsonl] [--baud 115200] [--databits 8] [--parity N|E|O] [--stopbits 1|2] [--crtscts]\n",
        prog);
}

int main(int argc, char **argv)
{
    const char *logpath = "serial-sniff.jsonl";
    devpath = NULL;

    for (int i=1;i<argc;i++) {
        if (!strcmp(argv[i], "-d") && i+1<argc) devpath = argv[++i];
        else if (!strcmp(argv[i], "-l") && i+1<argc) logpath = argv[++i];
        else if (!strcmp(argv[i], "--baud") && i+1<argc) cfg_speed = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--databits") && i+1<argc) cfg_databits = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--parity") && i+1<argc) cfg_parity = argv[++i][0];
        else if (!strcmp(argv[i], "--stopbits") && i+1<argc) cfg_stopbits = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--crtscts")) cfg_hwflow = true;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "Unknown arg: %s\n", argv[i]); usage(argv[0]); return 2; }
    }
    if (!devpath) { usage(argv[0]); return 2; }

    logf = fopen(logpath, "a");
    if (!logf) die("open log %s: %s", logpath, strerror(errno));

    // BPF open + load
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    struct sniffer_bpf *skel = sniffer_bpf__open();
    if (!skel) die("sniffer_bpf__open failed");
    if (sniffer_bpf__load(skel)) die("sniffer_bpf__load failed (need BTF)");

    // Set target *path* (syscall backend)
    {
        uint32_t idx0 = 0;
        char val[256] = {0};
        strncpy(val, devpath, sizeof(val)-1);
        int pfd = bpf_map__fd(skel->maps.target_path);
        if (pfd < 0) die("map fd(target_path) invalid");
        if (bpf_map_update_elem(pfd, &idx0, val, BPF_ANY))
            die("update target_path failed");
    }

    // Attach after map init
    if (sniffer_bpf__attach(skel))
        die("sniffer_bpf__attach failed");

    // Identify ourselves so BPF-driven state logic ignores our own opens/closes
    self_tgid = (uint32_t)getpid();

    // Ring buffer
    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.events),
                         handle_event, NULL, NULL);
    if (!rb) die("ring_buffer__new failed");

    // Enter ACTIVE initially if port is free (best-effort)
    active_fd = open(devpath, O_RDONLY | O_NOCTTY | O_NONBLOCK);
    if (active_fd >= 0) {
        set_termios(active_fd, cfg_speed, cfg_databits, cfg_parity, cfg_stopbits, cfg_hwflow);
        pthread_create(&active_reader_thr, NULL, active_reader, NULL);
        state = ST_ACTIVE;
        fprintf(stderr, "[state] initial ACTIVE (opened %s)\n", devpath);
    } else {
        state = ST_PASSIVE;
        fprintf(stderr, "[state] initial PASSIVE (cannot open %s: %s)\n", devpath, strerror(errno));
    }

    // signals
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    // pump
    while (!stop_flag) {
        int err = ring_buffer__poll(rb, -1); // block until event
        if (err == -EINTR) break;
    }

    // teardown
    if (active_fd >= 0) {
        close(active_fd);
        active_fd = -1;
        pthread_join(active_reader_thr, NULL);
    }

    ring_buffer__free(rb);
    sniffer_bpf__destroy(skel);
    fclose(logf);
    return 0;
}

