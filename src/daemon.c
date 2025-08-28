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
#include <systemd/sd-daemon.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sniffer.skel.h"

#define MAX_PORTS 16
#define DEFAULT_HTTP_PORT 12768
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

static void log_event_json(const struct event *e)
{
    uint32_t idx = e->port_idx;
    if (idx >= MAX_PORTS) return;
    FILE *f = port_logs[idx];
    if (!f) return;
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
    pthread_mutex_lock(&ports_mu);
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
    return (int)idx;
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
    } else if (!strncmp(buf, "GET /logs/", 11)) {
        int idx = -1;
        const char *p = buf + 11;
        if (*p >= '0' && *p <= '9') { idx = atoi(p); }
        if (idx < 0 || idx >= (int)MAX_PORTS) { http_send(cfd, 400, "text/plain", "bad index"); close(cfd); return; }
        pthread_mutex_lock(&ports_mu);
        FILE *f = port_logs[idx];
        if (!f) {
            // Try to reopen the log file if it was closed (e.g., after daemon restart)
            const char *devpath = ports[idx];
            if (devpath[0] != '\0' && log_paths[idx][0] != '\0') {
                f = fopen(log_paths[idx], "r");
                if (f) {
                    // Store the reopened file for reading
                    port_logs[idx] = f;
                }
            }
        }
        if (!f) { pthread_mutex_unlock(&ports_mu); http_send(cfd, 404, "text/plain", "no log"); close(cfd); return; }
        int fd = fileno(f);
        off_t cur = lseek(fd, 0, SEEK_CUR);
        off_t sz = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        char *body = NULL; size_t blen = (size_t)sz;
        body = (char*)malloc(blen + 1);
        if (!body) { lseek(fd, cur, SEEK_SET); pthread_mutex_unlock(&ports_mu); http_send(cfd, 500, "text/plain", "oom"); close(cfd); return; }
        size_t rd = fread(body, 1, blen, f);
        lseek(fd, cur, SEEK_SET);
        pthread_mutex_unlock(&ports_mu);
        body[rd] = '\0';
        dprintf(cfd, "HTTP/1.1 200\r\nContent-Type: application/x-ndjson\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", rd);
        if (rd) write(cfd, body, rd);
        free(body);
    } else if (!strncmp(buf, "GET /stream/", 13)) {
        int idx = -1;
        const char *p = buf + 13;
        if (*p >= '0' && *p <= '9') { idx = atoi(p); }
        if (idx < 0 || idx >= (int)MAX_PORTS) { http_send(cfd, 400, "text/plain", "bad index"); close(cfd); return; }
        pthread_mutex_lock(&ports_mu);
        FILE *f = port_logs[idx];
        if (!f) {
            // Try to reopen the log file if it was closed (e.g., after daemon restart)
            const char *devpath = ports[idx];
            if (devpath[0] != '\0' && log_paths[idx][0] != '\0') {
                f = fopen(log_paths[idx], "r");
                if (f) {
                    // Store the reopened file for reading
                    port_logs[idx] = f;
                }
            }
        }
        if (!f) { pthread_mutex_unlock(&ports_mu); http_send(cfd, 404, "text/plain", "no log"); close(cfd); return; }
        int fd = fileno(f);
        off_t cur = lseek(fd, 0, SEEK_END);
        pthread_mutex_unlock(&ports_mu);
        dprintf(cfd, "HTTP/1.1 200\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
        char chunk[4096];
        while (!stop_flag) {
            pthread_mutex_lock(&ports_mu);
            f = port_logs[idx];
            if (!f) { pthread_mutex_unlock(&ports_mu); break; }
            int fd2 = fileno(f);
            off_t end = lseek(fd2, 0, SEEK_END);
            if (end > cur) {
                size_t toread = (size_t)((end - cur) > (off_t)sizeof(chunk) ? sizeof(chunk) : (end - cur));
                lseek(fd2, cur, SEEK_SET);
                size_t rd = fread(chunk, 1, toread, f);
                cur += rd;
                pthread_mutex_unlock(&ports_mu);
                if (rd) {
                    dprintf(cfd, "%zx\r\n", rd);
                    write(cfd, chunk, rd);
                    dprintf(cfd, "\r\n");
                }
            } else { pthread_mutex_unlock(&ports_mu); usleep(100000); }
        }
        dprintf(cfd, "0\r\n\r\n");
    } else if (!strncmp(buf, "DELETE /ports/", 15)) {
        int idx = -1;
        const char *p = buf + 15;
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
        if (!dev[0] || !logp[0]) { http_send(cfd, 400, "text/plain", "missing dev/log"); close(cfd); return; }
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
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) { fprintf(stderr, "socket: %s\n", strerror(errno)); return NULL; }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
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
    g_skel = sniffer_bpf__open();
    if (!g_skel) { fprintf(stderr, "open skel failed\n"); return 1; }
    if (sniffer_bpf__load(g_skel)) { fprintf(stderr, "load skel failed (need BTF)\n"); return 1; }
    if (sniffer_bpf__attach(g_skel)) { fprintf(stderr, "attach failed\n"); return 1; }

    g_rb = ring_buffer__new(bpf_map__fd(g_skel->maps.events), handle_event, NULL, NULL);
    if (!g_rb) { fprintf(stderr, "ring_buffer__new failed\n"); return 1; }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    pthread_t http_thr;
    pthread_create(&http_thr, NULL, http_server, NULL);

    // Notify systemd that we're ready
    sd_notify(0, "READY=1");

    while (!stop_flag) {
        int err = ring_buffer__poll(g_rb, 100); /* 100ms to be responsive to signals */
        if (err == -EINTR) break;
    }

    stop_flag = 1;
    pthread_kill(http_thr, SIGINT);
    pthread_join(http_thr, NULL);

    ring_buffer__free(g_rb);
    sniffer_bpf__destroy(g_skel);

    for (uint32_t i=0;i<MAX_PORTS;i++) if (port_logs[i]) fclose(port_logs[i]);
    return 0;
}


