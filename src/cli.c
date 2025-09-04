// SPDX-License-Identifier: MIT
// tty-egpf-monitor: CLI client for tty-egpf-monitord

#define _GNU_SOURCE
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define DEFAULT_SOCKET_PATH "/run/tty-egpf-monitord.sock"

static int unix_connect_socket(const char *sockpath)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return -1; }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("connect"); close(s); return -1; }
    return s;
}

static int http_post_add_port(const char *sock, const char *dev, const char *log, int baudrate)
{
    int s = unix_connect_socket(sock);
    if (s < 0) return 1;
    char body[512];
    snprintf(body, sizeof(body), "{\"dev\":\"%s\",\"log\":\"%s\",\"baudrate\":%d}", dev, log, baudrate);
    dprintf(s, "POST /ports HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(body), body);
    char buf[4096]; ssize_t n;
    while ((n = read(s, buf, sizeof(buf)-1)) > 0) { buf[n] = 0; fwrite(buf,1,n,stdout); }
    close(s);
    return 0;
}

static int http_get_ports(const char *sock)
{
    int s = unix_connect_socket(sock);
    if (s < 0) return 1;
    dprintf(s, "GET /ports HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    char buf[4096]; ssize_t n;
    while ((n = read(s, buf, sizeof(buf)-1)) > 0) { buf[n] = 0; fwrite(buf,1,n,stdout); }
    close(s);
    return 0;
}

/* Fetch /ports JSON into caller-provided buffer (body only). Returns 0 on success. */
static int http_fetch_ports_json(const char *sock, char *out, size_t out_sz)
{
    int s = unix_connect_socket(sock);
    if (s < 0) return 1;
    dprintf(s, "GET /ports HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    size_t off = 0; ssize_t n; char buf[4096];
    /* Read entire HTTP response and extract body. We find the first \r\n\r\n and copy after it. */
    /* Accumulate response first (bounded). */
    while ((n = read(s, buf, sizeof(buf))) > 0) {
        if (off + (size_t)n < out_sz) {
            memcpy(out + off, buf, (size_t)n);
            off += (size_t)n;
        } else {
            /* Truncate if too large (should not happen: small JSON) */
            size_t can = out_sz > 0 ? out_sz - 1 : 0;
            if (can > 0) {
                size_t take = can - (off < can ? off : can);
                if (take > 0) memcpy(out + off, buf, take);
                off = can;
            }
        }
    }
    close(s);
    if (out_sz == 0) return 1;
    out[off < out_sz ? off : out_sz - 1] = '\0';
    /* Find body */
    char *body = strstr(out, "\r\n\r\n");
    if (!body) return 1;
    body += 4;
    /* Move body to beginning for easier parsing */
    size_t body_len = strlen(body);
    memmove(out, body, body_len + 1);
    return 0;
}

/* Resolve device path to index by scanning /ports JSON: [{"idx":N,"dev":"PATH"},...] */
static int resolve_dev_to_idx(const char *sock, const char *dev)
{
    char resp[8192];
    if (http_fetch_ports_json(sock, resp, sizeof(resp)) != 0) return -1;
    /* Look for the device string and then scan backward/forward for idx. */
    char needle[512];
    snprintf(needle, sizeof(needle), "\"dev\":\"%s\"", dev);
    char *p = strstr(resp, needle);
    if (!p) return -1;
    /* Search backwards up to some chars for "idx":number */
    char *start = resp;
    char *seg = p;
    int idx = -1;
    for (int back = 0; back < 128 && seg > start; back++, seg--) {
        if (seg[0] == 'i' && !strncmp(seg, "idx\":", 5)) {
            seg += 5;
            idx = atoi(seg);
            break;
        }
        if (seg[0] == '"' && seg > start && seg[-1] == '{') {
            /* reached object start without finding idx */
            break;
        }
    }
    if (idx < 0) {
        /* Try forward search from object start */
        char *obj = seg;
        char *idxp = strstr(obj, "\"idx\":");
        if (idxp) idx = atoi(idxp + 6);
    }
    return idx;
}

/* Parse argument that may be an index or a device path; returns index or -1. */
static int parse_idx_or_dev(const char *sock, const char *arg)
{
    char *endp = NULL;
    long v = strtol(arg, &endp, 10);
    if (endp && *endp == '\0') return (int)v;
    return resolve_dev_to_idx(sock, arg);
}

static int http_get_logs(const char *sock, int idx)
{
    int s = unix_connect_socket(sock);
    if (s < 0) return 1;
    dprintf(s, "GET /logs/%d HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", idx);
    char buf[4096]; ssize_t n;
    while ((n = read(s, buf, sizeof(buf)-1)) > 0) { buf[n] = 0; fwrite(buf,1,n,stdout); }
    close(s);
    return 0;
}

static int http_stream_logs(const char *sock, int idx)
{
    int s = unix_connect_socket(sock);
    if (s < 0) return 1;
    dprintf(s, "GET /stream/%d HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", idx);
    char line[8192]; ssize_t n;
    while ((n = read(s, line, sizeof(line)-1)) > 0) { line[n] = 0; fwrite(line,1,n,stdout); fflush(stdout); }
    close(s);
    return 0;
}

static int http_delete_port(const char *sock, int idx)
{
    int s = unix_connect_socket(sock);
    if (s < 0) return 1;
    dprintf(s, "DELETE /ports/%d HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", idx);
    char buf[4096]; ssize_t n;
    while ((n = read(s, buf, sizeof(buf)-1)) > 0) { buf[n] = 0; fwrite(buf,1,n,stdout); }
    close(s);
    return 0;
}

static void usage(const char *p)
{
    fprintf(stderr,
        "Usage: %s [--socket %s] <command> [args]\n\n"
        "Commands:\n"
        "  add <dev> [baudrate] [logfile]\n"
        "      Add a monitored serial device.\n"
        "      - dev: device path, e.g. /dev/ttyUSB0\n"
        "      - baudrate: optional, default 115200\n"
        "      - logfile: optional; default under /var/log/tty-egpf-monitor/<basename>.jsonl\n\n"
        "  list\n"
        "      List configured ports with indices.\n\n"
        "  logs <idx|dev>\n"
        "      Download full log for a port by index or device path.\n\n"
        "  stream <idx|dev>\n"
        "      Live stream log (chunked) for a port by index or device path.\n\n"
        "  remove <idx|dev>\n"
        "      Remove a port by index or device path.\n\n"
        "Examples:\n"
        "  %s add /dev/ttyUSB0 115200\n"
        "  %s list\n"
        "  %s stream /dev/ttyUSB0\n"
        "  %s logs 0\n"
        "  %s remove /dev/ttyUSB0\n",
        p, DEFAULT_SOCKET_PATH, p, p, p, p, p);
}

int main(int argc, char **argv)
{
    const char *sock = DEFAULT_SOCKET_PATH;
    int i = 1;
    while (i < argc) {
        if (!strcmp(argv[i], "--socket") && i+1<argc) { sock = argv[i+1]; i+=2; }
        else break;
    }
    if (i >= argc) { usage(argv[0]); return 2; }
    const char *cmd = argv[i++];
    if (!strcmp(cmd, "add")) {
        if (i >= argc) { usage(argv[0]); return 2; }
        const char *dev = argv[i++];
        int baudrate = 115200;  // Default baudrate
        const char *log = "";
        
        // Check if next argument is baudrate (numeric)
        if (i < argc) {
            char *endp = NULL;
            long baud = strtol(argv[i], &endp, 10);
            if (endp && *endp == '\0' && baud > 0) {
                baudrate = (int)baud;
                i++;
            }
        }
        
        // Check if next argument is log file
        if (i < argc) {
            log = argv[i++];
        }
        
        return http_post_add_port(sock, dev, log, baudrate);
    } else if (!strcmp(cmd, "list")) {
        return http_get_ports(sock);
    } else if (!strcmp(cmd, "logs")) {
        if (i >= argc) { usage(argv[0]); return 2; }
        const char *arg = argv[i++];
        int idx = parse_idx_or_dev(sock, arg);
        if (idx < 0) { fprintf(stderr, "Unknown device or bad index: %s\n", arg); return 1; }
        return http_get_logs(sock, idx);
    } else if (!strcmp(cmd, "stream")) {
        if (i >= argc) { usage(argv[0]); return 2; }
        const char *arg = argv[i++];
        int idx = parse_idx_or_dev(sock, arg);
        if (idx < 0) { fprintf(stderr, "Unknown device or bad index: %s\n", arg); return 1; }
        return http_stream_logs(sock, idx);
    } else if (!strcmp(cmd, "remove")) {
        if (i >= argc) { usage(argv[0]); return 2; }
        const char *arg = argv[i++];
        char *endp = NULL;
        long v = strtol(arg, &endp, 10);
        if (endp && *endp == '\0') {
            return http_delete_port(sock, (int)v);
        } else {
            int s = unix_connect_socket(sock);
            if (s < 0) return 1;
            char body[512];
            snprintf(body, sizeof(body), "{\"dev\":\"%s\"}", arg);
            dprintf(s, "DELETE /ports HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", strlen(body), body);
            char buf[4096]; ssize_t n;
            while ((n = read(s, buf, sizeof(buf)-1)) > 0) { buf[n] = 0; fwrite(buf,1,n,stdout); }
            close(s);
            return 0;
        }
    } else {
        usage(argv[0]);
        return 2;
    }
}


