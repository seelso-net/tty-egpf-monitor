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

static int http_post_add_port(const char *sock, const char *dev, const char *log)
{
    int s = unix_connect_socket(sock);
    if (s < 0) return 1;
    char body[512];
    snprintf(body, sizeof(body), "{\"dev\":\"%s\",\"log\":\"%s\"}", dev, log);
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
        "Usage: %s [--socket %s] <command> [args]\n"
        "Commands:\n"
        "  add <dev> [logfile]      Add monitored port; default log in daemon log dir\n"
        "  list                      List configured ports\n"
        "  logs <idx>                Download full NDJSON log for port idx\n"
        "  stream <idx>              Live stream log for port idx (chunked)\n"
        "  remove <idx|dev>          Remove by index or device path\n",
        p, DEFAULT_SOCKET_PATH);
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
        const char *log = (i < argc) ? argv[i++] : "";
        return http_post_add_port(sock, dev, log);
    } else if (!strcmp(cmd, "list")) {
        return http_get_ports(sock);
    } else if (!strcmp(cmd, "logs")) {
        if (i >= argc) { usage(argv[0]); return 2; }
        int idx = atoi(argv[i++]);
        return http_get_logs(sock, idx);
    } else if (!strcmp(cmd, "stream")) {
        if (i >= argc) { usage(argv[0]); return 2; }
        int idx = atoi(argv[i++]);
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


