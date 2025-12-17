#include "connection.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int net_create_socket() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("[NET] socket");
    }
    return fd;
}

int net_connect(const char *ip, int port) {
    int fd = net_create_socket();
    if (fd < 0) return -1;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        perror("[NET] inet_pton");
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[NET] connect");
        close(fd);
        return -1;
    }

    return fd;
}

ssize_t net_send(int fd, const void *buf, size_t len) {
    ssize_t total_sent = 0;
    const char *ptr = buf;

    while (total_sent < (ssize_t)len) {
        ssize_t s = send(fd, ptr + total_sent, len - total_sent, 0);
        if (s <= 0) {
            perror("[NET] send");
            return -1;
        }
        total_sent += s;
    }

    return total_sent;
}

ssize_t net_recv(int fd, void *buf, size_t len) {
    ssize_t r = recv(fd, buf, len, 0);
    if (r < 0)
        perror("[NET] recv");

    return r;
}

void net_close(int fd) {
    if (fd >= 0) close(fd);
}

int net_local_info(int fd, char *ip_out, int ip_len, int *port_out) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    if (getsockname(fd, (struct sockaddr *)&addr, &len) < 0) {
        perror("[NET] getsockname");
        return -1;
    }

    inet_ntop(AF_INET, &addr.sin_addr, ip_out, ip_len);
    *port_out = ntohs(addr.sin_port);
    return 0;
}

int net_peer_info(int fd, char *ip_out, int ip_len, int *port_out) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    if (getpeername(fd, (struct sockaddr *)&addr, &len) < 0) {
        perror("[NET] getpeername");
        return -1;
    }

    inet_ntop(AF_INET, &addr.sin_addr, ip_out, ip_len);
    *port_out = ntohs(addr.sin_port);
    return 0;
}

int net_listen(int port, int backlog) {
    int fd = net_create_socket();
    if (fd < 0) return -1;

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt,  sizeof(opt)) < 0) {
        perror("[NET] setsockopt");
        close(fd);
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[NET] bind");
        close(fd);
        return -1;
    }

    if (listen(fd, backlog) < 0) {
        perror("[NET] listen");
        close(fd);
        return -1;
    }

    return fd;
}