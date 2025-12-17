#ifndef COMMON_NET_H
#define COMMON_NET_H

#include <stddef.h>
#include <sys/types.h>

int net_create_socket();
int net_connect(const char *ip, int port);

ssize_t net_send(int fd, const void *buf, size_t len);
ssize_t net_recv(int fd, void *buf, size_t len);

void net_close(int fd);

int net_local_info(int fd, char *ip_out, int ip_len, int *port_out);
int net_peer_info(int fd, char *ip_out, int ip_len, int *port_out);
int net_listen(int port, int backlog);

#endif