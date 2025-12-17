// client.h
#ifndef CLIENT_H
#define CLIENT_H

#define PORT 8080
#define BUF_SIZE 1024

// === Buffer Sizes ===
#define CLIENT_BUFFER_SIZE_2048 2048
#define CLIENT_BUFFER_SIZE_4096 4096
#define CLIENT_BUFFER_SIZE_256 256
#define CLIENT_BUFFER_SIZE_64 64

// === String Length Constants ===
#define CLIENT_USERNAME_SIZE 64
#define CLIENT_SS_INFO_SIZE 256

int connect_to_ss(const char* ss_ip, int ss_port, const char* username);

#endif
