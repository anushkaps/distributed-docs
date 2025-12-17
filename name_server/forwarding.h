#ifndef FORWARDING_H
#define FORWARDING_H

#include "../common.h"

void return_ss_info(int fd, Packet p);
void forward_create_delete(int fd, Packet p);
void forward_to_ss(int fd, Packet p);
void forward_access_control(int fd, Packet p);

#endif // FORWARDING_H

