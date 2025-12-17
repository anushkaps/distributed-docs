#ifndef HANDLERS_H
#define HANDLERS_H

#include "../common.h"

void handle_view(int fd, Packet p);
void handle_list(int fd);
void handle_info(int fd, Packet p);
int handle_addaccess(Packet p);  // Returns 0 on success, -1 if file not found, -2 if not owner
int handle_remaccess(Packet p);  // Returns 0 on success, -1 if file not found, -2 if not owner
void handle_exec(int fd, Packet p);

#endif // HANDLERS_H

