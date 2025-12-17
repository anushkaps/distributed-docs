#ifndef COMMAND_HANDLERS_SS_H
#define COMMAND_HANDLERS_SS_H

#include "storage_server.h"

void handle_read_command(int client_fd, Packet *p, const char *username, 
                         const char *client_ip, int client_port, const char *op_name);

void handle_create_command(int client_fd, Packet *p, const char *username,
                           const char *client_ip, int client_port, const char *op_name);

void handle_write_command(int client_fd, Packet *p, const char *username,
                          const char *client_ip, int client_port, const char *op_name);

void handle_undo_command(int client_fd, Packet *p, const char *username,
                         const char *client_ip, int client_port, const char *op_name);

void handle_info_command(int client_fd, Packet *p, const char *username,
                         const char *client_ip, int client_port, const char *op_name);

void handle_delete_command(int client_fd, Packet *p, const char *username,
                           const char *client_ip, int client_port, const char *op_name);

void handle_stream_command(int client_fd, Packet *p, const char *username,
                           const char *client_ip, int client_port, const char *op_name);

void handle_addaccess_command(int client_fd, Packet *p, const char *username,
                              const char *client_ip, int client_port, const char *op_name);

void handle_remaccess_command(int client_fd, Packet *p, const char *username,
                              const char *client_ip, int client_port, const char *op_name);

void handle_checkpoint_command(int client_fd, Packet *p, const char *username,
                               const char *client_ip, int client_port, const char *op_name);

void handle_listcheckpoints_command(int client_fd, Packet *p, const char *username,
                                     const char *client_ip, int client_port, const char *op_name);

void handle_viewcheckpoint_command(int client_fd, Packet *p, const char *username,
                                    const char *client_ip, int client_port, const char *op_name);

void handle_revert_command(int client_fd, Packet *p, const char *username,
                           const char *client_ip, int client_port, const char *op_name);

void handle_requestaccess_command(int client_fd, Packet *p, const char *username,
                                   const char *client_ip, int client_port, const char *op_name);

void handle_viewrequests_command(int client_fd, Packet *p, const char *username,
                                  const char *client_ip, int client_port, const char *op_name);

void handle_approve_command(int client_fd, Packet *p, const char *username,
                             const char *client_ip, int client_port, const char *op_name);

void handle_reject_command(int client_fd, Packet *p, const char *username,
                            const char *client_ip, int client_port, const char *op_name);

#endif // COMMAND_HANDLERS_SS_H
