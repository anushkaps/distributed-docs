#ifndef COMMAND_HANDLER_UTILS_H
#define COMMAND_HANDLER_UTILS_H

#include "storage_server.h"

// Function to send a formatted error response to the client and log it.
void send_error_response(int client_fd, int error_code, const char *op_name, const char *username, const char *client_ip, int client_port, const char *log_message);

// Function to send a success response to the client and log it.
void send_success_response(int client_fd, const char *message, const char *op_name, const char *username, const char *client_ip, int client_port, const char *log_message);

// Trims leading and trailing whitespace from a string, modifying it in place.
void trim_whitespace(char *str);

// Finds a file in the hash table or sends an error if not found.
file* find_file_or_send_error(int client_fd, const char *filename, const char *op_name, const char *username, const char *client_ip, int client_port);

// Checks if a user has the required access to a file or sends an error.
bool check_access_or_send_error(int client_fd, file *f, const char *username, int required_access, const char *op_name, const char *client_ip, int client_port);

#endif // COMMAND_HANDLER_UTILS_H
