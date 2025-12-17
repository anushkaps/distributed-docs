#include "command_handler_utils.h"
#include "storage_server.h"
#include <string.h>
#include <stdio.h>

// Forward declarations for logging functions from another module
extern void log_response_ss(const char *op, const char *user, const char *ip, int port, const char *status);

void send_error_response(int client_fd, int error_code, const char *op_name, const char *username, const char *client_ip, int client_port, const char *log_message) {
    dprintf(client_fd, "[SS] ERROR: %s. Error code: %d - %s\n", log_message, error_code, get_error_message(error_code));
    send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
    log_response_ss(op_name, username, client_ip, client_port, log_message);
}

void send_success_response(int client_fd, const char *message, const char *op_name, const char *username, const char *client_ip, int client_port, const char *log_message) {
    dprintf(client_fd, "%s\n", message);
    send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
    log_response_ss(op_name, username, client_ip, client_port, log_message);
}

void trim_whitespace(char *str) {
    if (!str) return;
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\t' || str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[--len] = '\0';
    }
}

file* find_file_or_send_error(int client_fd, const char *filename, const char *op_name, const char *username, const char *client_ip, int client_port) {
    char trimmed_filename[FILE_NAME_SIZE];
    strncpy(trimmed_filename, filename, sizeof(trimmed_filename) - 1);
    trimmed_filename[sizeof(trimmed_filename) - 1] = '\0';
    trim_whitespace(trimmed_filename);

    file *f = in_htable(trimmed_filename, name_to_ptr);
    if (!f) {
        send_error_response(client_fd, ERR_FILE_NOT_FOUND, op_name, username, client_ip, client_port, "FAILED: File not found");
        return NULL;
    }
    return f;
}

bool check_access_or_send_error(int client_fd, file *f, const char *username, int required_access, const char *op_name, const char *client_ip, int client_port) {
    if (strcmp(f->info->owner, username) != 0 && !check_access(username, f, required_access)) {
        int error_code = (required_access == ACCESS_WRITE) ? ERR_WRITE_ACCESS_DENIED : ERR_READ_ACCESS_DENIED;
        send_error_response(client_fd, error_code, op_name, username, client_ip, client_port, "FAILED: Access denied");
        return false;
    }
    return true;
}
