#ifndef UTILS_H
#define UTILS_H

void log_event(const char *msg, const char *user);
void log_request(const char *op, const char *user, const char *ip, int port, const char *details);
void log_response(const char *op, const char *user, const char *ip, int port, const char *status);
void log_exec_command(const char *username, const char *filename, const char *command);

#endif // UTILS_H

