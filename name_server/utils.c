#include "name_server.h"

// Log file for Name Server
// Specification: NS logs to a text file for persistence
#define NS_LOG_FILE "name_server.log"

// ======== Utility ========
void log_event(const char *msg, const char *user) {
    time_t t = time(NULL);
    char ts[NS_TIMESTAMP_SIZE];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
    
    // Write to log file
    FILE *log_file = fopen(NS_LOG_FILE, "a");
    if (log_file) {
        fprintf(log_file, "[%s] (%s) %s\n", ts, user, msg);
        fclose(log_file);
    }
    
    // Also print to stdout
    printf("[%s] (%s) %s\n", ts, user, msg);
}

void log_request(const char *op, const char *user, const char *ip, int port, const char *details) {
    time_t t = time(NULL);
    char ts[NS_TIMESTAMP_SIZE];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
    
    // Write to log file
    // Specification: NS logs every client request with timestamp, IP, port, username, operation
    FILE *log_file = fopen(NS_LOG_FILE, "a");
    if (log_file) {
        if (details && strlen(details) > 0)
            fprintf(log_file, "[%s] [NS] REQUEST: %s | User: %s | IP: %s | Port: %d | Details: %s\n", 
                   ts, op, user, ip, port, details);
        else
            fprintf(log_file, "[%s] [NS] REQUEST: %s | User: %s | IP: %s | Port: %d\n", 
                   ts, op, user, ip, port);
        fclose(log_file);
    }
    
    // Also print to stdout for real-time monitoring
    if (details && strlen(details) > 0)
        printf("[%s] [NS] REQUEST: %s | User: %s | IP: %s | Port: %d | Details: %s\n", 
               ts, op, user, ip, port, details);
    else
        printf("[%s] [NS] REQUEST: %s | User: %s | IP: %s | Port: %d\n", 
               ts, op, user, ip, port);
}

void log_response(const char *op, const char *user, const char *ip, int port, const char *status) {
    time_t t = time(NULL);
    char ts[NS_TIMESTAMP_SIZE];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
    
    // Write to log file
    // Specification: NS logs every response with status
    FILE *log_file = fopen(NS_LOG_FILE, "a");
    if (log_file) {
        fprintf(log_file, "[%s] [NS] RESPONSE: %s | User: %s | IP: %s | Port: %d | Status: %s\n", 
               ts, op, user, ip, port, status);
        fclose(log_file);
    }
    
    // Also print to stdout for real-time monitoring
    printf("[%s] [NS] RESPONSE: %s | User: %s | IP: %s | Port: %d | Status: %s\n", 
           ts, op, user, ip, port, status);
}

// Log executed command for EXEC operation
// Specification: Log each executed command with username, filename, and timestamp
void log_exec_command(const char *username, const char *filename, const char *command) {
    time_t t = time(NULL);
    char ts[NS_TIMESTAMP_SIZE];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
    
    // Write to log file
    FILE *log_file = fopen(NS_LOG_FILE, "a");
    if (log_file) {
        fprintf(log_file, "[%s] [NS] EXEC: User: %s | File: %s | Command: %s\n", 
               ts, username, filename, command);
        fclose(log_file);
    }
    
    // Also print to stdout
    printf("[%s] [NS] EXEC: User: %s | File: %s | Command: %s\n", 
           ts, username, filename, command);
}

