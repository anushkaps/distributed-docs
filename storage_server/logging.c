/**
 * ============================================================================
 * logging.c - Storage Server Logging Functions
 * ============================================================================
 * 
 * PURPOSE:
 * This module provides logging functionality for the Storage Server (SS).
 * It logs all requests, acknowledgments, and responses as required by the
 * specification. Each log entry includes timestamps, IP addresses, ports,
 * usernames, and operation details for traceability and debugging.
 * 
 * SPECIFICATION REQUIREMENT:
 * - SS must log every request, acknowledgment and response
 * - Each entry should include timestamps, IP, port, usernames and operation details
 * 
 * USAGE:
 * - log_request_ss(): Called when a request is received from a client
 * - log_response_ss(): Called when a response is sent to a client
 * 
 * ============================================================================
 */

#include "storage_server.h"
#include <time.h>
#include <stdio.h>
#include <string.h>

/**
 * Log a request received from a client
 * 
 * WHAT: Records incoming client requests with full context
 * WHERE: Called at the start of processing each client request
 * WHY: Provides audit trail and debugging information for all operations
 * 
 * @param op - Operation name (e.g., "READ", "WRITE", "CREATE")
 * @param user - Username of the client making the request
 * @param ip - IP address of the client
 * @param port - Port number of the client connection
 * @param details - Additional operation-specific details (e.g., filename, sentence index)
 */
// Log file for Storage Server
// Specification: SS logs to a text file for persistence
#define SS_LOG_FILE "storage_server.log"

void log_request_ss(const char *op, const char *user, const char *ip, int port, const char *details)
{
    // Get current timestamp for the log entry
    time_t t = time(NULL);
    char ts[TIMESTAMP_SIZE];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
    
    // Open log file in append mode
    // Specification: Logs are written to text files for persistence
    FILE *log_file = fopen(SS_LOG_FILE, "a");
    if (log_file) {
        // Format log message with or without details
        // Details are optional and may include filename, sentence index, etc.
        if (details && strlen(details) > 0)
            fprintf(log_file, "[%s] [SS] REQUEST: %s | User: %s | IP: %s | Port: %d | Details: %s\n", 
                   ts, op, user, ip, port, details);
        else
            fprintf(log_file, "[%s] [SS] REQUEST: %s | User: %s | IP: %s | Port: %d\n", 
                   ts, op, user, ip, port);
        fclose(log_file);
    }
    
    // Also print to stdout for real-time monitoring
    if (details && strlen(details) > 0)
        printf("[%s] [SS] REQUEST: %s | User: %s | IP: %s | Port: %d | Details: %s\n", 
               ts, op, user, ip, port, details);
    else
        printf("[%s] [SS] REQUEST: %s | User: %s | IP: %s | Port: %d\n", 
               ts, op, user, ip, port);
}

/**
 * Log a response sent to a client
 * 
 * WHAT: Records outgoing responses to clients with status information
 * WHERE: Called after processing each client request, before sending response
 * WHY: Completes the request-response audit trail and shows operation outcomes
 * 
 * @param op - Operation name that was processed
 * @param user - Username of the client receiving the response
 * @param ip - IP address of the client
 * @param port - Port number of the client connection
 * @param status - Status of the operation (e.g., "OK", "FAILED: Access denied")
 */
void log_response_ss(const char *op, const char *user, const char *ip, int port, const char *status)
{
    // Get current timestamp for the log entry
    time_t t = time(NULL);
    char ts[TIMESTAMP_SIZE];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
    
    // Open log file in append mode
    // Specification: Logs are written to text files for persistence
    FILE *log_file = fopen(SS_LOG_FILE, "a");
    if (log_file) {
        // Log the response with status
        // Status indicates success or failure reason
        fprintf(log_file, "[%s] [SS] RESPONSE: %s | User: %s | IP: %s | Port: %d | Status: %s\n", 
               ts, op, user, ip, port, status);
        fclose(log_file);
    }
    
    // Also print to stdout for real-time monitoring
    printf("[%s] [SS] RESPONSE: %s | User: %s | IP: %s | Port: %d | Status: %s\n", 
           ts, op, user, ip, port, status);
}

/**
 * Log file operation events (lock/unlock, undo, etc.)
 * Specification: SS logs all file operations including lock/unlock and undo
 * 
 * @param event_type - Type of event (e.g., "LOCK", "UNLOCK", "UNDO", "CHECKPOINT")
 * @param filename - Name of the file
 * @param user - Username performing the operation
 * @param details - Additional details (e.g., sentence index for lock)
 */
void log_file_operation_ss(const char *event_type, const char *filename, const char *user, const char *details)
{
    time_t t = time(NULL);
    char ts[TIMESTAMP_SIZE];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
    
    // Open log file in append mode
    FILE *log_file = fopen(SS_LOG_FILE, "a");
    if (log_file) {
        if (details && strlen(details) > 0)
            fprintf(log_file, "[%s] [SS] FILE_OP: %s | File: %s | User: %s | Details: %s\n",
                   ts, event_type, filename, user, details);
        else
            fprintf(log_file, "[%s] [SS] FILE_OP: %s | File: %s | User: %s\n",
                   ts, event_type, filename, user);
        fclose(log_file);
    }
    
    // Also print to stdout
    if (details && strlen(details) > 0)
        printf("[%s] [SS] FILE_OP: %s | File: %s | User: %s | Details: %s\n",
               ts, event_type, filename, user, details);
    else
        printf("[%s] [SS] FILE_OP: %s | File: %s | User: %s\n",
               ts, event_type, filename, user);
}

