/**
 * ============================================================================
 * client_handler_ss.c - Storage Server Client Connection Handler
 * ============================================================================
 * 
 * PURPOSE:
 * This module handles client connections to the Storage Server. Each client
 * connection runs in a separate thread to support concurrent access. The handler
 * receives commands from clients, routes them to appropriate command handlers,
 * and sends responses back.
 * 
 * ARCHITECTURE:
 * - Each client connection spawns a new thread running client_connection_handler()
 * - Handler receives username first, then processes command packets
 * - Commands are routed to specific handler functions in command_handlers_ss.c
 * - All operations are logged for audit trail
 * 
 * CONCURRENCY:
 * - Multiple clients can connect simultaneously
 * - Files support concurrent reads
 * - Sentences are locked during write operations to prevent conflicts
 * 
 * ============================================================================
 */

#include "storage_server.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>

// External logging functions
extern void log_request_ss(const char *op, const char *user, const char *ip, int port, const char *details);
extern void log_response_ss(const char *op, const char *user, const char *ip, int port, const char *status);

// External command handler functions
extern void handle_read_command(int client_fd, Packet *p, const char *username, 
                                const char *client_ip, int client_port, const char *op_name);
extern void handle_create_command(int client_fd, Packet *p, const char *username,
                                  const char *client_ip, int client_port, const char *op_name);
extern void handle_write_command(int client_fd, Packet *p, const char *username,
                                 const char *client_ip, int client_port, const char *op_name, thread_lock_manager_t* lock_manager);
extern void handle_undo_command(int client_fd, Packet *p, const char *username,
                                const char *client_ip, int client_port, const char *op_name);
extern void handle_info_command(int client_fd, Packet *p, const char *username,
                                const char *client_ip, int client_port, const char *op_name);
extern void handle_delete_command(int client_fd, Packet *p, const char *username,
                                  const char *client_ip, int client_port, const char *op_name);
extern void handle_stream_command(int client_fd, Packet *p, const char *username,
                                  const char *client_ip, int client_port, const char *op_name);
extern void handle_addaccess_command(int client_fd, Packet *p, const char *username,
                                     const char *client_ip, int client_port, const char *op_name);
extern void handle_remaccess_command(int client_fd, Packet *p, const char *username,
                               const char *client_ip, int client_port, const char *op_name);
extern void handle_exec_command_ss(int client_fd, Packet *p, const char *username,
                            const char *client_ip, int client_port, const char *op_name);
extern void handle_checkpoint_command(int client_fd, Packet *p, const char *username,
                                       const char *client_ip, int client_port, const char *op_name);
extern void handle_listcheckpoints_command(int client_fd, Packet *p, const char *username,
                                            const char *client_ip, int client_port, const char *op_name);
extern void handle_viewcheckpoint_command(int client_fd, Packet *p, const char *username,
                                          const char *client_ip, int client_port, const char *op_name);
extern void handle_revert_command(int client_fd, Packet *p, const char *username,
                                  const char *client_ip, int client_port, const char *op_name);
extern void handle_requestaccess_command(int client_fd, Packet *p, const char *username,
                                          const char *client_ip, int client_port, const char *op_name);
extern void handle_viewrequests_command(int client_fd, Packet *p, const char *username,
                                         const char *client_ip, int client_port, const char *op_name);
extern void handle_approve_command(int client_fd, Packet *p, const char *username,
                                    const char *client_ip, int client_port, const char *op_name);
extern void handle_reject_command(int client_fd, Packet *p, const char *username,
                                   const char *client_ip, int client_port, const char *op_name);

/**
 * Connection structure for client connections
 * Stores socket file descriptor and client address information
 */
typedef struct {
    int fd;                      // Socket file descriptor
    struct sockaddr_in addr;     // Client address information
} client_conn_ss;

/**
 * Client Connection Handler - Main handler for each client connection
 * 
 * WHAT: Processes all commands from a single client connection
 * WHERE: Called in a separate thread for each client that connects
 * WHY: Enables concurrent handling of multiple clients simultaneously
 * 
 * SPECIFICATION:
 * - SS must support concurrent access by multiple clients (reads and writes)
 * - Files support concurrent access, but sentences are locked during write operations
 * - Username is received first for access control
 * - Commands are processed in a loop until client disconnects
 * 
 * @param arg - Pointer to client_conn_ss structure containing connection info
 * @return NULL (thread function)
 */
void *client_connection_handler(void *arg)
{
    // Extract connection information
    client_conn_ss *conn = (client_conn_ss *)arg;
    int client_fd = conn->fd;
    char client_ip[INET_ADDRSTRLEN];
    int client_port = ntohs(conn->addr.sin_port);
    inet_ntop(AF_INET, &conn->addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    free(conn);  // Free connection structure as we've extracted needed info
    
    // Initialize the lock manager for this thread
    thread_lock_manager_t lock_manager;
    lock_manager.held_sentence_locks = (linkedlist_t *)malloc(sizeof(linkedlist_t));
    if (!lock_manager.held_sentence_locks) {
        perror("[SS] Failed to allocate lock manager");
        close(client_fd);
        return NULL;
    }
    init_linkedlist(lock_manager.held_sentence_locks);
    
    char buffer[BUFFER_SIZE_2048];
    ssize_t n;
    Packet p;

    // Receive username first (required for access control)
    // Specification: Username is used for all file access control operations
    // This is sent by the client before any commands
    // Note: Username is sent as plain string (no newline), followed immediately by Packet
    // TCP might combine both into a single recv, so we need to handle this carefully
    char username[BUFFER_SIZE_128] = "unknown";
    n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (n > 0) {
        buffer[n] = '\0';
        // Extract username (assume it's at the start, up to first newline or reasonable length)
        // Username is typically short (max 64 chars per Packet structure), so read up to that
        // Note: Client sends username followed by newline, then Packet
        // Strategy: Read characters until we hit a newline or non-printable, or until reasonable max
        size_t username_len = 0;
        size_t max_username_len = ((size_t)n < sizeof(Packet)) ? (size_t)n : (size_t)64; // Username max 64 chars per Packet structure
        while (username_len < max_username_len && (ssize_t)username_len < n && 
               buffer[username_len] >= 32 && buffer[username_len] < 127) { // Printable ASCII
            username[username_len] = buffer[username_len];
            username_len++;
        }
        username[username_len] = '\0';
        log_request_ss("CONNECT", username, client_ip, client_port, "");
        
        // Skip newline character if present (client sends username\n)
        size_t packet_start = username_len;
        if (n > (ssize_t)packet_start) {
            // Handle \r\n sequence (Windows line ending)
            if (buffer[packet_start] == '\r' && packet_start + 1 < (size_t)n && buffer[packet_start + 1] == '\n') {
                packet_start += 2;  // Skip both \r and \n
            }
            // Handle single \n (Unix line ending)
            else if (buffer[packet_start] == '\n') {
                packet_start++;  // Skip \n
            }
            // Handle single \r (old Mac line ending)
            else if (buffer[packet_start] == '\r') {
                packet_start++;  // Skip \r
            }
        }
        
        // Check if Packet data is also in the buffer (TCP combined username + newline + Packet)
        // Packet starts right after username and newline
        // If we received more than just the username + newline, the Packet might be in the buffer
        if (n > (ssize_t)packet_start) {
            // Packet data is in the buffer, copy it to Packet structure
            // Skip the username bytes and newline, then read the Packet
            size_t bytes_avail = (size_t)(n - (ssize_t)packet_start);
            memcpy(&p, buffer + packet_start, sizeof(p) < bytes_avail ? sizeof(p) : bytes_avail);
            // If we didn't get the full Packet, continue reading
            if (bytes_avail < sizeof(p)) {
                // Read remaining Packet bytes
                char *p_bytes = (char *)&p;
                size_t total_received = bytes_avail;
                size_t remaining = sizeof(p) - total_received;
                while (remaining > 0) {
                    ssize_t recv_n = recv(client_fd, p_bytes + total_received, remaining, 0);
                    if (recv_n <= 0) break;
                    total_received += (size_t)recv_n;
                    remaining -= (size_t)recv_n;
                }
            }
            // Process this Packet (will fall through to the switch statement)
        } else {
            // Only username received, read Packet separately
            n = recv(client_fd, &p, sizeof(p), 0);
            if (n <= 0) {
                close(client_fd);
                return NULL;
            }
        }
    } else {
        close(client_fd);
        return NULL;
    }

    // Main command processing loop
    // Handles all file operations: READ, WRITE, CREATE, DELETE, VIEW, INFO, STREAM, etc.
    // Each operation enforces access control based on file ownership and access lists
    // Note: First iteration processes the Packet we just read (if it was in the username buffer)
    do {
        // Map opcode to operation name for logging
        // This array matches the COMMAND_CODE enum in common.h
        const char *op_names[] = {"", "VIEW", "READ", "CREATE", "WRITE", "UNDO", "INFO", 
                                  "DELETE", "STREAM", "LIST", "ADDACCESS", "REMACCESS", 
                                  "EXEC", "CHECKPOINT", "LISTCHECKPOINTS", "VIEWCHECKPOINT", 
                                  "REVERT", "REQUESTACCESS", "VIEWREQUESTS", "APPROVE", "REJECT"};
        const char *op_name = (p.opcode >= 1 && p.opcode <= 20) ? op_names[p.opcode] : "UNKNOWN";
        
        // Build details string for logging
        // Includes filename and additional context (e.g., sentence index for WRITE)
        char details[DETAILS_BUFFER_SIZE] = "";
        if (strlen(p.filename) > 0)
            snprintf(details, sizeof(details), "File: %s", p.filename);
        if (p.opcode == CMD_WRITE) {
            if (strlen(details) > 0)
                strcat(details, " | ");
            char temp[BUFFER_SIZE_64];
            snprintf(temp, sizeof(temp), "Sentence: %d", p.flag1);
            strcat(details, temp);
        }

        // Log the incoming request
        log_request_ss(op_name, username, client_ip, client_port, details);

        // Route command to appropriate handler
        // Each command type has its own handler function for better code organization
        switch (p.opcode) {
        case CMD_VIEW:
            // VIEW: Lists files user has access to (handled by view_file.c)
            view_all_files(client_fd, username, p.flag1);
            dprintf(client_fd, "[SS] VIEW done.\n");
            log_response_ss(op_name, username, client_ip, client_port, "OK");
            break;

        case CMD_READ:
            // READ: Retrieve complete file content
            handle_read_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_CREATE:
            // CREATE: Create a new empty file
            handle_create_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_WRITE:
            // WRITE: Update file content at word level
            handle_write_command(client_fd, &p, username, client_ip, client_port, op_name, &lock_manager);
            break;

        case CMD_UNDO:
            // UNDO: Revert the last change made to a file
            handle_undo_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_INFO:
            // INFO: Get file metadata
            handle_info_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_DELETE:
            // DELETE: Remove file from system
            handle_delete_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_STREAM:
            // STREAM: Display file content word-by-word with delay
            handle_stream_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_ADDACCESS:
            // ADDACCESS: Grant access to a user
            handle_addaccess_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_REMACCESS:
            // REMACCESS: Remove access from a user
            handle_remaccess_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_EXEC:
            // EXEC: Get file content formatted for execution (completely separate from READ)
            handle_exec_command_ss(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_CHECKPOINT:
            // CHECKPOINT: Create a checkpoint for a file
            handle_checkpoint_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_LISTCHECKPOINTS:
            // LISTCHECKPOINTS: List all checkpoints for a file
            handle_listcheckpoints_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_VIEWCHECKPOINT:
            // VIEWCHECKPOINT: View content of a specific checkpoint
            handle_viewcheckpoint_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_REVERT:
            // REVERT: Revert file to a checkpoint
            handle_revert_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_REQUESTACCESS:
            // REQUESTACCESS: Request access to a file
            handle_requestaccess_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_VIEWREQUESTS:
            // VIEWREQUESTS: View pending access requests for a file
            handle_viewrequests_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_APPROVE:
            // APPROVE: Approve an access request
            handle_approve_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        case CMD_REJECT:
            // REJECT: Reject an access request
            handle_reject_command(client_fd, &p, username, client_ip, client_port, op_name);
            break;

        default:
            // Unknown command - log error and inform client
            dprintf(client_fd, "[SS] ERROR: Unknown command: %d. Error code: %d - %s\n", 
                    p.opcode, ERR_INVALID_COMMAND, get_error_message(ERR_INVALID_COMMAND));
            log_response_ss("UNKNOWN", username, client_ip, client_port, "FAILED: Unknown opcode");
            break;
        }
        
        // Read next Packet for next iteration
        // First iteration already processed the Packet (either from username buffer or separate recv)
        n = recv(client_fd, &p, sizeof(p), 0);
    } while (n > 0);

    // Client disconnected - log and close connection
    // Cleanup any locks that were held by this thread
    if (lock_manager.held_sentence_locks->size > 0) {
        char log_details[128];
        snprintf(log_details, sizeof(log_details), "Cleaning up %zu held lock(s) on disconnect.", lock_manager.held_sentence_locks->size);
        log_response_ss("DISCONNECT", username, client_ip, client_port, log_details);

        node_t *current = lock_manager.held_sentence_locks->head;
        while (current) {
            sentence *s = (sentence *)current->data;
            pthread_mutex_unlock(&s->wrt);
            // We don't know the filename here, so we log it as unknown
            log_file_operation_ss("UNLOCK", "UNKNOWN", username, "Released lock due to client disconnect.");
            current = current->next;
        }
    }
    free_linkedlist(lock_manager.held_sentence_locks);

    log_response_ss("DISCONNECT", username, client_ip, client_port, "OK");
    close(client_fd);
    return NULL;
}

