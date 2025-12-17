#include "name_server.h"
#include "forwarding.h"
#include "utils.h"
#include "../linkedlist.h"
#include <sys/socket.h>

// Static variable for round-robin load balancing for CREATE operations
static int next_ss_idx_for_create = 0;

// ======== SS Connection Helpers ========
// Functions for communicating with Storage Servers and routing client requests

// Helper function to find the Storage Server that hosts a given file
// Uses efficient hash table lookup with LRU cache
// Returns index in ss_list, or -1 if not found
// This function is now a wrapper around the efficient lookup in file_lookup.c

// Return SS IP and port to client for direct connection
// Specification: For READ/WRITE/STREAM operations, NS identifies correct SS and 
// returns IP:port so client can establish direct connection
// Routes to the SS that actually hosts the file (from file_table)
// Enforces read access control for READ and STREAM operations
void return_ss_info(int fd, Packet p) {
    char client_ip[INET_ADDRSTRLEN] = "unknown";
    int client_port = 0;
    
    if (ss_count == 0) {
        dprintf(fd, "[NS] ERROR: No SS available. Error code: %d - %s\n", 
                ERR_STORAGE_SERVER_UNAVAILABLE, get_error_message(ERR_STORAGE_SERVER_UNAVAILABLE));
        log_response("SS_INFO", p.username, client_ip, client_port, "NO_SS_AVAILABLE");
        return;
    }
    
    // Find the SS that hosts this file using efficient hash table lookup
    int ss_idx = find_ss_for_file(p.filename);
    
    if (ss_idx < 0) {
        // File not found in hash table - try querying all Storage Servers as fallback
        // This handles cases where files exist on SS but weren't registered in NS hash table
        fprintf(stderr, "[NS DEBUG] File '%s' not in hash table, querying all SSs as fallback\n", p.filename);
        
        // Try each Storage Server to see if they have the file
        for (int i = 0; i < ss_count; i++) {
            int test_sock = socket(AF_INET, SOCK_STREAM, 0);
            if (test_sock < 0) continue;
            
            struct sockaddr_in test_addr = {0};
            test_addr.sin_family = AF_INET;
            test_addr.sin_port = htons(ss_list[i].port);
            inet_pton(AF_INET, ss_list[i].ip, &test_addr.sin_addr);
            
            if (connect(test_sock, (struct sockaddr*)&test_addr, sizeof(test_addr)) >= 0) {
                // Send username and INFO packet to check if file exists
                send(test_sock, p.username, strlen(p.username), 0);
                Packet info_packet = {0};
                info_packet.opcode = CMD_INFO;
                strncpy(info_packet.filename, p.filename, FILE_NAME_SIZE - 1);
                info_packet.filename[FILE_NAME_SIZE - 1] = '\0';
                strncpy(info_packet.username, p.username, sizeof(info_packet.username) - 1);
                info_packet.username[sizeof(info_packet.username) - 1] = '\0';
                send(test_sock, &info_packet, sizeof(info_packet), 0);
                
                // Check response
                char response[256];
                int n = recv(test_sock, response, sizeof(response) - 1, 0);
                close(test_sock);
                
                if (n > 0 && strstr(response, "ERROR") == NULL) {
                    // File exists on this SS - use it
                    ss_idx = i;
                    fprintf(stderr, "[NS DEBUG] Found file '%s' on SS %d (%s:%d)\n", 
                            p.filename, i, ss_list[i].ip, ss_list[i].port);
                    break;
                }
            } else {
                close(test_sock);
            }
        }
        
        if (ss_idx < 0) {
            // File not found anywhere - return error
            dprintf(fd, "[NS] ERROR: File '%s' not found. Error code: %d - %s\n", 
                    p.filename, ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
            log_response("SS_INFO", p.username, client_ip, client_port, "FILE_NOT_FOUND");
            return;
        }
    }
    
    // For READ and STREAM operations, enforce read access control
    if (p.opcode == CMD_READ || p.opcode == CMD_STREAM) {
        meta_data *meta = get_file_metadata(p.filename);
        if (!meta) {
            // File not in hash table - access control will be checked by Storage Server
            // For now, allow the request to proceed and let SS handle access control
            fprintf(stderr, "[NS DEBUG] File '%s' metadata not in hash table, letting SS handle access control\n", 
                    p.filename);
        } else {
            // File is in hash table - check access here
            pthread_mutex_lock(&lock);
            int has_access = user_has_read_access(p.username, meta);
            pthread_mutex_unlock(&lock);
            
            if (!has_access) {
                dprintf(fd, "[NS] ERROR: Unauthorized access. Error code: %d - %s\n", 
                        ERR_READ_ACCESS_DENIED, get_error_message(ERR_READ_ACCESS_DENIED));
                log_response("SS_INFO", p.username, client_ip, client_port, "UNAUTHORIZED");
                return;
            }
        }
    }
    
    // Return SS info to client
    char ss_info[NS_DETAILS_SIZE];
    snprintf(ss_info, sizeof(ss_info), PROTOCOL_SS_INFO_PREFIX "%s|%d", ss_list[ss_idx].ip, ss_list[ss_idx].port);
    send(fd, ss_info, strlen(ss_info), 0);
    
    char details[NS_DETAILS_SIZE];
    snprintf(details, sizeof(details), "Returned SS info: %s:%d", ss_list[ss_idx].ip, ss_list[ss_idx].port);
    log_response("SS_INFO", p.username, ss_list[ss_idx].ip, ss_list[ss_idx].port, "OK");
}

// Forward CREATE/DELETE to SS and relay ACK back
// Specification: 
// - NS forwards request to appropriate SS
// - SS processes request and sends ACK to NS
// - NS relays ACK back to client
// Routes to correct SS: DELETE uses file_table lookup, CREATE uses round-robin with failover
void forward_create_delete(int fd, Packet p) {
    if (ss_count == 0) { 
        dprintf(fd, "[NS] ERROR: No SS available. Error code: %d - %s\n", 
                ERR_STORAGE_SERVER_UNAVAILABLE, get_error_message(ERR_STORAGE_SERVER_UNAVAILABLE)); 
        return; 
    }

    int ss_idx = -1;
    int ss_sock = -1;
    
    if (p.opcode == CMD_DELETE) {
        // DELETE: Find the SS that hosts this file
        ss_idx = find_ss_for_file(p.filename);
        if (ss_idx < 0) {
            // Fallback: query all SSs to locate the file if it's not in our hash table
            fprintf(stderr, "[NS DEBUG] File '%s' not in hash table, querying all SSs as fallback for DELETE\n", p.filename);
            for (int i = 0; i < ss_count; i++) {
                int test_sock = socket(AF_INET, SOCK_STREAM, 0);
                if (test_sock < 0) continue;

                struct sockaddr_in test_addr = {0};
                test_addr.sin_family = AF_INET;
                test_addr.sin_port = htons(ss_list[i].port);
                inet_pton(AF_INET, ss_list[i].ip, &test_addr.sin_addr);

                if (connect(test_sock, (struct sockaddr*)&test_addr, sizeof(test_addr)) >= 0) {
                    // Send username and INFO packet to check if file exists
                    send(test_sock, p.username, strlen(p.username), 0);
                    Packet info_packet = {0};
                    info_packet.opcode = CMD_INFO;
                    strncpy(info_packet.filename, p.filename, FILE_NAME_SIZE - 1);
                    info_packet.filename[FILE_NAME_SIZE - 1] = '\0';
                    strncpy(info_packet.username, p.username, sizeof(info_packet.username) - 1);
                    info_packet.username[sizeof(info_packet.username) - 1] = '\0';
                    send(test_sock, &info_packet, sizeof(info_packet), 0);

                    char response[256];
                    int n = recv(test_sock, response, sizeof(response) - 1, 0);
                    close(test_sock);

                    if (n > 0 && strstr(response, "ERROR") == NULL) {
                        ss_idx = i;
                        fprintf(stderr, "[NS DEBUG] Found file '%s' on SS %d (%s:%d) for DELETE\n", p.filename, i, ss_list[i].ip, ss_list[i].port);
                        break;
                    }
                } else {
                    close(test_sock);
                }
            }
            if (ss_idx < 0) {
                dprintf(fd, "[NS] ERROR: File not found in system. Error code: %d - %s\n", 
                        ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
                return;
            }
        }
    } else if (p.opcode == CMD_CREATE) {
        // CREATE: Use round-robin with failover to find an available SS
        int initial_ss_idx = next_ss_idx_for_create;
        for (int i = 0; i < ss_count; i++) {
            int current_ss_idx = (initial_ss_idx + i) % ss_count;
            
            ss_sock = socket(AF_INET, SOCK_STREAM, 0);
            if (ss_sock < 0) continue;

            struct sockaddr_in ss_addr = {0};
            ss_addr.sin_family = AF_INET;
            ss_addr.sin_port = htons(ss_list[current_ss_idx].port);
            inet_pton(AF_INET, ss_list[current_ss_idx].ip, &ss_addr.sin_addr);

            if (connect(ss_sock, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) >= 0) {
                ss_idx = current_ss_idx;
                // Update round-robin counter only on successful connection
                next_ss_idx_for_create = (ss_idx + 1) % ss_count;
                break; // Connection successful, exit loop
            }
            
            close(ss_sock); // Close socket if connection failed
            ss_sock = -1;
        }

        if (ss_idx == -1) {
            dprintf(fd, "[NS] ERROR: Could not connect to any available SS. Error code: %d - %s\n", 
                    ERR_CONNECTION_FAILED, get_error_message(ERR_CONNECTION_FAILED));
            return;
        }
    } else {
        // Unknown operation
        dprintf(fd, "[NS] Unknown operation for forward_create_delete.\n");
        return;
    }

    // If we are handling DELETE, we need to establish the connection now
    if (p.opcode == CMD_DELETE) {
        ss_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (ss_sock < 0) {
            dprintf(fd, "[NS] ERROR: Could not create socket to SS. Error code: %d - %s\n", 
                    ERR_CONNECTION_FAILED, get_error_message(ERR_CONNECTION_FAILED));
            return;
        }
        struct sockaddr_in ss_addr = {0};
        ss_addr.sin_family = AF_INET;
        ss_addr.sin_port = htons(ss_list[ss_idx].port);
        inet_pton(AF_INET, ss_list[ss_idx].ip, &ss_addr.sin_addr);

        if (connect(ss_sock, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) < 0) {
            dprintf(fd, "[NS] ERROR: Could not connect to SS. Error code: %d - %s\n", 
                    ERR_CONNECTION_FAILED, get_error_message(ERR_CONNECTION_FAILED)); 
            close(ss_sock);
            return;
        }
    }
    
    char details[NS_DETAILS_SIZE];
    snprintf(details, sizeof(details), "Forwarding to SS %s:%d", ss_list[ss_idx].ip, ss_list[ss_idx].port);
    log_request("FORWARD", p.username, ss_list[ss_idx].ip, ss_list[ss_idx].port, details);
    
    // Send username first (required by SS for access control)
    send(ss_sock, p.username, strlen(p.username), 0);
    
    // Send packet with operation details
    send(ss_sock, &p, sizeof(p), 0);
    
    // Receive ACK from SS (may include multiple lines of response)
    char ack[NS_BUFFER_SIZE_4096];
    size_t total = 0;
    int n;
    while ((n = recv(ss_sock, ack + total, sizeof(ack) - total - 1, 0)) > 0) {
        total += n;
        if (total >= sizeof(ack) - 1) break;
        // Check if we got the ACK message
        ack[total] = '\0';
        if (strstr(ack, "[SS] ACK:") != NULL) {
            usleep(10000); // Small delay to ensure all data is received
            break;
        }
    }
    
    // If CREATE succeeded, update hash table with new file location
    if (p.opcode == CMD_CREATE && total > 0 && strstr(ack, "successfully") != NULL) {
        // Create metadata for new file
        meta_data *meta = (meta_data *)malloc(sizeof(meta_data));
        if (meta) {
            memset(meta, 0, sizeof(meta_data));
            strncpy((char *)meta->filename, p.filename, FILE_NAME_SIZE - 1);
            meta->filename[FILE_NAME_SIZE - 1] = '\0';
            strncpy(meta->owner, p.username, FILE_NAME_SIZE - 1);
            meta->owner[FILE_NAME_SIZE - 1] = '\0';
            meta->created = time(NULL);
            meta->modified = meta->created;
            meta->last_accessed = meta->created;
            meta->wordcount = 0;
            meta->charcount = 0;
            strncpy(meta->lastmodifiedby, p.username, FILE_NAME_SIZE - 1);
            meta->lastmodifiedby[FILE_NAME_SIZE - 1] = '\0';
            meta->users_with_access = (linkedlist_t *)malloc(sizeof(linkedlist_t));
            if (meta->users_with_access) {
                init_linkedlist(meta->users_with_access);
            }
            
            // Add to hash table (efficient O(1) insertion)
            add_file_location(p.filename, ss_list[ss_idx].ip, ss_list[ss_idx].port, ss_idx, meta);
            
            // Also update legacy file_table for compatibility
            // Note: filename and owner are in meta->filename and meta->owner, not in file_meta structure
            pthread_mutex_lock(&lock);
            if (file_count < MAX_FILES) {
                // Check if file already exists in file_table before adding
                int existing_index = -1;
                for (int i = 0; i < file_count; i++) {
                    if (file_table[i].meta && strcmp(file_table[i].meta->filename, meta->filename) == 0) {
                        existing_index = i;
                        break;
                    }
                }
                
                if (existing_index >= 0) {
                    // File exists - update existing entry
                    strcpy(file_table[existing_index].ss_ip, ss_list[ss_idx].ip);
                    file_table[existing_index].ss_port = ss_list[ss_idx].port;
                    // Free old metadata if different
                    if (file_table[existing_index].meta != meta) {
                        if (file_table[existing_index].meta->users_with_access) {
                            node_t *ua_node = file_table[existing_index].meta->users_with_access->head;
                            while (ua_node) {
                                free(ua_node->data);
                                ua_node = ua_node->next;
                            }
                            free(file_table[existing_index].meta->users_with_access);
                        }
                        free(file_table[existing_index].meta);
                    }
                    file_table[existing_index].meta = meta;
                } else {
                    // New file - add to file_table
                    if (file_count < MAX_FILES) {
                        strcpy(file_table[file_count].ss_ip, ss_list[ss_idx].ip);
                        file_table[file_count].ss_port = ss_list[ss_idx].port;
                        file_table[file_count].meta = meta;
                        file_count++;
                    }
                }
            }
            pthread_mutex_unlock(&lock);
        }
    }
    
    // If DELETE succeeded, remove file from hash table and file_table
    // Check for both old format ("successfully") and new format (PROTOCOL_METADATA with FAILURE status)
    int delete_succeeded = 0;
    if (p.opcode == CMD_DELETE && total > 0) {
        if (strstr(ack, "successfully") != NULL) {
            delete_succeeded = 1;
        } else {
            // Check for structured metadata response with FAILURE status (indicates deletion)
            char *metadata_line = strstr(ack, PROTOCOL_METADATA);
            if (metadata_line) {
                char *status_pos = strstr(metadata_line, PROTOCOL_METADATA_FAILURE);
                if (status_pos) {
                    delete_succeeded = 1;
                }
            }
        }
    }
    
    if (delete_succeeded) {
        // Remove from hash table (efficient O(1) removal)
        remove_file_location(p.filename);
        
        // Also remove from legacy file_table for compatibility
        // Note: filename is in meta->filename, not directly in file_meta structure
        pthread_mutex_lock(&lock);
        for (int i = 0; i < file_count; i++) {
            if (file_table[i].meta && strcmp(file_table[i].meta->filename, p.filename) == 0) {
                // Free metadata if it exists
                if (file_table[i].meta) {
                    if (file_table[i].meta->users_with_access) {
                        node_t *ua_node = file_table[i].meta->users_with_access->head;
                        while (ua_node) {
                            free(ua_node->data);
                            ua_node = ua_node->next;
                        }
                        free(file_table[i].meta->users_with_access);
                    }
                    free(file_table[i].meta);
                }
                // Remove file from table by shifting remaining entries
                for (int j = i; j < file_count - 1; j++) {
                    file_table[j] = file_table[j + 1];
                }
                file_count--;
                break;
            }
        }
        pthread_mutex_unlock(&lock);
    }
    
    if (total > 0) {
        ack[total] = 0;
        dprintf(fd, "%s", ack);
        log_response("FORWARD", p.username, ss_list[ss_idx].ip, ss_list[ss_idx].port, "ACK_RECEIVED");
    } else {
        dprintf(fd, "[NS] No ACK from SS.\n");
        log_response("FORWARD", p.username, ss_list[ss_idx].ip, ss_list[ss_idx].port, "FAILED");
    }
    close(ss_sock);
}

// Forward access control operations (ADDACCESS/REMACCESS) to SS
// Specification: NS updates its metadata first, then forwards to SS to persist ACL changes
// Routes to the SS that hosts the file (from file_table)
void forward_access_control(int fd, Packet p) {
    if (ss_count == 0) { 
        dprintf(fd, "[NS] ERROR: No SS available. Error code: %d - %s\n", 
                ERR_STORAGE_SERVER_UNAVAILABLE, get_error_message(ERR_STORAGE_SERVER_UNAVAILABLE)); 
        return; 
    }

    // Find the SS that hosts this file
    int ss_idx = find_ss_for_file(p.filename);
    
        if (ss_idx < 0) {
            // File not found - operation cannot proceed
            dprintf(fd, "[NS] ERROR: File not found in system. Error code: %d - %s\n", 
                    ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
            return;
        }

    int ss_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ss_addr = {0};
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(ss_list[ss_idx].port);
    inet_pton(AF_INET, ss_list[ss_idx].ip, &ss_addr.sin_addr);

    if (connect(ss_sock, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) < 0) {
        dprintf(fd, "[NS] ERROR: Could not connect to SS. Error code: %d - %s\n", 
                ERR_CONNECTION_FAILED, get_error_message(ERR_CONNECTION_FAILED)); 
        return;
    }
    
    char details[NS_DETAILS_SIZE];
    snprintf(details, sizeof(details), "Forwarding %s to SS %s:%d", 
             (p.opcode == CMD_ADDACCESS) ? "ADDACCESS" : "REMACCESS",
             ss_list[ss_idx].ip, ss_list[ss_idx].port);
    log_request("FORWARD_ACL", p.username, ss_list[ss_idx].ip, ss_list[ss_idx].port, details);
    
    // Send username first (required by SS for access control)
    send(ss_sock, p.username, strlen(p.username), 0);
    send(ss_sock, "\n", 1, 0);
    
    // Send packet
    send(ss_sock, &p, sizeof(p), 0);
    
    // Receive response from SS
    char ack[NS_OUTPUT_SIZE] = {0};
    int total = 0;
    int n;
    while ((n = recv(ss_sock, ack + total, sizeof(ack) - total - 1, 0)) > 0) {
        total += n;
        if (strstr(ack, "STOP") != NULL) {
            break;
        }
    }
    
    if (total > 0) {
        ack[total] = 0;
        // Remove STOP marker and display response
        char *stop_pos = strstr(ack, "STOP");
        if (stop_pos) {
            *stop_pos = '\0';
        }
        dprintf(fd, "%s", ack);
        log_response("FORWARD_ACL", p.username, ss_list[ss_idx].ip, ss_list[ss_idx].port, "OK");
    } else {
        dprintf(fd, "[NS] No response from SS.\n");
        log_response("FORWARD_ACL", p.username, ss_list[ss_idx].ip, ss_list[ss_idx].port, "FAILED");
    }
    close(ss_sock);
}

// Forward other operations to SS (UNDO, CHECKPOINT, etc.)
// Specification: Operations like UNDO, CHECKPOINT are forwarded to SS for processing
// NS acts as a proxy, forwarding request and relaying response back to client
// Routes to the SS that hosts the file (from file_table)
void forward_to_ss(int fd, Packet p) {
    if (ss_count == 0) { 
        dprintf(fd, "[NS] ERROR: No SS available. Error code: %d - %s\n", 
                ERR_STORAGE_SERVER_UNAVAILABLE, get_error_message(ERR_STORAGE_SERVER_UNAVAILABLE)); 
        return; 
    }

    // Find the SS that hosts this file
    int ss_idx = find_ss_for_file(p.filename);
    
    if (ss_idx < 0) {
        // File not found - operation cannot proceed
        // For UNDO, provide a more specific error message
        if (p.opcode == CMD_UNDO) {
            dprintf(fd, "[NS] ERROR: Cannot undo - file does not exist in system. Error code: %d - %s\n", 
                    ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
        } else {
            dprintf(fd, "[NS] ERROR: File not found in system. Error code: %d - %s\n", 
                    ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
        }
        return;
    }

    int ss_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ss_addr = {0};
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(ss_list[ss_idx].port);
    inet_pton(AF_INET, ss_list[ss_idx].ip, &ss_addr.sin_addr);

    if (connect(ss_sock, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) < 0) {
        dprintf(fd, "[NS] ERROR: Could not connect to SS. Error code: %d - %s\n", 
                ERR_CONNECTION_FAILED, get_error_message(ERR_CONNECTION_FAILED)); 
        return;
    }
    
    char details[NS_DETAILS_SIZE];
    snprintf(details, sizeof(details), "Forwarding to SS %s:%d", ss_list[ss_idx].ip, ss_list[ss_idx].port);
    log_request("FORWARD", p.username, ss_list[ss_idx].ip, ss_list[ss_idx].port, details);
    
    // Send username first (required by SS for access control)
    send(ss_sock, p.username, strlen(p.username), 0);
    
    // Send packet with operation details
    send(ss_sock, &p, sizeof(p), 0);
    
    // Special handling for WRITE: forward multiple packets until ETIRW
    // Specification: WRITE operation consists of multiple packets:
    // - First packet: sentence_index
    // - Subsequent packets: word_index and content
    // - Final packet: "ETIRW" to signal end of write operation
    if (p.opcode == CMD_WRITE) {
        while (1) {
            int n = recv(fd, &p, sizeof(p), 0);
            if (n <= 0) break;
            if (p.opcode != CMD_WRITE) break;
            send(ss_sock, &p, sizeof(p), 0);
            if (strcmp(p.payload, PROTOCOL_ETIRW) == 0) break;
        }
    }
    
    // Receive response
    char resp[NS_BUFFER_SIZE_4096]; 
    int n = recv(ss_sock, resp, sizeof(resp)-1, 0);
    if (n > 0) { 
        resp[n] = 0; 
        dprintf(fd, "%s", resp);
        log_response("FORWARD", p.username, ss_list[ss_idx].ip, ss_list[ss_idx].port, "OK");
    } else {
        log_response("FORWARD", p.username, ss_list[ss_idx].ip, ss_list[ss_idx].port, "FAILED");
    }
    close(ss_sock);
}

