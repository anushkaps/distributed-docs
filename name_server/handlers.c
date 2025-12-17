#include "name_server.h"
#include "handlers.h"
#include "../linkedlist.h"
#include <sys/socket.h>
#include <time.h>

// ======== Helper Functions ========

/**
 * Check if a user has read access to a file
 * Returns 1 if user has access (owner or in access list), 0 otherwise
 * Made non-static so it can be used by forwarding.c for access control
 */
int user_has_read_access(const char *username, meta_data *meta) {
    if (!username || !meta) return 0;
    
    // Owner always has read access
    if (strcmp(meta->owner, username) == 0) {
        return 1;
    }
    
    // Check access list
    if (meta->users_with_access) {
        for (node_t *ua_node = meta->users_with_access->head; ua_node != NULL; ua_node = ua_node->next) {
            user_access *ua = (user_access *)ua_node->data;
            if (ua && strcmp(ua->username, username) == 0) {
                // User has access (either read or write)
                return 1;
            }
        }
    }
    
    return 0;
}

/**
 * Format timestamp as "YYYY-MM-DD HH:MM"
 * Handles invalid/zero timestamps gracefully
 */
static void format_timestamp(char *buf, size_t buf_size, time_t t) {
    if (t == 0 || t < 0) {
        // Invalid timestamp - use current time or a default
        t = time(NULL);
    }
    struct tm *tm_info = localtime(&t);
    if (tm_info) {
        strftime(buf, buf_size, "%Y-%m-%d %H:%M", tm_info);
    } else {
        // Fallback if localtime fails
        snprintf(buf, buf_size, "1970-01-01 00:00");
    }
}

// VIEWFOLDER: Lists files in a specific folder
// Specification: Similar to VIEW but filtered by folder
// Shows files user has access to in the specified folder
void handle_viewfolder(int fd, Packet p) {
    char client_ip[INET_ADDRSTRLEN] = "unknown";
    int client_port = 0;
    
    // Normalize folder path
    char folder_path[FILE_NAME_SIZE];
    if (p.filename[0] == '/') {
        strncpy(folder_path, p.filename, FILE_NAME_SIZE - 1);
        folder_path[FILE_NAME_SIZE - 1] = '\0';
    } else {
        // Ensure we don't overflow - filename might be up to FILE_NAME_SIZE
        strncpy(folder_path, "/", sizeof(folder_path));
        strncat(folder_path, p.filename, sizeof(folder_path) - strlen(folder_path) - 1);
    }
    
    // Trim trailing whitespace
    size_t folder_len = strlen(folder_path);
    while (folder_len > 0 && (folder_path[folder_len-1] == ' ' || 
                              folder_path[folder_len-1] == '\t' || 
                              folder_path[folder_len-1] == '\n' || 
                              folder_path[folder_len-1] == '\r')) {
        folder_path[--folder_len] = '\0';
    }
    
    // Default to "/" if empty
    if (folder_path[0] == '\0') {
        strncpy(folder_path, "/", FILE_NAME_SIZE - 1);
        folder_path[FILE_NAME_SIZE - 1] = '\0';
    }
    
    pthread_mutex_lock(&lock);
    
    // Collect files in the specified folder
    meta_data *files_to_show[MAX_FILES];
    int file_count_to_show = 0;
    
    // Iterate through file_table and filter by folder
    // NOTE: Folder support is not implemented in meta_data structure yet
    // For now, show all files (folder filtering disabled)
    for (int i = 0; i < file_count && file_count_to_show < MAX_FILES; i++) {
        if (!file_table[i].meta) continue;
        
        // TODO: Implement folder support in meta_data structure
        // For now, all files are considered to be in root folder "/"
        // Check if user has read access
        if (user_has_read_access(p.username, file_table[i].meta)) {
            files_to_show[file_count_to_show++] = file_table[i].meta;
        }
    }
    
    pthread_mutex_unlock(&lock);
    
    // Display files
    if (file_count_to_show == 0) {
        dprintf(fd, "[NS] No files found in folder '%s'.\n", folder_path);
        log_response("VIEWFOLDER", p.username, client_ip, client_port, "NO_FILES");
        return;
    }
    
    // Simple list format (similar to VIEW without -l)
    for (int i = 0; i < file_count_to_show; i++) {
        dprintf(fd, "--> %s\n", files_to_show[i]->filename);
    }
    
    log_response("VIEWFOLDER", p.username, client_ip, client_port, "OK");
}

// ======== Command Handlers ========
// These functions handle operations that are processed directly by the Name Server
// without involving Storage Servers

// VIEW: Lists files based on access permissions
// Specification: 
// - Default: Lists files user has access to
// - VIEW -a: Lists all files on system (irrespective of access)
// - VIEW -l: Lists files with details (word count, char count, last access, owner)
// - VIEW -al: Lists all files with details
// NOTE: VIEW queries Storage Servers directly to get all files, not just what NS knows about
void handle_view(int fd, Packet p) {
    char client_ip[INET_ADDRSTRLEN] = "unknown";
    int client_port = 0;
    
    pthread_mutex_lock(&lock);
    
    // Validate flag
    if (p.flag1 != VIEW_USER_ONLY && p.flag1 != VIEW_ALL && 
        p.flag1 != VIEW_LONG && p.flag1 != VIEW_ALL_LONG) {
        pthread_mutex_unlock(&lock);
        dprintf(fd, "[NS] ERROR: Invalid flag for VIEW command. Error code: %d - %s\n", 
                ERR_INVALID_PARAMETERS, get_error_message(ERR_INVALID_PARAMETERS));
        log_response("VIEW", p.username, client_ip, client_port, "INVALID_FLAG");
        return;
    }
    
    if (ss_count == 0) {
        pthread_mutex_unlock(&lock);
        dprintf(fd, "[NS] ERROR: No Storage Server available. Error code: %d - %s\n",
                ERR_STORAGE_SERVER_UNAVAILABLE, get_error_message(ERR_STORAGE_SERVER_UNAVAILABLE));
        log_response("VIEW", p.username, client_ip, client_port, "NO_SS_AVAILABLE");
        return;
    }
    
    pthread_mutex_unlock(&lock);
    
    // Forward VIEW to all Storage Servers and aggregate results
    // Since VIEW should show all files on the system, we query SS directly
    for (int ss_idx = 0; ss_idx < ss_count; ss_idx++) {
        int ss_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (ss_sock < 0) {
            continue;  // Skip this SS if we can't create socket
        }
        
        struct sockaddr_in ss_addr = {0};
        ss_addr.sin_family = AF_INET;
        ss_addr.sin_port = htons(ss_list[ss_idx].port);
        inet_pton(AF_INET, ss_list[ss_idx].ip, &ss_addr.sin_addr);
        
        if (connect(ss_sock, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) < 0) {
            close(ss_sock);
            continue;  // Skip this SS if we can't connect
        }
        
        // Send username first (required by SS for access control)
        send(ss_sock, p.username, strlen(p.username), 0);
        
        // Send VIEW packet
        send(ss_sock, &p, sizeof(p), 0);
        
        // Receive response from SS (may include multiple lines)
        char response[NS_BUFFER_SIZE_4096];
        size_t total = 0;
        int n;
        while ((n = recv(ss_sock, response + total, sizeof(response) - total - 1, 0)) > 0) {
            total += n;
            if (total >= sizeof(response) - 1) break;
            response[total] = '\0';
            // Check for completion markers
            if (strstr(response, "[SS] VIEW done.") != NULL) {
                usleep(10000);  // Small delay to ensure all data is received
                break;
            }
        }
        response[total] = '\0';
        
        // Forward response to client (excluding the "[SS] VIEW done." marker)
        if (total > 0) {
            // Remove the "[SS] VIEW done." line before forwarding
            char *done_marker = strstr(response, "[SS] VIEW done.");
            if (done_marker) {
                *done_marker = '\0';
            }
            dprintf(fd, "%s", response);
        }
        
        close(ss_sock);
    }
    
    log_response("VIEW", p.username, client_ip, client_port, "OK");
}

// LIST: Lists all users currently registered in the system
// Specification: Users can view list of all users registered in the system
void handle_list(int fd) {
    pthread_mutex_lock(&lock);
    for (int i = 0; i < user_count; i++)
        dprintf(fd, "--> %s\n", active_users[i]);
    pthread_mutex_unlock(&lock);
}

// INFO: Get additional information about a file
// Specification: Display file details including:
// - File name, owner, size, created/modified timestamps
// - Access rights (list of users with read/write access)
// - Last accessed time
// - User must have read access to view file info
void handle_info(int fd, Packet p) {
    char client_ip[INET_ADDRSTRLEN] = "unknown";
    int client_port = 0;
    
    // Use efficient hash table lookup
    meta_data *meta = get_file_metadata(p.filename);
    
    if (!meta) {
        dprintf(fd, "[NS] ERROR: File not found. Error code: %d - %s\n", 
                ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
        log_response("INFO", p.username, client_ip, client_port, "FILE_NOT_FOUND");
        return;
    }
    
    // Check if user has read access
    pthread_mutex_lock(&lock);
    int has_access = user_has_read_access(p.username, meta);
    pthread_mutex_unlock(&lock);
    
    if (!has_access) {
        dprintf(fd, "[NS] ERROR: Unauthorized access. Error code: %d - %s\n", 
                ERR_READ_ACCESS_DENIED, get_error_message(ERR_READ_ACCESS_DENIED));
        log_response("INFO", p.username, client_ip, client_port, "UNAUTHORIZED");
        return;
    }
    
    // Format timestamps
    char created_buf[64], modified_buf[64], last_access_buf[64];
    format_timestamp(created_buf, sizeof(created_buf), meta->created);
    format_timestamp(modified_buf, sizeof(modified_buf), meta->modified);
    format_timestamp(last_access_buf, sizeof(last_access_buf), meta->last_accessed);
    
    // Calculate file size in bytes (approximate: charcount + metadata overhead)
    size_t file_size_bytes = meta->charcount;  // Simplified: use charcount as size
    
    // Display info matching example format
    dprintf(fd, "--> File: %s\n", meta->filename);
    dprintf(fd, "--> Owner: %s\n", meta->owner);
    dprintf(fd, "--> Created: %s\n", created_buf);
    dprintf(fd, "--> Last Modified: %s\n", modified_buf);
    dprintf(fd, "--> Size: %zu bytes\n", file_size_bytes);
    
    // Display access list
    dprintf(fd, "--> Access: ");
    // Owner always has RW access
    dprintf(fd, "%s (RW)", meta->owner);
    
    // Display other users with access
    // Ensure users_with_access is initialized (for backward compatibility with older files)
    pthread_mutex_lock(&lock);
    if (!meta->users_with_access) {
        meta->users_with_access = (linkedlist_t *)malloc(sizeof(linkedlist_t));
        if (meta->users_with_access) {
            init_linkedlist(meta->users_with_access);
        }
    }
    
    if (meta->users_with_access && meta->users_with_access->head) {
        for (node_t *ua_node = meta->users_with_access->head; ua_node != NULL; ua_node = ua_node->next) {
            user_access *ua = (user_access *)ua_node->data;
            if (ua && strcmp(ua->username, meta->owner) != 0) {  // Don't show owner twice
                const char *access_str = (ua->access_type == ACCESS_WRITE) ? "RW" : "R";
                dprintf(fd, ", %s (%s)", ua->username, access_str);
            }
        }
    }
    pthread_mutex_unlock(&lock);
    
    dprintf(fd, "\n");
    
    // Always print Last Accessed, even if it's 0 (will show as epoch time)
    dprintf(fd, "--> Last Accessed: %s\n", last_access_buf);
    
    dprintf(fd, "%s\n", PROTOCOL_STOP);
    log_response("INFO", p.username, client_ip, client_port, "OK");
}

// ADDACCESS: Owner grants access to other users
// Specification: 
// - Only file owner can add access
// - ADDACCESS -R: Grants read access
// - ADDACCESS -W: Grants write (and read) access
// - Owner always has both read and write access
int handle_addaccess(Packet p) {
    // Use efficient hash table lookup
    meta_data *meta = get_file_metadata(p.filename);
    if (!meta) {
        return -1;  // File not found
    }
    
    // Verify requester is owner
    if (strcmp(meta->owner, p.username) != 0) {
        return -2;  // Not owner
    }
    
    // Initialize users_with_access if needed
    if (!meta->users_with_access) {
        meta->users_with_access = (linkedlist_t *)malloc(sizeof(linkedlist_t));
        if (meta->users_with_access) {
            init_linkedlist(meta->users_with_access);
        } else {
            return -1;  // Memory allocation failed
        }
    }
    
    // Check if user already has access
    for (node_t *ua_node = meta->users_with_access->head; ua_node != NULL; ua_node = ua_node->next) {
        user_access *ua = (user_access *)ua_node->data;
        if (ua && strcmp(ua->username, p.payload) == 0) {
            // User already has access - update access type if upgrading to write
            if (p.flag1 == ACCESS_WRITE) {
                ua->access_type = ACCESS_WRITE;  // Upgrade to write access
            }
            return 0;  // Success (already had access)
        }
    }
    
    // Add new user access entry
    user_access *ua = (user_access *)malloc(sizeof(user_access));
    if (ua) {
        strncpy(ua->username, p.payload, FILE_NAME_SIZE - 1);
        ua->username[FILE_NAME_SIZE - 1] = '\0';
        ua->access_type = p.flag1;  // ACCESS_READ or ACCESS_WRITE
        ua->last_access = 0;  // Will be set on first access
        insert_at_n(meta->users_with_access, ua, meta->users_with_access->size);
    }
    
    return 0;  // Success
}

// REMACCESS: Owner removes access from other users
// Specification: Only file owner can remove access from users
// Removes all access (both read and write) for the specified user
int handle_remaccess(Packet p) {
    // Use efficient hash table lookup
    meta_data *meta = get_file_metadata(p.filename);
    if (!meta) {
        return -1;  // File not found
    }
    
    // Verify requester is owner
    if (strcmp(meta->owner, p.username) != 0) {
        return -2;  // Not owner
    }
    
    // Find user in access list and remove
    if (meta->users_with_access) {
        node_t *ua_node = meta->users_with_access->head;
        size_t idx = 0;
        while (ua_node) {
            user_access *ua = (user_access *)ua_node->data;
            if (ua && strcmp(ua->username, p.payload) == 0) {
                // Remove from list
                remove_at_n(meta->users_with_access, idx);
                free(ua);
                return 0;  // Success
            }
            ua_node = ua_node->next;
            idx++;
        }
    }
    
    return 0;  // Success (user not in list is also success - nothing to remove)
}

// EXEC: Execute file content as shell commands
// Specification: 
// - Users with read access can execute files
// - NS requests file content from SS
// - NS executes each line as shell command and pipes output to client
// - Execution happens on Name Server, not Storage Server
void handle_exec(int fd, Packet p) {
    if (ss_count == 0) { dprintf(fd, "[NS] No SS available.\n"); return; }
    
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
                send(test_sock, "\n", 1, 0);
                
                Packet info_p;
                memset(&info_p, 0, sizeof(info_p));
                info_p.opcode = CMD_INFO;
                strcpy(info_p.filename, p.filename);
                strcpy(info_p.username, p.username);
                send(test_sock, &info_p, sizeof(info_p), 0);
                
                // Read response
                char response[256];
                int n = recv(test_sock, response, sizeof(response) - 1, 0);
                close(test_sock);
                
                if (n > 0) {
                    response[n] = '\0';
                    // If response doesn't contain "not found" or "ERROR", file exists
                    if (strstr(response, "not found") == NULL && 
                        strstr(response, "ERROR") == NULL &&
                        strstr(response, "Error code") == NULL) {
                        ss_idx = i;
                        fprintf(stderr, "[NS DEBUG] Found file '%s' on SS %d (%s:%d)\n", 
                                p.filename, i, ss_list[i].ip, ss_list[i].port);
                        break;
                    }
                }
            }
        }
        
        if (ss_idx < 0) {
            dprintf(fd, "[NS] File not found in system.\n");
            return;
        }
    }
    
    // Enforce read access control for EXEC
    // Specification: Users need read access to execute files
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
            return;
        }
    }
    
    int ss_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ss_addr = {0};
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(ss_list[ss_idx].port);
    inet_pton(AF_INET, ss_list[ss_idx].ip, &ss_addr.sin_addr);
    if (connect(ss_sock, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) < 0) {
        dprintf(fd, "[NS] Could not reach SS.\n"); 
        log_response("EXEC", p.username, "unknown", 0, "FAILED: Could not connect to SS");
        return;
    }
    
    // Send username first (for access control on SS side)
    // Protocol: SS expects username followed by newline
    send(ss_sock, p.username, strlen(p.username), 0);
    send(ss_sock, "\n", 1, 0);
    
    // Send EXEC packet directly to SS (completely separate from READ)
    // SS has its own EXEC handler that reads file structure directly
    Packet exec_p;
    memset(&exec_p, 0, sizeof(exec_p));
    exec_p.opcode = CMD_EXEC;
    strcpy(exec_p.username, p.username);
    strcpy(exec_p.filename, p.filename);
    send(ss_sock, &exec_p, sizeof(exec_p), 0);
    
    // Receive file content from SS until STOP marker
    // Specification: SS sends content followed by "STOP" marker
    char buf[NS_BUFFER_SIZE_4096] = {0};
    size_t total = 0;
    int n;
    while ((n = recv(ss_sock, buf + total, sizeof(buf) - total - 1, 0)) > 0) {
        total += n;
        buf[total] = '\0';
        // Check if STOP marker is in the received data
        if (strstr(buf, PROTOCOL_STOP) != NULL) {
            // Remove STOP marker and everything after it
            char *stop_pos = strstr(buf, PROTOCOL_STOP);
            *stop_pos = '\0';
            break;
        }
        if (total >= sizeof(buf) - 1) break;  // Buffer full
    }
    close(ss_sock);
    
    if (total == 0) {
        dprintf(fd, "[NS] Could not retrieve file content from SS.\n");
        log_response("EXEC", p.username, "unknown", 0, "FAILED: No content received");
        return;
    }
    
    // Debug: print what we received
    fprintf(stderr, "[NS DEBUG] EXEC: Received %d bytes, content:\n%s\n", total, buf);
    
    // Remove STOP marker if still present (should already be removed above)
    // But keep all newlines - they separate commands!
    
    // Log EXEC request
    log_request("EXEC", p.username, "unknown", 0, p.filename);
    
    // Execute file content as shell commands
    // SS now returns content with newlines between sentences (via read_file_for_exec)
    // So we can simply split by newlines, and also handle semicolons within lines
    
    // Process content line by line - split by newlines
    // Each line is a separate command
    char *content_copy = strdup(buf);
    if (!content_copy) {
        log_response("EXEC", p.username, "unknown", 0, "FAILED: Memory error");
        return;
    }
    
    char *line = content_copy;
    char *next_line;
    int line_num = 0;
    
    // Split by newlines and execute each line
    while ((next_line = strchr(line, '\n')) != NULL || (next_line = strchr(line, '\r')) != NULL) {
        // Null-terminate this line
        *next_line = '\0';
        
        // Trim leading/trailing whitespace
        char *start = line;
        while (*start == ' ' || *start == '\t') start++;
        char *end = start + strlen(start) - 1;
        while (end > start && (*end == ' ' || *end == '\t')) *end-- = '\0';
        
        // Execute this command if not empty
        if (strlen(start) > 0) {
            line_num++;
            fprintf(stderr, "[NS DEBUG] EXEC: Processing line %d: '%s'\n", line_num, start);
            
            // If line contains semicolons, split further
            char *saveptr;
            char *cmd = strtok_r(start, ";", &saveptr);
            while (cmd != NULL) {
                // Trim whitespace from command
                while (*cmd == ' ' || *cmd == '\t') cmd++;
                char *cmd_end = cmd + strlen(cmd) - 1;
                while (cmd_end > cmd && (*cmd_end == ' ' || *cmd_end == '\t')) *cmd_end-- = '\0';
                
                    if (strlen(cmd) > 0) {
                        fprintf(stderr, "[NS DEBUG] EXEC: Executing command: '%s'\n", cmd);
                        log_exec_command(p.username, p.filename, cmd);
                        FILE *pipe = popen(cmd, "r");
                        if (pipe) {
                            char out[NS_OUTPUT_SIZE];
                            int output_count = 0;
                            while (fgets(out, sizeof(out), pipe)) {
                                // Use send() directly for socket to ensure data is sent immediately
                                send(fd, out, strlen(out), 0);
                                output_count++;
                            }
                            int status = pclose(pipe);
                            fprintf(stderr, "[NS DEBUG] Command '%s' produced %d lines, exit status %d\n", 
                                    cmd, output_count, status);
                            if (status != 0) {
                                fprintf(stderr, "[NS DEBUG] Command '%s' exited with status %d\n", cmd, status);
                            }
                        } else {
                            fprintf(stderr, "[NS DEBUG] Failed to execute command: '%s'\n", cmd);
                            log_response("EXEC", p.username, "unknown", 0, "WARNING: Command execution failed");
                        }
                    }
                cmd = strtok_r(NULL, ";", &saveptr);
            }
        }
        
        // Move to next line
        line = next_line + 1;
        // Skip any additional newline characters
        while (*line == '\n' || *line == '\r') line++;
    }
    
    // Process last line if it doesn't end with newline
    if (strlen(line) > 0) {
        // Trim leading/trailing whitespace
        char *start = line;
        while (*start == ' ' || *start == '\t') start++;
        char *end = start + strlen(start) - 1;
        while (end > start && (*end == ' ' || *end == '\t')) *end-- = '\0';
        
        if (strlen(start) > 0) {
            line_num++;
            fprintf(stderr, "[NS DEBUG] EXEC: Processing final line %d: '%s'\n", line_num, start);
            
            // If line contains semicolons, split further
            char *saveptr;
            char *cmd = strtok_r(start, ";", &saveptr);
            while (cmd != NULL) {
                // Trim whitespace from command
                while (*cmd == ' ' || *cmd == '\t') cmd++;
                char *cmd_end = cmd + strlen(cmd) - 1;
                while (cmd_end > cmd && (*cmd_end == ' ' || *cmd_end == '\t')) *cmd_end-- = '\0';
                
                    if (strlen(cmd) > 0) {
                        fprintf(stderr, "[NS DEBUG] EXEC: Executing final command: '%s'\n", cmd);
                        log_exec_command(p.username, p.filename, cmd);
                        FILE *pipe = popen(cmd, "r");
                        if (pipe) {
                            char out[NS_OUTPUT_SIZE];
                            int output_count = 0;
                            while (fgets(out, sizeof(out), pipe)) {
                                // Use send() directly for socket to ensure data is sent immediately
                                send(fd, out, strlen(out), 0);
                                output_count++;
                            }
                            int status = pclose(pipe);
                            fprintf(stderr, "[NS DEBUG] Final command '%s' produced %d lines, exit status %d\n", 
                                    cmd, output_count, status);
                            if (status != 0) {
                                fprintf(stderr, "[NS DEBUG] Final command '%s' exited with status %d\n", cmd, status);
                            }
                        } else {
                            log_response("EXEC", p.username, "unknown", 0, "WARNING: Command execution failed");
                        }
                    }
                cmd = strtok_r(NULL, ";", &saveptr);
            }
        }
    }
    
    free(content_copy);
    
    log_response("EXEC", p.username, "unknown", 0, "OK");
}

