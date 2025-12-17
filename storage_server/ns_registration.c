/**
 * ============================================================================
 * ns_registration.c - Name Server Registration and Initialization
 * ============================================================================
 * 
 * PURPOSE:
 * This module handles registration of the Storage Server with the Name Server
 * and server initialization. It manages the connection to the Name Server and
 * sends file list information during registration.
 * 
 * ARCHITECTURE:
 * - register_with_ns(): Registers SS with NS and sends file list
 * - server_init(): Initializes SS data structures and loads existing files
 * 
 * SPECIFICATION:
 * - SS sends vital details to NS upon initialization:
 *   - IP address, port for NM connection, port for client connection, list of files
 * - New SS can dynamically add entries to NS at any point during execution
 * 
 * ============================================================================
 */

 #include "storage_server.h"
 #include "connection.h"
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <dirent.h>
 #include <sys/stat.h>
 #include <unistd.h>
 
// External variables
extern int ss_port;
extern int ss_client_port;  // Port for client connections
extern char *ss_ip;
extern linkedlist_t file_list;
extern struct hsearch_data *name_to_ptr;
 
 // Forward declaration for append_file (defined in misc.c)
 // Note: append_file is a wrapper around append_file_dynamic that converts int to size_t
 extern char *append_file_dynamic(const char *filepath, char *buf, size_t *buf_size, size_t *len);
 
 // Wrapper function to match the signature used in original code
 char *append_file(const char *filepath, char *buf, int *buf_size, int *len) {
     size_t buf_size_sz = *buf_size;
     size_t len_sz = *len;
     char *result = append_file_dynamic(filepath, buf, &buf_size_sz, &len_sz);
     *buf_size = (int)buf_size_sz;
     *len = (int)len_sz;
     return result;
 }
 
 /**
  * Register this Storage Server with the Name Server
  * 
  * WHAT: Connects to NS, sends registration message with IP/port, and sends file list
  * WHERE: Called during server initialization and potentially for re-registration
  * WHY: NS needs to know about SS and its files to route client requests correctly
  * 
  * SPECIFICATION:
  * - New SS can dynamically add entries to NS at any point during execution
  * - SS sends: IP address, port, and list of files it stores
  * - NS responds with "REGISTERED" on success
  * 
 * @param ns_ip - IP address of the Name Server
 * @param ns_port - Port number of the Name Server
 * @param client_port - Port number for client connections
 * @param filepath - Path to file containing file list information
 * @return 0 on success, -1 on failure
 */
int register_with_ns(const char *ns_ip, int ns_port, int client_port, char *filepath)
 {
     // Connect to Name Server
     // This establishes the initial connection for registration
     int sock = net_connect(ns_ip, ns_port);
     if (sock < 0) {
         perror("[SS] Registration: Failed to connect to Name Server");
         return -1;
     }
 
     // Get local IP and port information
     // NS needs to know:
     // 1. SS IP address
     // 2. Port for NS connection (ephemeral port used for this registration connection)
     // 3. Port for client connections (SS_CLIENT_PORT)
     int ns_connection_port;
     net_local_info(sock, (char *)ss_ip, INET_ADDRSTRLEN, &ns_connection_port);
 
     // Prepare registration message
     // Format: "REGISTER SS <ip> <ns_port> <client_port>\n"
     // Specification: SS sends IP address, port for NM connection, port for client connection
     int buf_size = BUFFER_SIZE_2048 / 2;  // Initial size
     int len = 0;
     char *buf = malloc(BUFFER_SIZE_4096);
     if (!buf) {
         perror("[SS] Registration: Memory allocation failed");
         net_close(sock);
         return -1;
     }
 
     // Build registration message with SS IP, NS connection port, and client port
     len = sprintf(buf, PROTOCOL_REGISTER_SS " %s %d %d\n", ss_ip, ns_connection_port, client_port);
 
     // Append file list information to registration message
     // This tells NS which files are stored on this SS
     buf = append_file(filepath, buf, &buf_size, &len);
     if (!buf) {
         perror("[SS] Registration: Failed to read file list");
         net_close(sock);
         return -1;
     }
 
     // Send registration message to NS
     net_send(sock, buf, strlen(buf));
 
     // Wait for registration confirmation
     // NS should respond with "REGISTERED" on success
     char response[RESPONSE_BUFFER_SIZE];
     ssize_t n = net_recv(sock, response, sizeof(response) - 1);
     if (n <= 0) {
         perror("[SS] Registration: No response from Name Server");
         net_close(sock);
         free(buf);
         return -1;
     }
 
     response[n] = '\0';
     // Remove trailing newline if present
     response[strcspn(response, "\r\n")] = '\0';
     
     // Check if response contains "REGISTERED" (more robust - handles variations)
     if (strstr(response, PROTOCOL_REGISTERED) == NULL) {
         printf("[SS] Registration: Name Server responded with error: %s\n", response);
         printf("[SS] Registration: Expected response containing '%s'\n", PROTOCOL_REGISTERED);
         net_close(sock);
         free(buf);
         return -1;
     }
 
     // Registration successful
     net_close(sock);
     free(buf);
     return 0;
 }
 
 /**
  * Initialize Storage Server
  * 
  * WHAT: Sets up SS data structures, loads existing files from disk, and registers with NS
  * WHERE: Called at the start of main() before accepting client connections
  * WHY: Prepares the server to handle client requests and makes it known to the NS
  * 
  * SPECIFICATION:
  * - SS must load existing files from storage directory
  * - SS must register with NS upon initialization
  * - File metadata must be persisted and restored
  * 
 * @param ns_ip - IP address of the Name Server
 * @param ns_port - Port number of the Name Server
 * @param client_port - Port number for client connections
 * @return 0 on success, -1 on failure
 */
int server_init(const char *ns_ip, int ns_port, int client_port)
 {
     // Allocate and initialize hash tables
     // These enable efficient O(1) lookups for files, checkpoints, and undo history
     name_to_ptr = (struct hsearch_data *)malloc(sizeof(struct hsearch_data));
     if (!name_to_ptr) {
         perror("[SS] malloc name_to_ptr");
         return -1;
     }
     if (init_struct_table(name_to_ptr, HASH_TABLE_SIZE) != 0) {
         fprintf(stderr, "[SS] Failed to initialize name_to_ptr hash table\n");
         free(name_to_ptr);
         return -1;
     }
     
     curr_to_prev = (struct hsearch_data *)malloc(sizeof(struct hsearch_data));
     if (!curr_to_prev) {
         perror("[SS] malloc curr_to_prev");
         hdestroy_r(name_to_ptr);
         free(name_to_ptr);
         return -1;
     }
     if (init_struct_table(curr_to_prev, HASH_TABLE_SIZE) != 0) {
         fprintf(stderr, "[SS] Failed to initialize curr_to_prev hash table\n");
         hdestroy_r(name_to_ptr);
         free(name_to_ptr);
         free(curr_to_prev);
         return -1;
     }
     
     checkpoints = (struct hsearch_data *)malloc(sizeof(struct hsearch_data));
     if (!checkpoints) {
         perror("[SS] malloc checkpoints");
         hdestroy_r(name_to_ptr);
         hdestroy_r(curr_to_prev);
         free(name_to_ptr);
         free(curr_to_prev);
         return -1;
     }
     if (init_struct_table(checkpoints, HASH_TABLE_SIZE) != 0) {
         fprintf(stderr, "[SS] Failed to initialize checkpoints hash table\n");
         hdestroy_r(name_to_ptr);
         hdestroy_r(curr_to_prev);
         free(name_to_ptr);
         free(curr_to_prev);
         free(checkpoints);
         return -1;
     }
     
     // Initialize global file list
     // This linked list stores all files managed by this SS
     init_linkedlist(&file_list);
 
     // Create or open server info file
     // This file stores metadata about all files for persistence
     FILE *info_file = fopen("storage_server_info.txt", "w");
     if (!info_file) {
         perror("[SS] fopen");
         // Cleanup hash tables on error
         hdestroy_r(name_to_ptr);
         hdestroy_r(curr_to_prev);
         hdestroy_r(checkpoints);
         free(name_to_ptr);
         free(curr_to_prev);
         free(checkpoints);
         return -1;
     }
 
     // Ensure storage directory exists
     // Files are stored in ./storage_current/ directory
     DIR *dir = opendir(STORAGE_DIRECTORY);
     if (!dir) {
         if (mkdir(STORAGE_DIRECTORY, DIRECTORY_PERMISSIONS) != 0) {
             perror("[SS] mkdir");
             fclose(info_file);
             return -1;
         }
         dir = opendir("./storage_current");
     }
 
    // Load existing files from storage directory
    // This restores files that existed before server restart
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char *entry_name = entry->d_name;
        
        // Skip . and .. entries
        if (strcmp(entry_name, ".") == 0 || strcmp(entry_name, "..") == 0) {
            continue;
        }
        
        // Use stat() to check if it's a regular file (more reliable than d_type)
        // d_type may be DT_UNKNOWN on some filesystems (e.g., WSL/Windows)
        char filepath[FILEPATH_SIZE];
        snprintf(filepath, sizeof(filepath), STORAGE_DIRECTORY "/%s", entry_name);
        struct stat st;
        if (stat(filepath, &st) != 0) {
            continue;  // Skip if stat fails
        }
        
        // Only process regular files (not directories, symlinks, etc.)
        if (S_ISREG(st.st_mode)) {
             
             // Check if this is an undo file (.undo extension)
             size_t name_len = strlen(entry_name);
             if (name_len > 5 && strcmp(entry_name + name_len - 5, ".undo") == 0) {
                 // This is an undo state file - load it into undo hash table
                 char filepath[FILEPATH_SIZE];
                 snprintf(filepath, sizeof(filepath), STORAGE_DIRECTORY "/%s", entry_name);
                 
                 file *undo_file = file_to_struct(filepath);
                 if (undo_file) {
                     // Extract original filename (remove .undo extension)
                     char original_filename[FILE_NAME_SIZE];
                     strncpy(original_filename, entry_name, name_len - 5);
                     original_filename[name_len - 5] = '\0';
                     
                     // Restore original filename in the structure
                     strncpy(undo_file->info->filename, original_filename, FILE_NAME_SIZE - 1);
                     undo_file->info->filename[FILE_NAME_SIZE - 1] = '\0';
                     
                     // Add to undo hash table
                     if (add_struct_to_htable(undo_file, curr_to_prev) != 0) {
                         free_file(undo_file);
                     }
                 }
            } else {
                // Regular file - load it into memory
                // filepath already set above
                
                // Convert file from disk format to in-memory structure
                file *f = file_to_struct(filepath);
                if (!f) {
                    fprintf(stderr, "[SS] Warning: Failed to load file: %s (skipping)\n", filepath);
                    continue;  // Skip this file instead of exiting
                }
                add_struct_to_htable(f, name_to_ptr);
                
                // CRITICAL FIX: Use the actual directory entry name as the source of truth
                // The filename stored in binary metadata might be corrupted, so we override it
                // with the actual filename from the filesystem
                if (f->info && strcmp(f->info->filename, entry_name) != 0) {
                    // Filename mismatch - update to use directory entry name
                    char old_filename[FILE_NAME_SIZE];
                    strncpy(old_filename, f->info->filename, FILE_NAME_SIZE - 1);
                    old_filename[FILE_NAME_SIZE - 1] = '\0';
                    
                    // Update filename in metadata to match directory entry
                    size_t entry_name_len = strlen(entry_name);
                    if (entry_name_len >= FILE_NAME_SIZE) entry_name_len = FILE_NAME_SIZE - 1;
                    strncpy(f->info->filename, entry_name, entry_name_len);
                    f->info->filename[entry_name_len] = '\0';
                    
                    // Update hash table: remove old entry and add new one with correct filename
                    remove_struct_from_htable(old_filename, name_to_ptr);
                    if (add_struct_to_htable(f, name_to_ptr) != 0) {
                        fprintf(stderr, "[SS] Warning: Failed to update hash table for file: %s (skipping)\n", entry_name);
                        free_file(f);
                        continue;
                    }
                    
                    fprintf(stderr, "[SS] Fixed filename mismatch: metadata had '%s', using directory entry '%s'\n", 
                            old_filename, entry_name);
                }
                
                // Check if file is already in file_list (avoid duplicates)
                bool already_in_list = false;
                for (node_t *check = file_list.head; check != NULL; check = check->next) {
                    file *list_file = (file *)check->data;
                    if (list_file == f || (list_file && list_file->info && f->info && 
                        strcmp(list_file->info->filename, f->info->filename) == 0)) {
                        already_in_list = true;
                        break;
                    }
                }
                
                if (!already_in_list) {
                    // Add full file structure to list (not just metadata)
                    // The file is already in the hash table from file_to_struct
                    insert_at_n(&file_list, f, file_list.size);
                    fprintf(stderr, "[SS DEBUG] Added file '%s' to file_list (size now=%zu)\n", 
                            f->info->filename, file_list.size);
                } else {
                    fprintf(stderr, "[SS DEBUG] File '%s' already in file_list, skipping duplicate\n", 
                            f->info->filename);
                    // Free the duplicate file structure since we're not using it
                    free_file(f);
                }
            }
        }
    }
     closedir(dir);
 
     // Write file list to info file in TEXT format for Name Server
     // Format: One file per line: "FILE|filename|owner|wordcount|charcount|created|modified|last_accessed|lastmodifiedby|access_list"
     // Access list format: "user1:access_type:last_access,user2:access_type:last_access"
     fprintf(info_file, PROTOCOL_FILE_LIST "\n");
     
    size_t file_count = 0;
    for (node_t *curr = file_list.head; curr != NULL; curr = curr->next) {
        file *f = (file *)curr->data;
        if (f && f->info) {
            file_count++;
        }
    }
    fprintf(info_file, "%zu\n", file_count);  // Number of files
    
    for (node_t *curr = file_list.head; curr != NULL; curr = curr->next) {
        file *f = (file *)curr->data;
        if (f && f->info) {
            meta_data *meta = f->info;
             // Write file metadata in text format: FILE|filename|owner|wordcount|charcount|created|modified|last_accessed|lastmodifiedby
             fprintf(info_file, PROTOCOL_FILE "|%s|%s|%zu|%zu|%ld|%ld|%ld|%s",
                     meta->filename,
                     meta->owner,
                     meta->wordcount,
                     meta->charcount,
                     (long)meta->created,
                     (long)meta->modified,
                     (long)meta->last_accessed,
                     meta->lastmodifiedby);
             
             // Write access list: user1:access_type:last_access,user2:access_type:last_access
             if (meta->users_with_access && meta->users_with_access->size > 0) {
                 fprintf(info_file, "|");
                 int first = 1;
                 for (node_t *user_node = meta->users_with_access->head; user_node != NULL; user_node = user_node->next) {
                     user_access *ua = (user_access *)user_node->data;
                     if (ua) {
                         if (!first) fprintf(info_file, ",");
                         fprintf(info_file, "%s:%d:%ld", ua->username, ua->access_type, (long)ua->last_access);
                         first = 0;
                     }
                 }
             }
             fprintf(info_file, "\n");
         }
     }
     // Write end marker
     fprintf(info_file, PROTOCOL_END_FILE_LIST "\n");
     fclose(info_file);
 
     // Register with Name Server
     // This makes the SS known to the NS so it can route client requests
            if (register_with_ns(ns_ip, ns_port, client_port, SS_INFO_FILENAME) != 0) {
         perror("[SS] Initial registration with Name Server failed");
         return -1;
     }
     
     return 0;
 }
 