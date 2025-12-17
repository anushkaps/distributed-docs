#include "name_server.h"
#include "client_handler.h"
#include "handlers.h"
#include "forwarding.h"
#include "utils.h"
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/select.h>
#include "../linkedlist.h"
#include <search.h>

// ======== Client Handler ========
// Main handler for all incoming connections (both clients and storage servers)
// Runs in a separate thread for each connection to support concurrent access
// Specification: Multiple clients may run concurrently, all must interact simultaneously

// Helper: handle storage server registration and file-list parsing
static void handle_storage_server_registration(int client_fd, char *first_msg, char *first_line, char *conn_ip) {
    char ss_reg_ip[INET_ADDRSTRLEN];
    int ns_port, client_port;
    int ss_index = -1;
    if (sscanf(first_line, PROTOCOL_REGISTER_SS " %s %d %d", ss_reg_ip, &ns_port, &client_port) == 3) {
        int port = client_port;
        pthread_mutex_lock(&lock);
        int found = 0;
        for (int i = 0; i < ss_count; i++) {
            if (ss_list[i].port == port) {
                ss_list[i].fd = client_fd;
                // Use conn_ip (the IP NS sees) instead of ss_reg_ip (what SS claims)
                // This ensures clients get the correct reachable IP address
                strcpy(ss_list[i].ip, conn_ip);
                ss_index = i;
                found = 1;
                time_t t = time(NULL);
                char ts[NS_TIMESTAMP_SIZE];
                strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
                printf("[%s] [NS] ACK: Storage Server re-registered | IP: %s (from connection) | NS Port: %d | Client Port: %d\n", 
                       ts, conn_ip, ns_port, client_port);
                log_response("SS_RE_REGISTRATION", "SYSTEM", conn_ip, client_port, "OK");
                dprintf(client_fd, PROTOCOL_REGISTERED "\n");
                break;
            }
        }
        if (!found && ss_count < MAX_SS) {
            ss_list[ss_count].fd = client_fd;
            // Use conn_ip (the IP NS sees) instead of ss_reg_ip (what SS claims)
            // This ensures clients get the correct reachable IP address
            strcpy(ss_list[ss_count].ip, conn_ip);
            ss_list[ss_count].port = port;
            ss_index = ss_count;
            ss_count++;
            time_t t = time(NULL);
            char ts[NS_TIMESTAMP_SIZE];
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
            printf("[%s] [NS] ACK: Storage Server registered | IP: %s (from connection) | NS Port: %d | Client Port: %d\n", 
                   ts, conn_ip, ns_port, client_port);
            log_request("SS_REGISTRATION", "SYSTEM", conn_ip, client_port, "New SS connection");
            dprintf(client_fd, PROTOCOL_REGISTERED "\n");
        }
        pthread_mutex_unlock(&lock);

        if (ss_index >= 0) {
            char *file_list_start = strstr(first_msg, PROTOCOL_FILE_LIST);
            if (file_list_start) {
                char *line = file_list_start + PROTOCOL_FILE_LIST_LEN;
                while (*line == '\n' || *line == '\r') line++;
                size_t file_list_count = 0;
                if (sscanf(line, "%zu", &file_list_count) != 1) {
                    file_list_count = 0;
                }
                line = strchr(line, '\n');
                if (line) line++;
                time_t t = time(NULL);
                char ts[NS_TIMESTAMP_SIZE];
                strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
                printf("[%s] [NS] Processing %zu files from SS %s:%d\n", ts, file_list_count, conn_ip, client_port);
                int files_added = 0;
                int files_processed = 0;
                for (size_t i = 0; i < file_list_count && line; i++) {
                    if (strncmp(line, PROTOCOL_END_FILE_LIST, PROTOCOL_END_FILE_LIST_LEN) == 0) {
                        break;
                    }
                    if (strncmp(line, PROTOCOL_FILE, PROTOCOL_FILE_LEN) == 0) {
                        files_processed++;
                        char *fields = line + PROTOCOL_FILE_LEN + 1;
                        meta_data *meta = (meta_data *)malloc(sizeof(meta_data));
                        if (!meta) { perror("[NS] malloc meta_data"); break; }
                        memset(meta, 0, sizeof(meta_data));
                        char *token = strtok(fields, "|");
                        int field_num = 0;
                        while (token && field_num < 10) {
                            switch (field_num) {
                                case 0:
                                    strncpy((char *)meta->filename, token, FILE_NAME_SIZE - 1);
                                    meta->filename[FILE_NAME_SIZE - 1] = '\0';
                                    break;
                                case 1:
                                    strncpy(meta->owner, token, FILE_NAME_SIZE - 1);
                                    meta->owner[FILE_NAME_SIZE - 1] = '\0';
                                    break;
                                case 2:
                                    meta->wordcount = (size_t)atoll(token);
                                    break;
                                case 3:
                                    meta->charcount = (size_t)atoll(token);
                                    break;
                                case 4:
                                    meta->created = (time_t)atoll(token);
                                    break;
                                case 5:
                                    meta->modified = (time_t)atoll(token);
                                    break;
                                case 6:
                                    meta->last_accessed = (time_t)atoll(token);
                                    break;
                                case 7:
                                    strncpy(meta->lastmodifiedby, token, FILE_NAME_SIZE - 1);
                                    meta->lastmodifiedby[FILE_NAME_SIZE - 1] = '\0';
                                    break;
                                case 8:
                                    if (strlen(token) > 0) {
                                        meta->users_with_access = (linkedlist_t *)malloc(sizeof(linkedlist_t));
                                        if (meta->users_with_access) {
                                            init_linkedlist(meta->users_with_access);
                                            char *access_token = strtok(token, ",");
                                            while (access_token) {
                                                char *user_name = access_token;
                                                char *colon1 = strchr(access_token, ':');
                                                if (colon1) {
                                                    *colon1 = '\0';
                                                    char *access_type_str = colon1 + 1;
                                                    char *colon2 = strchr(access_type_str, ':');
                                                    if (colon2) {
                                                        *colon2 = '\0';
                                                        char *last_access_str = colon2 + 1;
                                                        user_access *ua = (user_access *)malloc(sizeof(user_access));
                                                        if (ua) {
                                                            strncpy(ua->username, user_name, FILE_NAME_SIZE - 1);
                                                            ua->username[FILE_NAME_SIZE - 1] = '\0';
                                                            ua->access_type = atoi(access_type_str);
                                                            ua->last_access = (time_t)atoll(last_access_str);
                                                            insert_at_n(meta->users_with_access, ua, meta->users_with_access->size);
                                                        }
                                                    }
                                                }
                                                access_token = strtok(NULL, ",");
                                            }
                                        }
                                    }
                                    break;
                            }
                            field_num++;
                            token = strtok(NULL, "|");
                        }
                        if (!meta->users_with_access) {
                            meta->users_with_access = (linkedlist_t *)malloc(sizeof(linkedlist_t));
                            if (meta->users_with_access) init_linkedlist(meta->users_with_access);
                        }
                        /* was a new file, tracked via file_table/file_count */
                        pthread_mutex_lock(&lock);
                        int existing_index = -1;
                        for (int i = 0; i < file_count; i++) {
                            if (file_table[i].meta && strcmp(file_table[i].meta->filename, meta->filename) == 0) {
                                existing_index = i; break;
                            }
                        }
                        if (existing_index >= 0) {
                            strcpy(file_table[existing_index].ss_ip, conn_ip);
                            file_table[existing_index].ss_port = client_port;
                            if (file_table[existing_index].meta != meta) {
                                if (file_table[existing_index].meta->users_with_access) {
                                    node_t *ua_node = file_table[existing_index].meta->users_with_access->head;
                                    while (ua_node) { free(ua_node->data); ua_node = ua_node->next; }
                                    free(file_table[existing_index].meta->users_with_access);
                                }
                                free(file_table[existing_index].meta);
                            }
                            file_table[existing_index].meta = meta;
                        } else {
                            if (file_count < MAX_FILES) {
                                strcpy(file_table[file_count].ss_ip, conn_ip);
                                file_table[file_count].ss_port = client_port;
                                file_table[file_count].meta = meta;
                                    file_count++;
                                    /* was a new file; file_count updated */
                            }
                        }
                        pthread_mutex_unlock(&lock);
                        int was_in_hash_table = 0;
                        pthread_mutex_lock(&lock);
                        if (file_location_hash) {
                            ENTRY e, *ep;
                            e.key = (char *)meta->filename;
                            e.data = NULL;
                            if (hsearch_r(e, FIND, &ep, file_location_hash) != 0 && ep != NULL) {
                                was_in_hash_table = 1;
                            }
                        }
                        pthread_mutex_unlock(&lock);
                        if (add_file_location(meta->filename, conn_ip, client_port, ss_index, meta) == 0) {
                            if (!was_in_hash_table) files_added++;
                        } else {
                            fprintf(stderr, "[NS DEBUG] Failed to add file '%s' to hash table\n", meta->filename);
                            if (meta->users_with_access) {
                                node_t *ua_node = meta->users_with_access->head;
                                while (ua_node) { free(ua_node->data); ua_node = ua_node->next; }
                                free(meta->users_with_access);
                            }
                            free(meta);
                        }
                    }
                    line = strchr(line, '\n');
                    if (line) line++;
                }
                t = time(NULL);
                strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
                // Report both new files added and total files processed
                if (files_added > 0) {
                    printf("[%s] [NS] Registered %d new files (processed %d total) from SS %s:%d\n", 
                           ts, files_added, files_processed, conn_ip, client_port);
                } else if (files_processed > 0) {
                    printf("[%s] [NS] Updated %d existing files from SS %s:%d\n", 
                           ts, files_processed, conn_ip, client_port);
                } else {
                    printf("[%s] [NS] Registered 0 files from SS %s:%d\n", ts, conn_ip, client_port);
                }
                log_response("SS_REGISTRATION", "SYSTEM", conn_ip, client_port, files_processed > 0 ? "OK" : "NO_FILES");
            }
        }
    }
}

// Helper: handle a connected user client (parse username and process commands)
static void handle_user_client(int client_fd, char *first_msg, char *conn_ip, int conn_port) {
    char uname[NS_USERNAME_SIZE];
    char client_sent_ip[INET_ADDRSTRLEN] = "";
    int client_sent_port = 0;
    
    // Parse client message: "username|ip|port" or just "username"
    char *pipe1 = strchr(first_msg, '|');
    if (pipe1) {
        *pipe1 = '\0';
        strncpy(uname, first_msg, sizeof(uname)-1);
        uname[sizeof(uname)-1] = '\0';
        char *pipe2 = strchr(pipe1 + 1, '|');
        if (pipe2) {
            *pipe2 = '\0';
            strncpy(client_sent_ip, pipe1 + 1, sizeof(client_sent_ip)-1);
            client_sent_port = atoi(pipe2 + 1);
        }
    } else {
        strncpy(uname, first_msg, sizeof(uname)-1);
        uname[sizeof(uname)-1] = '\0';
    }
    if (strlen(client_sent_ip) > 0 && client_sent_port > 0) {
        strncpy(conn_ip, client_sent_ip, INET_ADDRSTRLEN-1);
        conn_port = client_sent_port;
    }
    
    pthread_mutex_lock(&lock);
    // Check if user already exists to avoid duplicates
    int user_exists = 0;
    for (int i = 0; i < user_count; i++) {
        if (strcmp(active_users[i], uname) == 0) {
            user_exists = 1;
            break;
        }
    }
    if (!user_exists && user_count < MAX_CLIENTS) {
        strcpy(active_users[user_count++], uname);
    }
    pthread_mutex_unlock(&lock);
    log_request("CONNECT", uname, conn_ip, conn_port, "");

    Packet p;
    while (recv(client_fd, &p, sizeof(p), 0) > 0) {
        const char *op_names[] = {"", "VIEW", "READ", "CREATE", "WRITE", "UNDO", "INFO", "DELETE", "STREAM", "LIST", "ADDACCESS", "REMACCESS", "EXEC", "CHECKPOINT", "LISTCHECKPOINTS", "VIEWCHECKPOINT", "REVERT", "REQUESTACCESS", "VIEWREQUESTS", "APPROVE", "REJECT"};
        const char *op_name = (p.opcode >= 1 && p.opcode <= 20) ? op_names[p.opcode] : "UNKNOWN";
        char details[NS_OUTPUT_SIZE] = "";
        if (strlen(p.filename) > 0) snprintf(details, sizeof(details), "File: %s", p.filename);
        if (p.opcode == CMD_ADDACCESS || p.opcode == CMD_REMACCESS) {
            // Safe concatenation with bounds checking
            size_t current_len = strlen(details);
            if (current_len > 0 && current_len + 3 < sizeof(details)) {
                strncat(details, " | ", sizeof(details) - current_len - 1);
                current_len = strlen(details);
            }
            if (current_len + 6 < sizeof(details)) {
                strncat(details, "User: ", sizeof(details) - current_len - 1);
                current_len = strlen(details);
            }
            size_t payload_len = strlen(p.payload);
            if (current_len + payload_len < sizeof(details) - 1) {
                strncat(details, p.payload, sizeof(details) - current_len - 1);
            }
        }
        log_request(op_name, uname, conn_ip, conn_port, details);
        switch (p.opcode) {
            case CMD_VIEW: handle_view(client_fd, p); break;
            case CMD_INFO: handle_info(client_fd, p); break;
            case CMD_LIST: {
                printf("[NS] LIST requested by %s\n", uname);
                handle_list(client_fd);
                log_response(op_name, uname, conn_ip, conn_port, "OK");
            } break;
            case CMD_ADDACCESS: {
                printf("[NS] Access modification request for file '%s' by %s\n", p.filename, uname);
                int result = handle_addaccess(p);
                if (result == -1) {
                    dprintf(client_fd, "[NS] ERROR: File not found. Error code: %d - %s\n", ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
                    log_response("ADDACCESS", uname, conn_ip, conn_port, "FILE_NOT_FOUND");
                } else if (result == -2) {
                    dprintf(client_fd, "[NS] ERROR: Only owner can modify access. Error code: %d - %s\n", 
                            ERR_NOT_OWNER, get_error_message(ERR_NOT_OWNER));
                    log_response("ADDACCESS", uname, conn_ip, conn_port, "NOT_OWNER");
                } else if (result == -3) {
                    // Extract target username from payload
                    char target_username[FILE_NAME_SIZE];
                    strncpy(target_username, p.payload, FILE_NAME_SIZE - 1);
                    target_username[FILE_NAME_SIZE - 1] = '\0';
                    dprintf(client_fd, "[NS] ERROR: User '%s' not found. Error code: %d - %s\n", 
                            target_username, ERR_USER_NOT_FOUND, get_error_message(ERR_USER_NOT_FOUND));
                    log_response("ADDACCESS", uname, conn_ip, conn_port, "USER_NOT_FOUND");
                } else { forward_access_control(client_fd, p); }
            } break;
            case CMD_REMACCESS: {
                printf("[NS] Access modification request for file '%s' by %s\n", p.filename, uname);
                int result = handle_remaccess(p);
                if (result == -1) {
                    dprintf(client_fd, "[NS] ERROR: File not found. Error code: %d - %s\n", ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
                    log_response("REMACCESS", uname, conn_ip, conn_port, "FILE_NOT_FOUND");
                } else if (result == -2) {
                    dprintf(client_fd, "[NS] ERROR: Only owner can modify access. Error code: %d - %s\n", 
                            ERR_NOT_OWNER, get_error_message(ERR_NOT_OWNER));
                    log_response("REMACCESS", uname, conn_ip, conn_port, "NOT_OWNER");
                } else if (result == -3) {
                    // Extract target username from payload
                    char target_username[FILE_NAME_SIZE];
                    strncpy(target_username, p.payload, FILE_NAME_SIZE - 1);
                    target_username[FILE_NAME_SIZE - 1] = '\0';
                    dprintf(client_fd, "[NS] ERROR: User '%s' not found. Error code: %d - %s\n", 
                            target_username, ERR_USER_NOT_FOUND, get_error_message(ERR_USER_NOT_FOUND));
                    log_response("REMACCESS", uname, conn_ip, conn_port, "USER_NOT_FOUND");
                } else { forward_access_control(client_fd, p); }
            } break;
            case CMD_EXEC: handle_exec(client_fd, p); log_response(op_name, uname, conn_ip, conn_port, "OK"); break;
            case CMD_READ: case CMD_WRITE: case CMD_STREAM: return_ss_info(client_fd, p); log_response(op_name, uname, conn_ip, conn_port, "SS_INFO_SENT"); break;
            case CMD_CREATE: case CMD_DELETE: forward_create_delete(client_fd, p); log_response(op_name, uname, conn_ip, conn_port, "FORWARDED_ACK"); break;
            default: forward_to_ss(client_fd, p); log_response(op_name, uname, conn_ip, conn_port, "FORWARDED"); break;
        }
    }
    log_response("DISCONNECT", uname, conn_ip, conn_port, "OK");
    close(client_fd);
}
void* client_handler(void *arg) {
    client_conn *conn = (client_conn*)arg;
    int client_fd = conn->fd;
    char client_ip[INET_ADDRSTRLEN];
    int client_port = ntohs(conn->addr.sin_port);
    inet_ntop(AF_INET, &conn->addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    free(conn);

    // Receive first message to determine connection type
    // Storage servers send "REGISTER SS <port>" 
    // Clients send "username|ip|port" or just "username"
    // Storage Servers send "REGISTER SS <ip> <ns_port> <client_port>\nFILE ...\n..." (entire message)
    char first_msg[NS_BUFFER_SIZE_4096];  // Large buffer to hold entire registration + file list
    int n = recv(client_fd, first_msg, sizeof(first_msg)-1, 0);
    if (n <= 0) { close(client_fd); return NULL; }
    first_msg[n] = 0;
    
    // Extract first line for protocol detection (but keep full buffer for file list parsing)
    char first_line[NS_FIRST_MSG_SIZE];
    strncpy(first_line, first_msg, sizeof(first_line) - 1);
    first_line[sizeof(first_line) - 1] = '\0';
    first_line[strcspn(first_line, "\n")] = 0;
    
    if (strncasecmp(first_line, PROTOCOL_REGISTER_SS, PROTOCOL_REGISTER_SS_LEN) == 0) {
        handle_storage_server_registration(client_fd, first_msg, first_line, client_ip);
        return NULL;
    }
    
    // Delegate client handling to the helper to keep client_handler concise
    handle_user_client(client_fd, first_msg, client_ip, client_port);
    return NULL;
}

