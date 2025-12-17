/**
 * ============================================================================
 * exec_handler_ss.c - Storage Server EXEC Command Handler
 * ============================================================================
 * 
 * PURPOSE:
 * This module handles EXEC requests completely separately from READ.
 * It reads the file structure directly and returns commands (one per sentence)
 * for execution on the Name Server.
 * 
 * ARCHITECTURE:
 * - Reads file structure directly (bypasses READ)
 * - Each sentence becomes one command
 * - Returns commands separated by newlines
 * - Completely isolated from other file operations
 * 
 * ============================================================================
 */

#include "storage_server.h"
#include <string.h>
#include <time.h>

// Forward declarations
extern void log_request_ss(const char *op, const char *user, const char *ip, int port, const char *details);
extern void log_response_ss(const char *op, const char *user, const char *ip, int port, const char *status);
extern void update_last_access(const char *username, file *f);

/**
 * Handle EXEC command - Get file content formatted for execution
 * 
 * WHAT: Reads file structure directly and returns commands (one per sentence)
 * WHERE: Called from client_connection_handler when CMD_EXEC is received
 * WHY: Completely separate from READ to avoid interfering with other operations
 * 
 * SPECIFICATION:
 * - Each sentence in the file becomes one command
 * - Commands are separated by newlines
 * - Access control is enforced (read access required)
 * - Returns content formatted for shell execution
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename and username
 * @param username - Username of the requesting client
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_exec_command_ss(int client_fd, Packet *p, const char *username, 
                            const char *client_ip, int client_port, const char *op_name)
{
    // Trim filename
    char trimmed_filename[FILE_NAME_SIZE];
    strncpy(trimmed_filename, p->filename, sizeof(trimmed_filename) - 1);
    trimmed_filename[sizeof(trimmed_filename) - 1] = '\0';
    size_t len = strlen(trimmed_filename);
    while (len > 0 && (trimmed_filename[len-1] == ' ' || trimmed_filename[len-1] == '\t' || 
                       trimmed_filename[len-1] == '\n' || trimmed_filename[len-1] == '\r')) {
        trimmed_filename[--len] = '\0';
    }
    
    // Get file structure directly from hash table or disk
    extern struct hsearch_data *name_to_ptr;
    extern void *in_htable(const char *filename, struct hsearch_data *htab);
    extern file *file_to_struct(const char *filepath);
    extern bool check_access(const char *user, file *f, int access_type);
    
    file *f = (file *)in_htable(trimmed_filename, name_to_ptr);
    if (f == NULL) {
        // File not in memory, load from disk
        char filepath[FILEPATH_SIZE];
        snprintf(filepath, sizeof(filepath), STORAGE_DIRECTORY "/%s", trimmed_filename);
        f = file_to_struct(filepath);
        if (f == NULL) {
            dprintf(client_fd, "[SS] ERROR: File not found. Error code: %d - %s\n", 
                    ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
            send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
            log_response_ss(op_name, username, client_ip, client_port, "FAILED: File not found");
            return;
        }
        add_struct_to_htable(f, name_to_ptr);
    }
    
    // Enforce read access control
    if (strcmp(f->info->owner, username) != 0 && !check_access(username, f, ACCESS_READ)) {
        dprintf(client_fd, "[SS] ERROR: Read access denied. Error code: %d - %s\n", 
                ERR_READ_ACCESS_DENIED, get_error_message(ERR_READ_ACCESS_DENIED));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Access denied");
        return;
    }
    
    // Update last access time
    update_last_access(username, f);
    
    // Read file structure and convert each sentence to a command
    // Allocate buffer for commands
    char *buffer = calloc(1, 8192);
    if (buffer == NULL) {
        dprintf(client_fd, "[SS] ERROR: Memory allocation failed. Error code: %d - %s\n", 
                ERR_MEMORY_ALLOCATION_FAILED, get_error_message(ERR_MEMORY_ALLOCATION_FAILED));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Memory error");
        return;
    }
    
    // Lock file for reading (concurrency control)
    pthread_mutex_lock(&f->mutex);
    f->readcount++;
    if (f->readcount == 1 && f->writecount == 0) {
        // Lock all sentences for reading
        for (node_t *current = f->data->head; current != NULL; current = current->next) {
            sentence *s = (sentence *)current->data;
            if (s) {
                pthread_mutex_lock(&s->wrt);
            }
        }
    } else {
        f->readcount--;
        pthread_mutex_unlock(&f->mutex);
        free(buffer);
        dprintf(client_fd, "[SS] ERROR: File is being written. Error code: %d - %s\n", 
                ERR_FILE_IS_BEING_WRITTEN, get_error_message(ERR_FILE_IS_BEING_WRITTEN));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: File locked");
        return;
    }
    pthread_mutex_unlock(&f->mutex);
    
    // Process each sentence and convert to command
    int sentence_num = 0;
    for (node_t *current = f->data->head; current != NULL; current = current->next) {
        sentence *s = (sentence *)current->data;
        if (s == NULL || s->data == NULL) {
            continue; // Skip NULL sentences
        }
        
        sentence_num++;
        fprintf(stderr, "[SS DEBUG] Processing sentence %d (size=%zu):\n", sentence_num, s->data ? s->data->size : 0);
        
        // Debug: Print all words in this sentence
        int word_num = 0;
        for (node_t *word = s->data->head; word != NULL; word = word->next) {
            char *word_str = (char *)word->data;
            if (word_str != NULL) {
                fprintf(stderr, "[SS DEBUG]   Word %d: '%s'\n", word_num++, word_str);
            }
        }
        
        // Skip empty sentences
        if (s->data->size == 0) {
            fprintf(stderr, "[SS DEBUG]   Skipping empty sentence %d\n", sentence_num);
            continue;
        }
        
        // Build command from sentence words
        bool first_word = true;
        char temp_cmd[1024] = {0};  // Temporary buffer to build command for debug
        for (node_t *word = s->data->head; word != NULL; word = word->next) {
            char *word_str = (char *)word->data;
            if (word_str != NULL && strlen(word_str) > 0) {
                if (!first_word) {
                    strcat(buffer, " ");
                    strcat(temp_cmd, " ");
                }
                strcat(buffer, word_str);
                strcat(temp_cmd, word_str);
                first_word = false;
            }
        }
        
        // Add newline after each sentence (command)
        if (!first_word) {
            fprintf(stderr, "[SS DEBUG]   Sentence %d command: '%s'\n", sentence_num, temp_cmd);
            strcat(buffer, "\n");
        }
    }
    
    fprintf(stderr, "[SS DEBUG] Total sentences processed: %d\n", sentence_num);
    
    // Unlock file
    pthread_mutex_lock(&f->mutex);
    if (f->readcount == 1 && f->writecount == 0) {
        for (node_t *current = f->data->head; current != NULL; current = current->next) {
            sentence *s = (sentence *)current->data;
            if (s) {
                pthread_mutex_unlock(&s->wrt);
            }
        }
    }
    f->readcount--;
    pthread_mutex_unlock(&f->mutex);
    
    // Send commands to client (one per line)
    // Debug: print what we're sending
    fprintf(stderr, "[SS DEBUG] EXEC: Sending %zu bytes, content:\n%s\n", strlen(buffer), buffer);
    
    if (strlen(buffer) > 0) {
        dprintf(client_fd, "%s", buffer);
    }
    free(buffer);
    
    send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
    log_response_ss(op_name, username, client_ip, client_port, "OK");
}

