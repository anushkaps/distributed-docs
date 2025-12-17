/**
 * ============================================================================
 * command_handlers_ss.c - Storage Server Command Handlers
 * ============================================================================
 * 
 * PURPOSE:
 * This module contains the individual command handlers for all file operations
 * that the Storage Server supports. Each handler processes a specific command
 * type (READ, WRITE, CREATE, DELETE, etc.) and enforces access control.
 * 
 * ARCHITECTURE:
 * - Each handler function processes one command type
 * - All handlers enforce access control before performing operations
 * - Handlers update file metadata (timestamps, last modified by, etc.)
 * - Handlers send appropriate responses back to clients
 * 
 * ACCESS CONTROL:
 * - Owner always has both read and write access
 * - Other users need explicit access permissions
 * - Access is checked using check_access() before operations
 * 
 * ============================================================================
 */

#include "storage_server.h"
#include <unistd.h>
#include <string.h>
#include <time.h>

// Forward declarations for logging functions
extern void log_request_ss(const char *op, const char *user, const char *ip, int port, const char *details);
extern void log_response_ss(const char *op, const char *user, const char *ip, int port, const char *status);
extern void log_file_operation_ss(const char *event_type, const char *filename, const char *user, const char *details);

/**
 * Handle READ command - Retrieve complete file content
 * 
 * WHAT: Reads and sends the entire file content to the client
 * WHERE: Called from client_connection_handler when CMD_READ is received
 * WHY: Allows users to view file contents they have read access to
 * 
 * SPECIFICATION:
 * - Users can retrieve contents of files they have read access to
 * - Owner always has read access
 * - File content is sent until "STOP" packet is sent
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename and username
 * @param username - Username of the requesting client
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_read_command(int client_fd, Packet *p, const char *username, 
                         const char *client_ip, int client_port, const char *op_name)
{
    // Trim filename to remove any trailing whitespace
    char trimmed_filename[FILE_NAME_SIZE];
    strncpy(trimmed_filename, p->filename, sizeof(trimmed_filename) - 1);
    trimmed_filename[sizeof(trimmed_filename) - 1] = '\0';
    size_t len = strlen(trimmed_filename);
    while (len > 0 && (trimmed_filename[len-1] == ' ' || trimmed_filename[len-1] == '\t' || 
                       trimmed_filename[len-1] == '\n' || trimmed_filename[len-1] == '\r')) {
        trimmed_filename[--len] = '\0';
    }
    
    // Check if this is an EXEC request (filename ends with "|EXEC")
    int is_exec_request = 0;
    if (len >= 5 && strcmp(trimmed_filename + len - 5, "|EXEC") == 0) {
        // Remove the marker for file lookup
        trimmed_filename[len - 5] = '\0';
        is_exec_request = 1;
    }
    
    // Look up file in hash table for O(1) access
    file *f = in_htable(trimmed_filename, name_to_ptr);
    if (!f) {
        dprintf(client_fd, "[SS] ERROR: File not found. Error code: %d - %s\n", 
                ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: File not found");
        return;
    }
    
    // Enforce access control: owner always has access, others need read permission
    // This ensures only authorized users can read files
    if (strcmp(f->info->owner, username) != 0 && !check_access(username, f, ACCESS_READ)) {
        dprintf(client_fd, "[SS] ERROR: Read access denied. Error code: %d - %s\n", 
                ERR_READ_ACCESS_DENIED, get_error_message(ERR_READ_ACCESS_DENIED));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Access denied");
        return;
    }
    
    // Update last access time for this user
    // This tracks when users last accessed the file
    update_last_access(username, f);
    
    // Read file content from disk/structure
    // For EXEC: Use read_file_for_exec to get content with newlines between sentences
    char *res = NULL;
    if (is_exec_request) {
        res = read_file_for_exec(trimmed_filename, name_to_ptr);
    } else {
        res = read_file(trimmed_filename, name_to_ptr);
    }
    
    if (res) {
        // Send file content to client
        // For EXEC requests, content already has newlines between sentences
        // For regular READ, content has spaces between sentences
        // Send content as-is (without adding extra newline for EXEC, but keep it for regular READ for compatibility)
        if (is_exec_request) {
            // For EXEC: send content directly (already has newlines between sentences)
            dprintf(client_fd, "%s", res);
        } else {
            // For regular READ: add newline at end (for compatibility with existing clients)
            dprintf(client_fd, "%s\n", res);
        }
        free(res);
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "OK");
    } else {
        dprintf(client_fd, "[SS] ERROR: File read failed. Error code: %d - %s\n", 
                ERR_FILE_READ_FAILED, get_error_message(ERR_FILE_READ_FAILED));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Read error");
    }
}

/**
 * Handle CREATE command - Create a new empty file
 * 
 * WHAT: Creates a new file structure and adds it to the system
 * WHERE: Called from client_connection_handler when CMD_CREATE is received
 * WHY: Allows users to create new files, with creator becoming the owner
 * 
 * SPECIFICATION:
 * - Users can create new files
 * - Creator becomes the file owner
 * - Owner always has both read and write access
 * - File must not already exist
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename and username
 * @param username - Username of the creating client (becomes owner)
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_create_command(int client_fd, Packet *p, const char *username,
                           const char *client_ip, int client_port, const char *op_name)
{
    // Trim filename to remove any trailing whitespace
    // This ensures consistent lookup in the hash table
    char trimmed_filename[FILE_NAME_SIZE];
    strncpy(trimmed_filename, p->filename, sizeof(trimmed_filename) - 1);
    trimmed_filename[sizeof(trimmed_filename) - 1] = '\0';
    size_t len = strlen(trimmed_filename);
    while (len > 0 && (trimmed_filename[len-1] == ' ' || trimmed_filename[len-1] == '\t' || 
                       trimmed_filename[len-1] == '\n' || trimmed_filename[len-1] == '\r')) {
        trimmed_filename[--len] = '\0';
    }
    
    // Check if file already exists to prevent duplicates
    file *existing = in_htable(trimmed_filename, name_to_ptr);
    if (existing) {
        dprintf(client_fd, "[SS] ERROR: File already exists. Error code: %d - %s\n", 
                ERR_FILE_ALREADY_EXISTS, get_error_message(ERR_FILE_ALREADY_EXISTS));
        send(client_fd, "[SS] ACK: CREATE failed - File already exists.\n", 49, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: File exists");
        return;
    }
    
    // Also check file_list for any stale entries with same filename (cleanup duplicates)
    node_t *current = file_list.head;
    size_t idx = 0;
    while (current) {
        file *f_in_list = (file *)current->data;
        if (f_in_list && f_in_list->info && strcmp(f_in_list->info->filename, trimmed_filename) == 0) {
            // Found duplicate entry - remove it
            node_t *next = current->next;
            remove_at_n(&file_list, idx);
            // Free the stale file structure
            free_file(f_in_list);
            current = next;
            // Don't increment idx since we removed an element
            continue;
        }
        current = current->next;
        idx++;
    }

    // Create new file structure
    // This allocates memory and initializes all file metadata
    file *f = create_file_struct(trimmed_filename);
    if (f) {
        // Set creator as owner and last modifier
        // Owner always has both read and write access
        strcpy(f->info->owner, username);
        strcpy(f->info->lastmodifiedby, username);
        
        // Add owner to access list with write access
        // Write access automatically grants read access too
        add_access(username, f, ACCESS_WRITE);
        
        // Add file to global file list and hash table
        // Hash table enables O(1) file lookups by name
        insert_at_n(&file_list, f, file_list.size);
        
        // DEBUG: Print what we're adding
        fprintf(stderr, "[SS DEBUG] CREATE: Adding file '%s' (len=%zu) to hash table\n", f->info->filename, strlen(f->info->filename));
        
        if (add_struct_to_htable(f, name_to_ptr) != 0) {
            dprintf(client_fd, "[SS] CREATE failed: Could not add file to hash table.\n");
            send(client_fd, "[SS] ACK: CREATE failed - Hash table error.\n", 42, 0);
            log_response_ss(op_name, username, client_ip, client_port, "FAILED: Hash table error");
            return;
        }
        
        // DEBUG: Verify it was added
        file *verify = in_htable(f->info->filename, name_to_ptr);
        if (verify) {
            fprintf(stderr, "[SS DEBUG] CREATE: Verified file '%s' is in hash table\n", f->info->filename);
        } else {
            fprintf(stderr, "[SS DEBUG] CREATE: ERROR - File '%s' NOT found in hash table after adding!\n", f->info->filename);
        }
        
        // Save file to disk for persistence (without removing from hash table or freeing)
        // This ensures the file exists on disk and can be loaded on restart
        if (save_file_to_disk(f) != 0) {
            dprintf(client_fd, "[SS] Warning: File created but could not save to disk.\n");
            // Continue anyway - file is in memory and hash table
        }
        
        dprintf(client_fd, "[SS] File created.\n");
        // Send ACK back to NS (which relays to client)
        // CREATE operations are forwarded by NS, so we send ACK
        send(client_fd, "[SS] ACK: File created successfully.\n", 38, 0);
        log_response_ss(op_name, username, client_ip, client_port, "OK");
    } else {
        dprintf(client_fd, "[SS] CREATE failed.\n");
        send(client_fd, "[SS] ACK: CREATE failed.\n", 26, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED");
    }
}

/**
 * Helper function to calculate word and character counts from file structure
 * Used to update metadata after WRITE operations
 */
static void update_file_counts(file *f) {
    if (!f || !f->data) return;
    
    size_t word_count = 0;
    size_t char_count = 0;
    
    // Iterate through all sentences
    for (node_t *sent_node = f->data->head; sent_node != NULL; sent_node = sent_node->next) {
        sentence *s = (sentence *)sent_node->data;
        if (s && s->data) {
            // Count words in this sentence
            bool first_word = true;
            for (node_t *word_node = s->data->head; word_node != NULL; word_node = word_node->next) {
                char *word = (char *)word_node->data;
                if (word) {
                    word_count++;
                    char_count += strlen(word);
                    // Add 1 for space between words (not before first word, not after last word)
                    if (!first_word) {
                        char_count++;
                    }
                    first_word = false;
                }
            }
            // Add 1 for sentence delimiter (if sentence has words)
            if (s->data->size > 0) {
                char_count++; // For delimiter (. ! or ?)
            }
        }
    }
    
    if (f->info) {
        f->info->wordcount = word_count;
        f->info->charcount = char_count;
    }
}

/**
 * Handle WRITE command - Update file content at word level with per-sentence locking
 * 
 * WHAT: Processes word-level updates to a sentence in a file
 * WHERE: Called from client_connection_handler when CMD_WRITE is received
 * WHY: Allows users to edit files at granular word level within sentences
 * 
 * SPECIFICATION:
 * - Users can update content at word level within a sentence
 * - Sentence is locked at WRITE start and held until ETIRW (prevents concurrent edits)
 * - Multiple words can be updated in a single WRITE operation
 * - All updates are queued and applied as ONE operation when ETIRW is received
 * - Content may contain sentence delimiters (. ! ?) which create new sentences
 * - After WRITE completion, sentence indices update and metadata is refreshed
 * - Protocol: First packet has sentence_index, then word updates, finally "ETIRW"
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename, sentence_index, and username
 * @param username - Username of the writing client
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_write_command(int client_fd, Packet *p, const char *username,
                          const char *client_ip, int client_port, const char *op_name,
                          thread_lock_manager_t *lock_manager)
{
    // Extract sentence index from first packet
    int sentence_index = p->flag1;

    // Look up file and verify it exists
    char trimmed_filename[FILE_NAME_SIZE];
    strncpy(trimmed_filename, p->filename, sizeof(trimmed_filename) - 1);
    trimmed_filename[sizeof(trimmed_filename) - 1] = '\0';
    // Remove trailing whitespace
    size_t len = strlen(trimmed_filename);
    while (len > 0 && (trimmed_filename[len-1] == ' ' || trimmed_filename[len-1] == '\t' || 
                       trimmed_filename[len-1] == '\n' || trimmed_filename[len-1] == '\r')) {
        trimmed_filename[--len] = '\0';
    }
    
    file *f = in_htable(trimmed_filename, name_to_ptr);
    if (!f) {
        // Try searching in file_list as fallback
        file *found = NULL;
            for (node_t *current = file_list.head; current != NULL; current = current->next) {
            file *check = (file *)current->data;
            if (check && check->info && strcmp(check->info->filename, trimmed_filename) == 0) {
                found = check;
                break;
            }
        }
        
        if (found) {
            add_struct_to_htable(found, name_to_ptr);
            f = found; 
        } else {
            dprintf(client_fd, "[SS] ERROR: File not found. Error code: %d - %s\n", 
                ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
            send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
            log_response_ss(op_name, username, client_ip, client_port, "FAILED: File not found");
        
            // Consume remaining packets until ETIRW
            int n;
            while ((n = recv(client_fd, p, sizeof(*p), 0)) > 0) {
                if (p->opcode == CMD_WRITE && strcmp(p->payload, PROTOCOL_ETIRW) == 0) 
                    break;
            }
            return;
        }
    }
    
    // Update filename in packet
    strncpy(p->filename, trimmed_filename, sizeof(p->filename) - 1);
    p->filename[sizeof(p->filename) - 1] = '\0';

    // Enforce write access control
    if (strcmp(f->info->owner, username) != 0 && !check_access(username, f, ACCESS_WRITE)) {
        dprintf(client_fd, "[SS] ERROR: Write access denied. Error code: %d - %s\n", 
                ERR_WRITE_ACCESS_DENIED, get_error_message(ERR_WRITE_ACCESS_DENIED));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Access denied");
        
        // Consume remaining packets until ETIRW
        int n;
        while ((n = recv(client_fd, p, sizeof(*p), 0)) > 0) {
            if (p->opcode == CMD_WRITE && strcmp(p->payload, PROTOCOL_ETIRW) == 0) 
                break;
        }
        return;
    }

    // Validate sentence index BEFORE locking
    // sentence_index must be >= 0 and can be up to sentence_count (to create new sentence)
    // But if sentence_index > sentence_count, it's out of bounds (can't skip sentences)
    size_t sentence_count = f->data ? f->data->size : 0;
    if (sentence_index < 0) {
        dprintf(client_fd, "[SS] ERROR: Invalid sentence index: %d (must be >= 0). Error code: %d - %s\n", 
                sentence_index, ERR_SENTENCE_INDEX_NEGATIVE, get_error_message(ERR_SENTENCE_INDEX_NEGATIVE));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Invalid sentence index");
        
        // Consume remaining packets until ETIRW
        int n;
        while ((n = recv(client_fd, p, sizeof(*p), 0)) > 0) {
            if (p->opcode == CMD_WRITE && strcmp(p->payload, PROTOCOL_ETIRW) == 0) 
                break;
        }
        return;
    }
    
    // Reject if sentence_index is too far beyond existing sentences
    // Allow sentence_index == sentence_count to create a new sentence at the end
    // But reject if sentence_index > sentence_count (can't skip sentences)
    if (sentence_index > (int)sentence_count) {
        dprintf(client_fd, "[SS] ERROR: Sentence index out of range: %d (file has %zu sentences, max valid: %zu). Error code: %d - %s\n", 
                sentence_index, sentence_count, sentence_count, ERR_SENTENCE_INDEX_OUT_OF_RANGE, 
                get_error_message(ERR_SENTENCE_INDEX_OUT_OF_RANGE));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Sentence index out of range");
        
        // Consume remaining packets until ETIRW
        int n;
        while ((n = recv(client_fd, p, sizeof(*p), 0)) > 0) {
            if (p->opcode == CMD_WRITE && strcmp(p->payload, PROTOCOL_ETIRW) == 0) 
                break;
        }
        return;
    }

    // Get or create the target sentence
    // Create sentences if needed (up to sentence_index)
    // First, navigate to the current end of the sentence list
    node_t *sentence_node = f->data->head;
    int current_count = 0;
    while (sentence_node != NULL && current_count < sentence_index) {
        sentence_node = sentence_node->next;
        current_count++;
    }
    
    // Create sentences if needed (only if sentence_index == sentence_count, to append)
    // If sentence_index < sentence_count, the sentence already exists
    while (current_count <= sentence_index) {
        sentence *new_s = (sentence *)malloc(sizeof(sentence));
        if (!new_s) {
            dprintf(client_fd, "[SS] ERROR: Failed to allocate memory for sentence. Error code: %d - %s\n", 
                    ERR_MEMORY_ALLOCATION_FAILED, get_error_message(ERR_MEMORY_ALLOCATION_FAILED));
            send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
            log_response_ss(op_name, username, client_ip, client_port, "FAILED: Memory error");
            return;
        }
        pthread_mutex_init(&new_s->wrt, NULL);
        new_s->data = (linkedlist_t *)malloc(sizeof(linkedlist_t));
        if (!new_s->data) {
            free(new_s);
            dprintf(client_fd, "[SS] ERROR: Failed to allocate memory for sentence data. Error code: %d - %s\n", 
                    ERR_MEMORY_ALLOCATION_FAILED, get_error_message(ERR_MEMORY_ALLOCATION_FAILED));
            send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
            log_response_ss(op_name, username, client_ip, client_port, "FAILED: Memory error");
            return;
        }
        init_linkedlist(new_s->data);
        insert_at_n(f->data, new_s, f->data->size);
        current_count++;
    }
    
    // Get the sentence node (should exist now) - re-traverse to get correct node
    sentence_node = f->data->head;
    for (int j = 0; j < sentence_index && sentence_node != NULL; j++) {
        sentence_node = sentence_node->next;
    }
    
    if (!sentence_node) {
        dprintf(client_fd, "[SS] ERROR: Internal error - sentence node is NULL. Error code: %d - %s\n", 
                ERR_INTERNAL_ERROR, get_error_message(ERR_INTERNAL_ERROR));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Internal error");
        return;
    }
    
    sentence *target_sentence = (sentence *)sentence_node->data;
    if (!target_sentence || !target_sentence->data) {
        dprintf(client_fd, "[SS] ERROR: Internal error - sentence structure is NULL. Error code: %d - %s\n", 
                ERR_INTERNAL_ERROR, get_error_message(ERR_INTERNAL_ERROR));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Internal error");
        return;
    }

    // LOCK THE SENTENCE: Try to acquire lock (non-blocking)
    // Specification: Sentence is locked during write operation to prevent concurrent edits
    pthread_mutex_lock(&f->mutex);
    if (pthread_mutex_trylock(&target_sentence->wrt) != 0) {
        // Sentence is already locked by another client
        pthread_mutex_unlock(&f->mutex);
        dprintf(client_fd, "[SS] ERROR: Sentence %d is locked by another user. Error code: %d - %s\n", 
                sentence_index, ERR_SENTENCE_LOCKED, get_error_message(ERR_SENTENCE_LOCKED));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Sentence locked");
        
        // Log lock failure
        char lock_details[256];
        snprintf(lock_details, sizeof(lock_details), "Sentence %d locked by another user", sentence_index);
        log_file_operation_ss("LOCK_FAILED", p->filename, username, lock_details);
        
        // Consume remaining packets until ETIRW
        int n;
        while ((n = recv(client_fd, p, sizeof(*p), 0)) > 0) {
            if (p->opcode == CMD_WRITE && strcmp(p->payload, PROTOCOL_ETIRW) == 0) 
                break;
        }
        return;
    }
    pthread_mutex_unlock(&f->mutex);
    
    // Add the locked sentence to the manager
    insert_at_n(lock_manager->held_sentence_locks, target_sentence, lock_manager->held_sentence_locks->size);

    // Lock acquired successfully - sentence is now locked for this WRITE operation
    // Will be unlocked when ETIRW is received
    // Log successful lock acquisition
    char lock_details[256];
    snprintf(lock_details, sizeof(lock_details), "Sentence %d locked for WRITE", sentence_index);
    log_file_operation_ss("LOCK", p->filename, username, lock_details);

    // Save undo state BEFORE making any changes
    // Specification: All updates in this WRITE are considered one operation for UNDO
    save_undo_state(p->filename);

    // Queue to collect all word updates before applying them
    // Specification: All updates are applied as ONE operation when ETIRW is received
    linkedlist_t *updates_queue = (linkedlist_t *)malloc(sizeof(linkedlist_t));
    if (!updates_queue) {
        pthread_mutex_unlock(&target_sentence->wrt);
            dprintf(client_fd, "[SS] ERROR: Failed to allocate memory for updates queue. Error code: %d - %s\n", 
                    ERR_MEMORY_ALLOCATION_FAILED, get_error_message(ERR_MEMORY_ALLOCATION_FAILED));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Memory error");
        return;
    }
    init_linkedlist(updates_queue);

    // Read word updates until ETIRW signal
    // WRITE protocol: First packet has sentence_index, then word updates, finally "ETIRW"
    int n;
    bool has_error = false;
    while ((n = recv(client_fd, p, sizeof(*p), 0)) > 0) {
        if (p->opcode != CMD_WRITE)
            break;
        
        // Check for end-of-write signal
        if (strcmp(p->payload, PROTOCOL_ETIRW) == 0) {
            break; // End of write operation - will apply all queued updates
        }
        
        // Queue this word update (word_index in flag2, content in payload)
        word_update_t *update = (word_update_t *)malloc(sizeof(word_update_t));
        if (!update) {
            has_error = true;
            break;
        }
        update->word_index = p->flag2;
        update->content = strdup(p->payload);
        if (!update->content) {
            free(update);
            has_error = true;
            break;
        }
        insert_at_n(updates_queue, update, updates_queue->size);
    }
    
    // Apply all queued updates as ONE operation
    // Specification: All updates in a single WRITE are considered one operation
    if (!has_error && updates_queue->size > 0) {
        // Apply all updates with delimiter detection and sentence splitting
        // This function handles: splitting content by spaces, detecting delimiters (. ! ?),
        // creating new sentences when delimiters are found, and inserting words
        int result = apply_queued_updates(f, sentence_index, updates_queue);
        
        if (result != 0) {
            has_error = true;
        }
    }
    
    // Free updates queue properly
    // Strategy: Free data first, then nodes, then structure
    // Critical: Save next pointer before freeing data to prevent accessing freed memory
    if (updates_queue) {
        // Step 1: Free all data (word_update_t structures and their content strings)
        // We iterate through nodes and free the data, but keep the node structure intact
        node_t *update_node = updates_queue->head;
        while (update_node) {
            word_update_t *update = (word_update_t *)update_node->data;
            if (update) {
                if (update->content) {
                    free(update->content);
                    update->content = NULL;
                }
                free(update);
                update = NULL;
            }
            // Clear data pointer to prevent double-free
            update_node->data = NULL;
            // Move to next node (safe because we haven't freed the node yet)
            update_node = update_node->next;
        }
        
        // Step 2: Free all nodes using remove_all
        // This is safe because we've already freed the data and cleared data pointers
        remove_all(updates_queue);
        
        // Step 3: Free the linkedlist structure itself
        free(updates_queue);
        updates_queue = NULL;
    }
    
    // Remove the sentence from the lock manager before unlocking
    node_t *current = lock_manager->held_sentence_locks->head;
    size_t idx = 0;
    while (current) {
        if (current->data == target_sentence) {
            remove_at_n(lock_manager->held_sentence_locks, idx);
            break;
        }
        current = current->next;
        idx++;
    }

    // UNLOCK THE SENTENCE: Release lock after all updates are applied
    pthread_mutex_unlock(&target_sentence->wrt);
    
    // Log unlock operation
    char unlock_details[256];
    snprintf(unlock_details, sizeof(unlock_details), "Sentence %d unlocked after WRITE", sentence_index);
    log_file_operation_ss("UNLOCK", p->filename, username, unlock_details);
    
    if (has_error) {
        dprintf(client_fd, "[SS] WRITE completed with errors. Some updates may not have been applied.\n");
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Write errors");
        return;
    }
    
    // Update file metadata AFTER all updates are applied
    // Specification: Metadata (word count, char count, timestamps) updated after WRITE completes
    strcpy(f->info->lastmodifiedby, username);
    f->info->modified = time(NULL);
    f->info->last_accessed = time(NULL);
    update_last_access(username, f);
    update_file_counts(f);  // Recalculate word and character counts
    
    // Persist changes to disk (without removing from hash table or freeing)
    save_file_to_disk(f);
    
    dprintf(client_fd, "Write Successful!\n");
    send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
    log_response_ss(op_name, username, client_ip, client_port, "OK");
}

/**
 * Handle UNDO command - Revert the last change made to a file
 * 
 * WHAT: Reverts the most recent change to a file
 * WHERE: Called from client_connection_handler when CMD_UNDO is received
 * WHY: Allows users to undo mistakes or revert unwanted changes
 * 
 * SPECIFICATION:
 * - Users can revert last changes made to a file
 * - Undo is file-specific, not user-specific (any user can undo any user's change)
 * - Only one undo operation is supported (most recent change)
 * - Undo history is maintained by storage server
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename
 * @param username - Username of the requesting client
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_undo_command(int client_fd, Packet *p, const char *username,
                         const char *client_ip, int client_port, const char *op_name)
{
    // Look up file and verify write access
    // Specification: Users need write access to undo changes
    file *f = in_htable(p->filename, name_to_ptr);
    if (!f) {
        dprintf(client_fd, "[SS] ERROR: File not found. Error code: %d - %s\n", 
                ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: File not found");
        return;
    }
    
    // Enforce write access control
    if (strcmp(f->info->owner, username) != 0 && !check_access(username, f, ACCESS_WRITE)) {
        dprintf(client_fd, "[SS] ERROR: Write access denied. Error code: %d - %s\n", 
                ERR_WRITE_ACCESS_DENIED, get_error_message(ERR_WRITE_ACCESS_DENIED));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Access denied");
        return;
    }
    
    // CRITICAL: Check if file exists before attempting undo
    // If file was deleted, undo should fail gracefully
    file *f_check = in_htable(p->filename, name_to_ptr);
    if (!f_check) {
        // File doesn't exist - check if it exists on disk
        char filepath[FILEPATH_SIZE];
        snprintf(filepath, sizeof(filepath), STORAGE_DIRECTORY "/%s", p->filename);
        FILE *test_file = fopen(filepath, "r");
        if (!test_file) {
            // File doesn't exist - cannot undo
            dprintf(client_fd, "[SS] ERROR: Cannot undo - file does not exist. Error code: %d - %s\n", 
                    ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
            send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
            log_response_ss(op_name, username, client_ip, client_port, "FAILED: File not found");
            log_file_operation_ss("UNDO_FAILED", p->filename, username, "File does not exist");
            return;
        }
        fclose(test_file);
    }
    
    // Call undo function which handles the actual reversion
    // undo_last_change() maintains the undo history and reverts the file
    int res = undo_last_change(p->filename);
    if (res == 0) {
        dprintf(client_fd, "Undo Successful!\n");
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "OK");
        // Log undo operation
        log_file_operation_ss("UNDO", p->filename, username, "File reverted to previous state");
    } else {
        dprintf(client_fd, "[SS] ERROR: No previous version available. Error code: %d - %s\n", 
                ERR_NO_UNDO_HISTORY, get_error_message(ERR_NO_UNDO_HISTORY));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: No undo state");
        // Log undo failure
        log_file_operation_ss("UNDO_FAILED", p->filename, username, "No previous version available");
    }
}

/**
 * Handle INFO command - Get file metadata
 * 
 * WHAT: Retrieves and displays detailed file information
 * WHERE: Called from client_connection_handler when CMD_INFO is received
 * WHY: Provides users with comprehensive file metadata
 * 
 * SPECIFICATION:
 * - Display file details including owner, size, access rights, timestamps
 * - Users need read access to view file info
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename
 * @param username - Username of the requesting client
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_info_command(int client_fd, Packet *p, const char *username,
                         const char *client_ip, int client_port, const char *op_name)
{
    // Look up file
    file *f = in_htable(p->filename, name_to_ptr);
    if (!f) {
        dprintf(client_fd, "[SS] File not found.\n");
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: File not found");
        return;
    }

    // Enforce access control - need read access to view file info
    if (strcmp(f->info->owner, username) != 0 && !check_access(username, f, ACCESS_READ)) {
        dprintf(client_fd, "[SS] INFO failed: Access denied.\n");
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Access denied");
        return;
    }

    // Print detailed file information
    // Includes owner, size, timestamps, access rights, etc.
    printf_additional_file_info(client_fd, f);
    dprintf(client_fd, "[SS] INFO printed.\n");
    log_response_ss(op_name, username, client_ip, client_port, "OK");
}

/**
 * Handle DELETE command - Remove file from system
 * 
 * WHAT: Deletes a file and removes it from all data structures
 * WHERE: Called from client_connection_handler when CMD_DELETE is received
 * WHY: Allows file owners to remove files they no longer need
 * 
 * SPECIFICATION:
 * - Only file owner can delete files
 * - All data including user access lists should be updated accordingly
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename
 * @param username - Username of the requesting client
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_delete_command(int client_fd, Packet *p, const char *username,
                           const char *client_ip, int client_port, const char *op_name)
{
    // Look up file and verify ownership
    file *f = in_htable(p->filename, name_to_ptr);
    if (!f) {
        // File not found
        dprintf(client_fd, "[SS] ERROR: File not found. Error code: %d - %s\n", 
                ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
        send(client_fd, "[SS] ACK: DELETE failed - File not found.\n", 42, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: File not found");
    } else if (strcmp(f->info->owner, username) != 0) {
        // Access denied - not owner
        dprintf(client_fd, "[SS] ERROR: Only owner can delete file. Error code: %d - %s\n", 
                ERR_NOT_OWNER, get_error_message(ERR_NOT_OWNER));
        send(client_fd, "[SS] ACK: DELETE failed - Access denied.\n", 42, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Access denied");
    } else {
        // Only owner can delete - delete_file() removes from hash table and frees memory
        delete_file(p->filename);
        dprintf(client_fd, "[SS] DELETE done.\n");
        // Send ACK back to NS (which relays to client)
        send(client_fd, "[SS] ACK: File deleted successfully.\n", 38, 0);
        log_response_ss(op_name, username, client_ip, client_port, "OK");
    }
}

/**
 * Handle STREAM command - Display file content word-by-word with delay
 * 
 * WHAT: Streams file content word-by-word with 0.1s delay between words
 * WHERE: Called from client_connection_handler when CMD_STREAM is received
 * WHY: Simulates streaming effect for dynamic content display
 * 
 * SPECIFICATION:
 * - Client establishes direct connection with SS
 * - SS fetches and displays content word-by-word with 0.1s delay between words
 * - Simulates streaming effect
 * - If SS goes down mid-streaming, appropriate error message should be displayed
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename
 * @param username - Username of the requesting client
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_stream_command(int client_fd, Packet *p, const char *username,
                           const char *client_ip, int client_port, const char *op_name)
{
    // Look up file
    file *f = in_htable(p->filename, name_to_ptr);
    if (!f) {
        dprintf(client_fd, "[SS] STREAM failed: File not found.\n");
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: File not found");
        return;
    }

    // Enforce read access control
    if (strcmp(f->info->owner, username) != 0 && !check_access(username, f, ACCESS_READ)) {
        dprintf(client_fd, "[SS] STREAM failed: Access denied.\n");
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Access denied");
        return;
    }

    // Update last access time for this user
    update_last_access(username, f);

    // Read file content
    char *res = read_file(p->filename, name_to_ptr);
    if (res) {
        // Stream words one by one with 0.1s delay between words
        // Specification: Words are sequences of ASCII characters without spaces
        // We need to preserve sentence structure while streaming word-by-word
        char *content = res;
        char *pos = content;
        
        // Track if we need to send a space before the next word
        int need_space = 0;
        
        while (*pos != '\0') {
            // Skip leading whitespace
            while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r') {
                if (*pos == ' ') {
                    need_space = 1;  // Mark that we need a space before next word
                }
                pos++;
            }
            
            if (*pos == '\0') break;
            
            // Find the end of the current word
            // A word is a sequence of ASCII characters without spaces
            // Sentence delimiters (. ! ?) are part of the word if they're at the end
            char *word_start = pos;
            char *word_end = pos;
            
            // Find word boundary (space, newline, or end of string)
            while (*word_end != '\0' && *word_end != ' ' && *word_end != '\t' && 
                   *word_end != '\n' && *word_end != '\r') {
                word_end++;
            }
            
            if (word_start < word_end) {
                // Send space before word if needed
                if (need_space) {
                    dprintf(client_fd, " ");
            fflush(stdout);
                    need_space = 0;
                }
                
                // Send the word character by character to preserve structure
                // But send it as a single unit for efficiency
                size_t word_len = (size_t)(word_end - word_start);
                char word_buf[BUFFER_SIZE_512];
                if (word_len < sizeof(word_buf) - 1) {
                    strncpy(word_buf, word_start, word_len);
                    word_buf[word_len] = '\0';
                    dprintf(client_fd, "%s", word_buf);
                    fflush(stdout);
                    
                    // 0.1 second delay between words (as per specification)
                    usleep(STREAM_WORD_DELAY_US);
                }
            }
            
            pos = word_end;
        }
        
        // Send newline and completion message
        dprintf(client_fd, "\n");
        fflush(stdout);
        
        free(res);
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "OK");
    } else {
        dprintf(client_fd, "[SS] STREAM failed: Could not read file.\n");
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED");
    }
}

/**
 * Handle ADDACCESS command - Grant access to a user
 * 
 * WHAT: Adds read or write access for a user to a file
 * WHERE: Called from client_connection_handler when CMD_ADDACCESS is received
 * WHY: Allows file owners to share files with other users
 * 
 * SPECIFICATION:
 * - Only owner can add access
 * - Write access automatically grants read access
 * - Access type is specified in flag1 (ACCESS_READ or ACCESS_WRITE)
 * - Username is in payload
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename, access type, and username
 * @param username - Username of the file owner making the request
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_addaccess_command(int client_fd, Packet *p, const char *username,
                              const char *client_ip, int client_port, const char *op_name)
{
    // Look up file and verify ownership
    file *f = in_htable(p->filename, name_to_ptr);
    if (f && strcmp(f->info->owner, username) == 0) {
        // Only owner can add access
        // p->flag1 contains ACCESS_READ or ACCESS_WRITE
        int access_type = (p->flag1 == ACCESS_WRITE) ? ACCESS_WRITE : ACCESS_READ;
        
        // Add access for the user specified in payload
        int res = add_access(p->payload, f, access_type);
        if (res == 0) {
            // Persist ACL changes to disk (without removing from hash table or freeing)
            save_file_to_disk(f);
            dprintf(client_fd, "Access granted successfully!\n");
            send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
            log_response_ss(op_name, username, client_ip, client_port, "OK");
        } else if (res == 1) {
            // User already has access
            dprintf(client_fd, "[SS] ERROR: User already has access. Error code: %d - %s\n",
                    ERR_ACCESS_ALREADY_GRANTED, get_error_message(ERR_ACCESS_ALREADY_GRANTED));
            send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
            log_response_ss(op_name, username, client_ip, client_port, "FAILED: User already has access");
        } else if (res == -2) {
            // User is owner
            dprintf(client_fd, "[SS] ERROR: User is already the owner. Error code: %d - %s\n",
                    ERR_USER_IS_OWNER, get_error_message(ERR_USER_IS_OWNER));
            send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
            log_response_ss(op_name, username, client_ip, client_port, "FAILED: User is owner");
        } else {
            dprintf(client_fd, "[SS] ADDACCESS failed.\n");
            send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
            log_response_ss(op_name, username, client_ip, client_port, "FAILED");
        }
    } else {
        dprintf(client_fd, "[SS] ADDACCESS failed: Not owner or file not found.\n");
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Not owner or not found");
    }
}

/**
 * Handle REMACCESS command - Remove access from a user
 * 
 * WHAT: Removes all access for a user from a file
 * WHERE: Called from client_connection_handler when CMD_REMACCESS is received
 * WHY: Allows file owners to revoke access they previously granted
 * 
 * SPECIFICATION:
 * - Only owner can remove access
 * - Username to remove is in payload
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename and username to remove
 * @param username - Username of the file owner making the request
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_remaccess_command(int client_fd, Packet *p, const char *username,
                              const char *client_ip, int client_port, const char *op_name)
{
    // Look up file and verify ownership
    file *f = in_htable(p->filename, name_to_ptr);
    if (f && strcmp(f->info->owner, username) == 0) {
        // Only owner can remove access
        // Use remove_access() which properly handles user_access structures
        int res = remove_access(p->payload, f);
        if (res == 0) {
            // Persist ACL changes to disk (without removing from hash table or freeing)
            save_file_to_disk(f);
            dprintf(client_fd, "Access removed successfully!\n");
            send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
                log_response_ss(op_name, username, client_ip, client_port, "OK");
        } else {
            dprintf(client_fd, "[SS] REMACCESS failed: Could not remove access.\n");
            send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
            log_response_ss(op_name, username, client_ip, client_port, "FAILED");
        }
    } else {
        dprintf(client_fd, "[SS] REMACCESS failed: Not owner or file not found.\n");
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Not owner or not found");
    }
}

/**
 * Handle CHECKPOINT command - Create a checkpoint for a file
 * 
 * WHAT: Creates a snapshot of the current file state with a given tag
 * WHERE: Called from client_connection_handler when CMD_CHECKPOINT is received
 * WHY: Allows users to save file state at specific points for later reversion
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename and checkpoint name (in payload)
 * @param username - Username creating the checkpoint
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_checkpoint_command(int client_fd, Packet *p, const char *username,
                               const char *client_ip, int client_port, const char *op_name)
{
    // Verify file exists
    file *f = in_htable(p->filename, name_to_ptr);
    if (!f) {
        dprintf(client_fd, "[SS] CHECKPOINT failed: File not found.\n");
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: File not found");
        return;
    }
    
    // Checkpoint name is in payload
    int res = create_checkpoint(p->filename, p->payload, username, name_to_ptr);
    if (res == 0) {
        dprintf(client_fd, "[SS] Checkpoint '%s' created successfully.\n", p->payload);
        log_response_ss(op_name, username, client_ip, client_port, "OK");
    } else {
        dprintf(client_fd, "[SS] CHECKPOINT failed.\n");
        log_response_ss(op_name, username, client_ip, client_port, "FAILED");
    }
}

/**
 * Handle LISTCHECKPOINTS command - List all checkpoints for a file
 * 
 * WHAT: Lists all checkpoints that exist for a file
 * WHERE: Called from client_connection_handler when CMD_LISTCHECKPOINTS is received
 * WHY: Allows users to see available checkpoints before reverting
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename
 * @param username - Username of the requesting client
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_listcheckpoints_command(int client_fd, Packet *p, const char *username,
                                     const char *client_ip, int client_port, const char *op_name)
{
    int res = list_checkpoints(p->filename, client_fd);
    log_response_ss(op_name, username, client_ip, client_port, res == 0 ? "OK" : "FAILED");
}

/**
 * Handle VIEWCHECKPOINT command - View content of a specific checkpoint
 * 
 * WHAT: Displays the content of a checkpoint
 * WHERE: Called from client_connection_handler when CMD_VIEWCHECKPOINT is received
 * WHY: Allows users to preview checkpoint content before reverting
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename and checkpoint name (in payload)
 * @param username - Username of the requesting client
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_viewcheckpoint_command(int client_fd, Packet *p, const char *username,
                                    const char *client_ip, int client_port, const char *op_name)
{
    // Checkpoint name is in payload
    int res = view_checkpoint(p->filename, p->payload, client_fd);
    log_response_ss(op_name, username, client_ip, client_port, res == 0 ? "OK" : "FAILED");
}

/**
 * Handle REVERT command - Revert file to a checkpoint
 * 
 * WHAT: Restores a file to the state saved in a checkpoint
 * WHERE: Called from client_connection_handler when CMD_REVERT is received
 * WHY: Allows users to undo changes by reverting to a previous checkpoint
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename and checkpoint name (in payload)
 * @param username - Username performing the revert
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_revert_command(int client_fd, Packet *p, const char *username,
                           const char *client_ip, int client_port, const char *op_name)
{
    // Checkpoint name is in payload
    int res = revert_to_checkpoint(p->filename, p->payload, username, name_to_ptr);
    if (res == 0) {
        dprintf(client_fd, "[SS] Reverted to checkpoint '%s' successfully.\n", p->payload);
        log_response_ss(op_name, username, client_ip, client_port, "OK");
    } else {
        dprintf(client_fd, "[SS] REVERT failed: Checkpoint not found or access denied.\n");
        log_response_ss(op_name, username, client_ip, client_port, "FAILED");
    }
}

/**
 * Handle REQUESTACCESS command - Request access to a file
 * 
 * WHAT: Creates an access request for a file
 * WHERE: Called from client_connection_handler when CMD_REQUESTACCESS is received
 * WHY: Allows users to request access to files they don't own
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename and access type (in flag1)
 * @param username - Username requesting access
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_requestaccess_command(int client_fd, Packet *p, const char *username,
                                   const char *client_ip, int client_port, const char *op_name)
{
    // Access type in flag1, filename in p->filename
    int res = request_access(p->filename, username, p->flag1);
    if (res == 0) {
        dprintf(client_fd, "[SS] Access request sent successfully.\n");
        log_response_ss(op_name, username, client_ip, client_port, "OK");
    } else {
        dprintf(client_fd, "[SS] REQUESTACCESS failed.\n");
        log_response_ss(op_name, username, client_ip, client_port, "FAILED");
    }
}

/**
 * Handle VIEWREQUESTS command - View pending access requests for a file
 * 
 * WHAT: Lists all pending access requests for files owned by the user
 * WHERE: Called from client_connection_handler when CMD_VIEWREQUESTS is received
 * WHY: Allows file owners to see and manage access requests
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename
 * @param username - Username of the file owner
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_viewrequests_command(int client_fd, Packet *p, const char *username,
                                  const char *client_ip, int client_port, const char *op_name)
{
    int res = view_requests(p->filename, username, client_fd);
    log_response_ss(op_name, username, client_ip, client_port, res == 0 ? "OK" : "FAILED");
}

/**
 * Handle APPROVE command - Approve an access request
 * 
 * WHAT: Approves a pending access request and grants access
 * WHERE: Called from client_connection_handler when CMD_APPROVE is received
 * WHY: Allows file owners to grant requested access
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename and requester username (in payload)
 * @param username - Username of the file owner approving the request
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_approve_command(int client_fd, Packet *p, const char *username,
                             const char *client_ip, int client_port, const char *op_name)
{
    // Requester username in payload
    int res = approve_request(p->filename, p->payload, username);
    if (res == 0) {
        dprintf(client_fd, "[SS] Request approved. Access granted to %s.\n", p->payload);
        log_response_ss(op_name, username, client_ip, client_port, "OK");
    } else {
        dprintf(client_fd, "[SS] APPROVE failed: Request not found or access denied.\n");
        log_response_ss(op_name, username, client_ip, client_port, "FAILED");
    }
}

/**
 * Handle REJECT command - Reject an access request
 * 
 * WHAT: Rejects a pending access request without granting access
 * WHERE: Called from client_connection_handler when CMD_REJECT is received
 * WHY: Allows file owners to deny access requests
 * 
 * @param client_fd - File descriptor for client connection
 * @param p - Packet containing filename and requester username (in payload)
 * @param username - Username of the file owner rejecting the request
 * @param client_ip - IP address of client (for logging)
 * @param client_port - Port of client (for logging)
 * @param op_name - Operation name for logging
 */
void handle_reject_command(int client_fd, Packet *p, const char *username,
                            const char *client_ip, int client_port, const char *op_name)
{
    // Requester username in payload
    int res = reject_request(p->filename, p->payload);
    if (res == 0) {
        dprintf(client_fd, "[SS] Request rejected.\n");
        log_response_ss(op_name, username, client_ip, client_port, "OK");
    } else {
        dprintf(client_fd, "[SS] REJECT failed: Request not found.\n");
        log_response_ss(op_name, username, client_ip, client_port, "FAILED");
    }
}

