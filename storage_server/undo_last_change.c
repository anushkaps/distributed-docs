#include "storage_server.h"

/**
 * Deep copy a file structure for undo state
 * Creates a complete independent copy of the file structure including:
 * - Metadata (filename, owner, timestamps, word/char counts)
 * - Access control list (users_with_access)
 * - All sentences and words
 * 
 * @param src - Source file structure to copy
 * @return Deep copy of file structure, or NULL on failure
 */
static file* copy_file_struct_for_undo(file *src) {
    if (!src || !src->info) return NULL;
    
    file *dest = create_file_struct(src->info->filename);
    if (!dest) return NULL;
    
    // Copy metadata (but not the pointer fields)
    strncpy(dest->info->filename, src->info->filename, FILE_NAME_SIZE - 1);
    dest->info->filename[FILE_NAME_SIZE - 1] = '\0';
    dest->info->created = src->info->created;
    dest->info->modified = src->info->modified;
    dest->info->last_accessed = src->info->last_accessed;
    strncpy(dest->info->owner, src->info->owner, FILE_NAME_SIZE - 1);
    dest->info->owner[FILE_NAME_SIZE - 1] = '\0';
    dest->info->wordcount = src->info->wordcount;
    dest->info->charcount = src->info->charcount;
    strncpy(dest->info->lastmodifiedby, src->info->lastmodifiedby, FILE_NAME_SIZE - 1);
    dest->info->lastmodifiedby[FILE_NAME_SIZE - 1] = '\0';
    
    // Copy users_with_access (deep copy each user_access)
    if (src->info->users_with_access) {
        node_t *current = src->info->users_with_access->head;
        while (current) {
            user_access *ua = (user_access *)current->data;
            if (ua) {
                user_access *ua_copy = (user_access *)malloc(sizeof(user_access));
                if (ua_copy) {
                    strncpy(ua_copy->username, ua->username, FILE_NAME_SIZE - 1);
                    ua_copy->username[FILE_NAME_SIZE - 1] = '\0';
                    ua_copy->access_type = ua->access_type;
                    ua_copy->last_access = ua->last_access;
                    insert_at_n(dest->info->users_with_access, ua_copy, dest->info->users_with_access->size);
                }
            }
            current = current->next;
        }
    }
    
    // Copy sentences and words (deep copy)
    if (src->data) {
        node_t *sent_node = src->data->head;
        while (sent_node) {
            sentence *src_s = (sentence *)sent_node->data;
            if (src_s && src_s->data) {
                // Create new sentence
                sentence *dest_s = (sentence *)malloc(sizeof(sentence));
                if (dest_s) {
                    pthread_mutex_init(&dest_s->wrt, NULL);
                    dest_s->data = (linkedlist_t *)malloc(sizeof(linkedlist_t));
                    if (dest_s->data) {
                        init_linkedlist(dest_s->data);
                        
                        // Copy words in this sentence
                        node_t *word_node = src_s->data->head;
                        while (word_node) {
                            char *word = (char *)word_node->data;
                            if (word) {
                                insert_at_n(dest_s->data, strdup(word), dest_s->data->size);
                            }
                            word_node = word_node->next;
                        }
                        
                        insert_at_n(dest->data, dest_s, dest->data->size);
                    } else {
                        free(dest_s);
                    }
                }
            }
            sent_node = sent_node->next;
        }
    }
    
    return dest;
}

/**
 * Save current file state to undo history
 * This should be called BEFORE any write operation to enable undo
 * Saves undo state both in memory (hash table) and to disk for persistence
 * 
 * @param filename - Name of the file to save state for
 * @return 0 on success, -1 on failure
 */
int save_undo_state(const char *filename) {
    if (!filename || !curr_to_prev) return -1;
    
    // Get current file structure
    file *curr = in_htable(filename, name_to_ptr);
    if (!curr) {
        // File might not be in memory, try loading from disk
        char filepath[FILEPATH_SIZE];
        snprintf(filepath, sizeof(filepath), STORAGE_DIRECTORY "/%s", filename);
        curr = file_to_struct(filepath);
        if (!curr) return -1;
        // Add to main hash table
        if (name_to_ptr) {
            add_struct_to_htable(curr, name_to_ptr);
        }
    }
    
    // Remove any existing undo state for this file (both memory and disk)
    // (Only one undo level is supported)
    file *existing_prev = in_htable(filename, curr_to_prev);
    if (existing_prev) {
        remove_struct_from_htable(filename, curr_to_prev);
        free_file(existing_prev);
    }
    
    // Also remove existing undo file from disk
    char undo_filepath[FILEPATH_SIZE];
    snprintf(undo_filepath, sizeof(undo_filepath), STORAGE_DIRECTORY "/%s.undo", filename);
    remove(undo_filepath);
    
    // Acquire a read lock to ensure a consistent state during the copy
    pthread_rwlock_rdlock(&curr->rwlock);

    // Create deep copy of current state
    file *prev_copy = copy_file_struct_for_undo(curr);

    // Release the read lock
    pthread_rwlock_unlock(&curr->rwlock);

    if (!prev_copy) return -1;
    
    // Store in undo hash table (memory)
    ENTRY e, *ep;
    e.key = strdup(filename);
    e.data = prev_copy;
    
    if (hsearch_r(e, ENTER, &ep, curr_to_prev) == 0) {
        free_file(prev_copy);
        free(e.key);
        return -1;
    }
    
    // Persist undo state to disk for server restart recovery
    // Save to a special file with .undo extension
    // CRITICAL: We cannot use struct_to_file() because it frees the structure and removes from name_to_ptr
    // Instead, we manually save the undo file without modifying the in-memory structure
    char undo_file_path[FILEPATH_SIZE];
    snprintf(undo_file_path, sizeof(undo_file_path), STORAGE_DIRECTORY "/%s.undo", filename);
    
    FILE *undo_file = fopen(undo_file_path, "wb");
    if (undo_file) {
        // Write file using same format as struct_to_file, but don't free the structure
        fwrite(MAGIC, sizeof(char), 4, undo_file);
        fwrite(prev_copy->info->filename, sizeof(char), FILE_NAME_SIZE, undo_file);
        fwrite(&prev_copy->info->created, sizeof(time_t), 1, undo_file);
        fwrite(&prev_copy->info->modified, sizeof(time_t), 1, undo_file);
        fwrite(&prev_copy->info->last_accessed, sizeof(time_t), 1, undo_file);
        fwrite(prev_copy->info->owner, sizeof(char), FILE_NAME_SIZE, undo_file);
        fwrite(&prev_copy->info->wordcount, sizeof(size_t), 1, undo_file);
        fwrite(&prev_copy->info->charcount, sizeof(size_t), 1, undo_file);
        fwrite(prev_copy->info->lastmodifiedby, sizeof(char), FILE_NAME_SIZE, undo_file);
        
        // Write users_with_access
        linkedlist_t *users_with_access = prev_copy->info->users_with_access;
        fwrite(&users_with_access->size, sizeof(size_t), 1, undo_file);
        node_t *current = users_with_access->head;
        while (current) {
            user_access *ua = (user_access *)current->data;
            if (ua) {
                size_t user_len = strlen(ua->username) + 1;
                fwrite(&user_len, sizeof(size_t), 1, undo_file);
                fwrite(ua->username, sizeof(char), user_len, undo_file);
                fwrite(&ua->access_type, sizeof(int), 1, undo_file);
                fwrite(&ua->last_access, sizeof(time_t), 1, undo_file);
            }
            current = current->next;
        }
        
        // Write sentences and words
        linkedlist_t *data = prev_copy->data;
        fwrite(&data->size, sizeof(size_t), 1, undo_file);
        node_t *data_current = data->head;
        while (data_current) {
            sentence *s = (sentence *)data_current->data;
            size_t sentence_len = s->data->size;
            fwrite(&sentence_len, sizeof(size_t), 1, undo_file);
            
            node_t *word_node = s->data->head;
            while (word_node) {
                char *word = (char *)word_node->data;
                size_t word_len = strlen(word) + 1;
                fwrite(&word_len, sizeof(size_t), 1, undo_file);
                fwrite(word, sizeof(char), word_len, undo_file);
                word_node = word_node->next;
            }
            
            data_current = data_current->next;
        }
        
        fclose(undo_file);
    }
    // If file save fails, we still have it in memory (in hash table), so continue
    
    return 0;
}

int undo_last_change(const char *filename)
{
    if (!filename) return -1;

    // Step 1: Get the current version from the main hash table
    file *curr = in_htable(filename, name_to_ptr);
    if (!curr) {
        return -1;
    }

    // Step 2: Get the previous version from the undo hash table (or disk)
    file *prev = in_htable(filename, curr_to_prev);
    if (prev == NULL) {
        char undo_filepath[FILEPATH_SIZE];
        snprintf(undo_filepath, sizeof(undo_filepath), STORAGE_DIRECTORY "/%s.undo", filename);
        prev = file_to_struct(undo_filepath);
    }

    if (prev == NULL) {
        return -1; // No undo state available
    }

    // Acquire write locks to ensure thread safety during swap
    // (Optional but recommended if concurrency is high)
    pthread_rwlock_wrlock(&curr->rwlock);

    // Step 3: Swap the core content
    // 3a. Swap Data Pointers (Linked Lists)
    // It is safe to swap pointers here because the Hash Table does not point to data.
    linkedlist_t *temp_data = curr->data;
    curr->data = prev->data;
    prev->data = temp_data;

    // 3b. Swap Metadata CONTENTS (Values)
    // CRITICAL FIX: We swap the *values* of the structures, not the pointers.
    // This keeps the memory address of 'curr->info' (and 'curr->info->filename') unchanged,
    // ensuring the Hash Table key pointer remains valid.
    if (curr->info && prev->info) {
        meta_data temp_info = *curr->info; // Copy current values to temp
        *curr->info = *prev->info;         // Overwrite current with prev values
        *prev->info = temp_info;           // Move old values to prev (to be freed)
    }

    // Now `curr` holds the restored state with the SAME metadata pointer address.
    // `prev` holds the state that was just undone.

    pthread_rwlock_unlock(&curr->rwlock);

    // Step 4: Remove the undo state from the undo hash table
    remove_struct_from_htable(filename, curr_to_prev);

    // Step 5: Free the `prev` struct
    // This now frees the *contents* we wanted to discard, while the pointers 
    // in the main Hash Table remain pointing to `curr`.
    free_file(prev);

    // Step 6: Persist the restored state (now in `curr`) to the main file
    save_file_to_disk(curr);

    // Step 7: Remove the .undo file from disk
    char undo_filepath[FILEPATH_SIZE];
    snprintf(undo_filepath, sizeof(undo_filepath), STORAGE_DIRECTORY "/%s.undo", filename);
    remove(undo_filepath);

    return 0;
}