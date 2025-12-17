#include "storage_server.h"
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>

/**
 * Split content at sentence delimiters (. ! ?)
 * * Every delimiter creates a split point.
 * Delimiter is included with the content before it.
 * * IMPORTANT: Delimiters inside quotes are IGNORED to preserve shell commands.
 * This allows commands like: echo "Running diagnostics..." to stay as one sentence.
 * * Examples:
 * - "AAD." -> ["AAD."]
 * - "e.g." -> ["e.", "g."] (no quotes, so splits)
 * - "echo \"test.\"" -> ["echo \"test.\""] (period in quotes, no split)
 * - "???" -> ["?", "?", "?"]
 * - ".." -> [".", "."]
 */
static linkedlist_t* split_at_delimiters(const char *content) {
    linkedlist_t *parts = (linkedlist_t*)malloc(sizeof(linkedlist_t));
    if (!parts) return NULL;
    init_linkedlist(parts);
    
    if (!content || strlen(content) == 0) {
        char *empty = strdup("");
        if (empty) insert_at_n(parts, empty, parts->size);
        return parts;
    }
    
    int start = 0;
    int len = strlen(content);
    int in_quotes = 0;  // Track if we're inside quotes
    char quote_char = 0;  // Track which quote character (' or ")
    
    for (int i = 0; i < len; i++) {
        // Handle quote characters
        if (content[i] == '"' || content[i] == '\'') {
            if (!in_quotes) {
                // Entering quotes
                in_quotes = 1;
                quote_char = content[i];
            } else if (content[i] == quote_char) {
                // Exiting quotes (matching quote)
                in_quotes = 0;
                quote_char = 0;
            }
            // If in quotes but different quote type, treat as regular char
            continue;
        }
        
        // Only split on delimiters if NOT inside quotes
        if (!in_quotes && (content[i] == '.' || content[i] == '!' || content[i] == '?')) {
            // Include delimiter in current part
            int part_len = i - start + 1;
            char *part = (char*)malloc(part_len + 1);
            if (part) {
                strncpy(part, content + start, part_len);
                part[part_len] = '\0';
                insert_at_n(parts, part, parts->size);
            }
            start = i + 1;
        }
    }
    
    // Add remaining content after last delimiter (if any and non-empty)
    if (start < len) {
        int part_len = len - start;
        char *part = (char*)malloc(part_len + 1);
        if (part) {
            strncpy(part, content + start, part_len);
            part[part_len] = '\0';
            insert_at_n(parts, part, parts->size);
        }
    }
    
    // If no delimiters and no parts, add whole content
    if (parts->size == 0) {
        char *whole = strdup(content);
        if (whole) insert_at_n(parts, whole, parts->size);
    }
    
    return parts;
}

static char* get_swap_file_path(const char *filename) {
    char *swap_path = (char*)malloc(strlen(filename) + 10);
    if (!swap_path) return NULL;
    snprintf(swap_path, strlen(filename) + 10, "%s.swap", filename);
    return swap_path;
}

static int struct_to_file_path(file *f, const char *filepath) {
    if (!f || !f->info || !filepath) {
        return -1;
    }

    FILE *file = fopen(filepath, "wb");
    if (file == NULL) {
        return -1;
    }

    fwrite(MAGIC, sizeof(char), 4, file);
    fwrite(f->info->filename, sizeof(char), FILE_NAME_SIZE, file);
    fwrite(&f->info->created, sizeof(time_t), 1, file);
    fwrite(&f->info->modified, sizeof(time_t), 1, file);
    fwrite(&f->info->last_accessed, sizeof(time_t), 1, file);
    fwrite(f->info->owner, sizeof(char), FILE_NAME_SIZE, file);
    fwrite(&f->info->wordcount, sizeof(size_t), 1, file);
    fwrite(&f->info->charcount, sizeof(size_t), 1, file);
    fwrite(f->info->lastmodifiedby, sizeof(char), FILE_NAME_SIZE, file);

    linkedlist_t *users_with_access = (linkedlist_t *)f->info->users_with_access;
    fwrite(&users_with_access->size, sizeof(size_t), 1, file);

    node_t *current = (node_t *)users_with_access->head;
    while (current) {
        user_access *ua = (user_access *)current->data;
        if (ua) {
            size_t user_len = strlen(ua->username) + 1;
            fwrite(&user_len, sizeof(size_t), 1, file); 
            fwrite(ua->username, sizeof(char), user_len, file);
            fwrite(&ua->access_type, sizeof(int), 1, file);
            fwrite(&ua->last_access, sizeof(time_t), 1, file);
        }
        current = current->next;
    }

    linkedlist_t *data = (linkedlist_t *)f->data;
    fwrite(&data->size, sizeof(size_t), 1, file);

    current = (node_t *)data->head;
    while (current) {
        sentence *s = (sentence *)current->data;
        size_t sentence_len = s->data->size;
        fwrite(&sentence_len, sizeof(size_t), 1, file);

        node_t *current_word = (node_t *)s->data->head;
        for (current_word = s->data->head; current_word != NULL; current_word = current_word->next) {
            char *word = (char *)current_word->data;
            size_t word_len = strlen(word) + 1;
            fwrite(&word_len, sizeof(size_t), 1, file);
            fwrite(word, sizeof(char), word_len, file);
        }

        current = current->next;
    }

    fclose(file);
    return 0;
}

int finalize_write_atomic(const char *filename, struct hsearch_data *name_to_ptr) {
    if (!filename) return -1;
    
    file *f = in_htable(filename, name_to_ptr);
    if (!f) {
        f = file_to_struct(filename);
        if (!f) return -1;
        if (name_to_ptr) {
            add_struct_to_htable(f, name_to_ptr);
        }
    }
    
    char *swap_path = get_swap_file_path(filename);
    if (!swap_path) return -1;
    
    int result = struct_to_file_path(f, swap_path);
    
    if (result != 0) {
        free(swap_path);
        return -1;
    }
    
    if (rename(swap_path, filename) == 0) {
        free(swap_path);
        return 0;
    }
    
    unlink(swap_path);
    free(swap_path);
    return -1;
}

// Helper function to check if a word ends with a sentence delimiter
static int ends_with_delimiter(const char *word) {
    if (!word) return 0;
    size_t len = strlen(word);
    if (len == 0) return 0;
    char last = word[len-1];
    return (last == '.' || last == '!' || last == '?');
}

/**
 * Apply all queued word updates to a file
 * * RULES:
 * 1. Each update line targets the ORIGINAL sentence_index
 * 2. Split content by spaces → get words
 * 3. For each word, split by delimiters (. ! ?)
 * 4. Enforce sentence structure: Delimiters only at end of sentence.
 * - If insertion follows a word with delimiter -> SPLIT
 * - If inserted word has delimiter -> SPLIT
 */
int apply_queued_updates(file *f, int sentence_index, linkedlist_t *updates) {
    if (!f || !f->data || !updates) return -1;
    
    node_t *update_node = updates->head;
    
    while (update_node) {
        word_update_t *update = (word_update_t *)update_node->data;
        if (!update || !update->content) {
            update_node = update_node->next;
            continue;
        }
        
        if (update->word_index < 0) {
            update_node = update_node->next;
            continue;
        }

        // Create sentences up to sentence_index if needed
        while ((size_t)sentence_index >= f->data->size) {
            sentence *new_s = (sentence *)malloc(sizeof(sentence));
            if (!new_s) continue; // Or handle error
            pthread_mutex_init(&new_s->wrt, NULL);
            new_s->data = (linkedlist_t *)malloc(sizeof(linkedlist_t));
            if (!new_s->data) {
                free(new_s);
                continue; // Or handle error
            }
            init_linkedlist(new_s->data);
            insert_at_n(f->data, new_s, f->data->size);
        }
        
        // Each update line targets the ORIGINAL sentence (before splits in this batch)
        node_t *sentence_node = f->data->head;
        size_t i;
        for (i = 0; i < (size_t)sentence_index && sentence_node != NULL; i++) {
            sentence_node = sentence_node->next;
        }
        if (!sentence_node) {
            update_node = update_node->next;
            continue;
        }
        
        sentence *target_sentence = (sentence *)sentence_node->data;
        if (!target_sentence || !target_sentence->data) {
            update_node = update_node->next;
            continue;
        }
        
        // Check bounds
        if (update->word_index > (int)target_sentence->data->size) {
            update_node = update_node->next;
            continue;
        }
        
        // Split by spaces
        char *content_copy = strdup(update->content);
        if (!content_copy) {
            update_node = update_node->next;
            continue;
        }
        
        linkedlist_t *words_list = (linkedlist_t *)malloc(sizeof(linkedlist_t));
        if (!words_list) {
            free(content_copy);
            update_node = update_node->next;
            continue;
        }
        init_linkedlist(words_list);
        
        char *saveptr;
        char *token = strtok_r(content_copy, " ", &saveptr);
        while (token) {
            char *word = strdup(token);
            if (word) {
                insert_at_n(words_list, word, words_list->size);
            }
            token = strtok_r(NULL, " ", &saveptr);
        }
        free(content_copy);
        
        // Process words
        node_t *word_node = words_list->head;
        int insert_position = update->word_index;
        int working_sentence_index = sentence_index;
        sentence *working_sentence = target_sentence;
        
        while (word_node) {
            char *word_str = (char *)word_node->data;
            if (!word_str) {
                word_node = word_node->next;
                continue;
            }
            
            // Split word at delimiters
            linkedlist_t *parts = split_at_delimiters(word_str);
            if (!parts || parts->size == 0) {
                word_node = word_node->next;
                continue;
            }
            
            node_t *part_node = parts->head;
            while (part_node) {
                char *part = (char *)part_node->data;
                if (part && strlen(part) > 0) {
                    // 1. Insert the part
                    insert_at_n(working_sentence->data, strdup(part), insert_position);
                    insert_position++;
                    
                    // 2. Check for SPLIT CONDITION: Previous word ended with delimiter
                    // If we inserted at index K (now K+1), check word at K-1.
                    // Note: insert_position is now K+1. Prev word is at insert_position-2.
                    if (insert_position >= 2) {
                        node_t *curr = working_sentence->data->head;
                        for (int k=0; k < insert_position - 2; k++) curr = curr->next;
                        char *prev_word = (char*)curr->data;
                        
                        if (ends_with_delimiter(prev_word)) {
                            // SPLIT at insert_position - 1 (the word we just inserted starts new sentence)
                            int split_idx = insert_position - 1;
                            
                            sentence *new_s = (sentence *)malloc(sizeof(sentence));
                            pthread_mutex_init(&new_s->wrt, NULL);
                            new_s->data = (linkedlist_t *)malloc(sizeof(linkedlist_t));
                            init_linkedlist(new_s->data);
                            
                            // Move words from split_idx to new sentence
                            node_t *curr_n = working_sentence->data->head;
                            node_t *prev_n = NULL;
                            for (int k=0; k < split_idx; k++) {
                                prev_n = curr_n;
                                curr_n = curr_n->next;
                            }
                            
                            // Transfer list tail to new sentence
                            new_s->data->head = curr_n;
                            // Calculate size of new list (inefficient but safe)
                            size_t new_size = 0;
                            node_t *temp = curr_n;
                            while (temp) { new_size++; temp = temp->next; }
                            new_s->data->size = new_size;
                            
                            // Cut old list
                            if (prev_n) prev_n->next = NULL;
                            else working_sentence->data->head = NULL; // Split at 0
                            working_sentence->data->size = split_idx;
                            
                            // Insert new sentence into file
                            insert_at_n(f->data, new_s, working_sentence_index + 1);
                            working_sentence_index++;
                            working_sentence = new_s;
                            
                            // Updates continue in the new sentence
                            insert_position = 1; // We moved 1 word (the one we just inserted)
                        }
                    }
                    
                    // 3. Check for SPLIT CONDITION: Current (inserted) word ends with delimiter
                    // Word is at insert_position - 1.
                    {
                        node_t *curr = working_sentence->data->head;
                        for (int k=0; k < insert_position - 1; k++) curr = curr->next;
                        char *curr_word = (char*)curr->data;
                        
                        if (ends_with_delimiter(curr_word)) {
                            // SPLIT after this word (at insert_position)
                            int split_idx = insert_position;
                            
                            sentence *new_s = (sentence *)malloc(sizeof(sentence));
                            pthread_mutex_init(&new_s->wrt, NULL);
                            new_s->data = (linkedlist_t *)malloc(sizeof(linkedlist_t));
                            init_linkedlist(new_s->data);
                            
                            // Move words (if any) to new sentence
                            node_t *curr_n = working_sentence->data->head;
                            node_t *prev_n = NULL;
                            for (int k=0; k < split_idx; k++) {
                                prev_n = curr_n;
                                curr_n = curr_n->next;
                            }
                            
                            new_s->data->head = curr_n;
                            size_t new_size = 0;
                            node_t *temp = curr_n;
                            while (temp) { new_size++; temp = temp->next; }
                            new_s->data->size = new_size;
                            
                            if (prev_n) prev_n->next = NULL;
                            else working_sentence->data->head = NULL;
                            working_sentence->data->size = split_idx;
                            
                            insert_at_n(f->data, new_s, working_sentence_index + 1);
                            working_sentence_index++;
                            working_sentence = new_s;
                            
                            // Updates continue in the new sentence (at start)
                            insert_position = 0;
                        }
                    }
                }
                part_node = part_node->next;
            }
            
            // Free parts list
            node_t *part_node_free = parts->head;
            while (part_node_free) {
                node_t *next = part_node_free->next;
                free(part_node_free);
                part_node_free = next;
            }
            free(parts);
            
            word_node = word_node->next;
        }
        
        // Free words_list
        node_t *word_node_free = words_list->head;
        while (word_node_free) {
            node_t *next = word_node_free->next;
            free(word_node_free->data);
            free(word_node_free);
            word_node_free = next;
        }
        free(words_list);
        
        update_node = update_node->next;
    }
    
    return 0;
}

int write_file(const char *filename, int sentence_index, int word_index, const char *data, struct hsearch_data *name_to_ptr)
{
    // This function remains mostly wrapper around queueing logic in command_handlers
    // But if called directly, it acts as a single update.
    // We'll keep the original implementation but fix the splitting logic inside the loop if needed.
    // However, the main logic is now in apply_queued_updates which is used by handle_write_command.
    // For direct calls, we can just use similar logic.
    // But since this function duplicates logic, let's just fix the split_at_delimiters part 
    // or rely on apply_queued_updates if refactoring.
    // For minimal disruption, we leave this as legacy/direct support but update it to match fix.
    
    // ... (omitted for brevity as user issue is with queued updates via command handler)
    // The user explicitly mentioned "write command", which uses handle_write_command -> apply_queued_updates.
    
    // We return the original implementation for write_file to avoid breaking other paths,
    // assuming handle_write_command is the primary entry point for the CLI issue.
    // (Implementation from previous file content fetch is preserved below for completeness)

    if (word_index < 0 || sentence_index < 0) {
        return -1;
    }

    file *f = in_htable(filename, name_to_ptr);
    if (f == NULL) {
        f = file_to_struct(filename);
        if (f == NULL) {
            return -1;
        }
        add_struct_to_htable(f, name_to_ptr);
    }

    size_t original_sentence_count = f->data->size;
    if (sentence_index > (int)original_sentence_count) {
        fprintf(stderr, "Sentence index out of bounds: %d (file has %zu sentences)\n", 
                sentence_index, original_sentence_count);
        return -1;
    }
    
    // Create sentences up to sentence_index if needed
    node_t *current = f->data->head;
    size_t i;
    for (i = 0; i < (size_t)sentence_index && current != NULL; i++) {
        current = current->next;
    }

    while (i <= (size_t)sentence_index) {
        sentence *new_s = (sentence *)malloc(sizeof(sentence));
        if (new_s == NULL) {
            return -1;
        }
        pthread_mutex_init(&new_s->wrt, NULL);
        new_s->data = (linkedlist_t *)malloc(sizeof(linkedlist_t));
        if (new_s->data == NULL) {
            free(new_s);
            return -1;
        }
        init_linkedlist(new_s->data);
        insert_at_n(f->data, new_s, f->data->size);
        i++;
    }
    
    // Get target sentence
    current = f->data->head;
    for (i = 0; i < (size_t)sentence_index && current != NULL; i++) {
        current = current->next;
    }
    
    if (current == NULL) {
        return -1;
    }
    
    sentence *s = (sentence *)current->data;
    if (s == NULL || s->data == NULL) {
        return -1;
    }

    // Concurrency control
    pthread_mutex_lock(&f->mutex);
    f->writecount++;
    if (pthread_mutex_trylock(&s->wrt) != 0) {
        f->writecount--;
        pthread_mutex_unlock(&f->mutex);
        return -1;
    }
    pthread_mutex_unlock(&f->mutex);

    // Use a temporary list to create an update and apply it using the fixed function
    linkedlist_t *updates = (linkedlist_t*)malloc(sizeof(linkedlist_t));
    init_linkedlist(updates);
    word_update_t *up = (word_update_t*)malloc(sizeof(word_update_t));
    up->word_index = word_index;
    up->content = strdup(data);
    insert_at_n(updates, up, 0);
    
    int res = apply_queued_updates(f, sentence_index, updates);
    
    // Cleanup
    node_t *n = updates->head;
    while(n) {
        word_update_t *u = (word_update_t*)n->data;
        free(u->content);
        free(u);
        n = n->next;
    }
    free_linkedlist(updates);

    pthread_mutex_lock(&f->mutex);
    f->writecount--;
    pthread_mutex_unlock(&s->wrt);
    pthread_mutex_unlock(&f->mutex);

    return res;
}