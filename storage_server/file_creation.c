#include "storage_server.h"

void free_file(file *f)
{
    if (!f)
    {
        return;
    }

    // Destroy locks before freeing memory
    pthread_mutex_destroy(&f->mutex);
    pthread_rwlock_destroy(&f->rwlock);

    // Free user_access structures before freeing the linkedlist
    if (f->info && f->info->users_with_access) {
        node_t *current = f->info->users_with_access->head;
        while (current) {
            user_access *ua = (user_access *)current->data;
            if (ua) {
                free(ua);
            }
            current = current->next;
        }
    }
    free_linkedlist(f->info->users_with_access);
    free(f->info);

    for(node_t *current = f->data->head; current != NULL; current = current -> next)
    {
        sentence *s = (sentence *)current->data;
        pthread_mutex_destroy(&s->wrt); // Destroy sentence mutex
        // The word data (char*) is freed by the caller of free_linkedlist on s->data
        free_linkedlist(s->data);
        free(s);
    }
    
    free_linkedlist((linkedlist_t *)f->data);
    free(f);
    f = NULL;
}

file *create_file_struct(const char *filename)
{
    file *f = (file *)malloc(sizeof(file));
    if (f == NULL)
    {
        perror("[SS] create_file_struct: malloc");
        return NULL;
    }

    pthread_mutex_init(&f->mutex, NULL);
    pthread_rwlock_init(&f->rwlock, NULL); // Initialize rwlock
    f->readcount = 0;
    f->writecount = 0;

    f->info = (meta_data *)malloc(sizeof(meta_data));
    if (f->info == NULL)
    {
        perror("[SS] create_file_struct: malloc");
        pthread_mutex_destroy(&f->mutex);
        pthread_rwlock_destroy(&f->rwlock);
        free(f);
        return NULL;
    }

    // Extract just the filename from the path (handle paths like "./storage_current/t1.undo")
    const char *base_filename = filename;
    const char *last_slash = strrchr(filename, '/');
    if (last_slash != NULL) {
        base_filename = last_slash + 1;
    }
    
    // Copy and trim filename to ensure consistent storage
    // Trim trailing whitespace to prevent hash table lookup issues
    size_t filename_len = strlen(base_filename);
    if (filename_len >= FILE_NAME_SIZE) filename_len = FILE_NAME_SIZE - 1;
    
    strncpy((char *)f->info->filename, base_filename, filename_len);
    f->info->filename[filename_len] = '\0';
    
    // Trim trailing whitespace
    while (filename_len > 0 && (f->info->filename[filename_len-1] == ' ' || 
                                f->info->filename[filename_len-1] == '\t' || 
                                f->info->filename[filename_len-1] == '\n' || 
                                f->info->filename[filename_len-1] == '\r')) {
        f->info->filename[--filename_len] = '\0';
    }
    f->info->created = time(NULL);
    f->info->modified = f->info->created;
    f->info->last_accessed = f->info->created;  // Initialize last_accessed to creation time
    // strncpy(f->info->owner, "unknown", FILE_NAME_SIZE);
    f->info->wordcount = 0;
    f->info->charcount = 0;
    // strncpy(f->info->lastmodifiedby, "unknown", FILE_NAME_SIZE);
    f->info->users_with_access = (linkedlist_t *)malloc(sizeof(linkedlist_t));
    if (f->info->users_with_access == NULL)
    {
        perror("[SS] create_file_struct: malloc");
        free(f->info);
        pthread_mutex_destroy(&f->mutex);
        pthread_rwlock_destroy(&f->rwlock);
        free(f);
        return NULL;
    }
    init_linkedlist(f->info->users_with_access);

    f->data = (linkedlist_t *)malloc(sizeof(linkedlist_t));
    if (f->data == NULL)
    {
        free(f->info->users_with_access);
        free(f->info);
        pthread_mutex_destroy(&f->mutex);
        pthread_rwlock_destroy(&f->rwlock);
        free(f);
        return NULL;
    }
    init_linkedlist(f->data);

    return f;
}

int delete_file(const char *filename)
{
    if (!filename) return -1;
    
    // Construct full file path in storage directory
    // Files are stored in ./storage_current/ directory
    char filepath[FILEPATH_SIZE];
    snprintf(filepath, sizeof(filepath), STORAGE_DIRECTORY "/%s", filename);
    
    // Also construct path for .undo file
    char undo_filepath[FILEPATH_SIZE];
    snprintf(undo_filepath, sizeof(undo_filepath), STORAGE_DIRECTORY "/%s.undo", filename);
    
    // Remove file from memory structures first
    file *f = in_htable(filename, name_to_ptr);
    if (f != NULL)
    {
        // Remove from file_list before freeing
        // Need to check all entries to handle potential duplicates
        node_t *current = file_list.head;
        size_t idx = 0;
        while (current) {
            file *file_in_list = (file *)current->data;
            // Remove if pointer matches OR filename matches (handle stale entries)
            if (file_in_list == f || (file_in_list && file_in_list->info && 
                strcmp(file_in_list->info->filename, filename) == 0)) {
                node_t *next = current->next;
                remove_at_n(&file_list, idx);
                // If we removed by pointer match, break; otherwise continue to remove duplicates
                if (file_in_list == f) {
                    break;
                }
                current = next;
                // Don't increment idx since we removed an element
                continue;
            }
            current = current->next;
            idx++;
        }
        remove_struct_from_htable(filename, name_to_ptr);
        free_file(f);
    }
    
    // Remove undo state from memory (if exists)
    file *undo_f = in_htable(filename, curr_to_prev);
    if (undo_f != NULL)
    {
        remove_struct_from_htable(filename, curr_to_prev);
        free_file(undo_f);
    }
    
    // Remove main file from disk
    if (remove(filepath) != 0) {
        // File might not exist on disk, but that's okay if it's already removed
        // We still return success if it was removed from memory structures
    }
    
    // Remove .undo file from disk (if exists)
    remove(undo_filepath);

    return 0;
}