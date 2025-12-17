#include "storage_server.h"

int struct_to_file(file *f)
{
    if (!f || !f->info)
    {
        return -1; // we allow empty files
    }

    // Construct full file path in storage directory
    // Files are stored in ./storage_current/ directory
    char filepath[FILEPATH_SIZE];
    snprintf(filepath, sizeof(filepath), STORAGE_DIRECTORY "/%s", f->info->filename);
    
    FILE *file = fopen(filepath, "wb");
    if (file == NULL)
    {
        return -1;
    }

    fwrite(MAGIC, sizeof(char), 4, file);
    fwrite(f->info->filename, sizeof(char), FILE_NAME_SIZE, file);
    fwrite(&f->info->created, sizeof(time_t), 1, file);
    fwrite(&f->info->modified, sizeof(time_t), 1, file);
    fwrite(&f->info->last_accessed, sizeof(time_t), 1, file);  // Write last_accessed timestamp
    fwrite(f->info->owner, sizeof(char), FILE_NAME_SIZE, file);
    fwrite(&f->info->wordcount, sizeof(size_t), 1, file);
    fwrite(&f->info->charcount, sizeof(size_t), 1, file);
    fwrite(f->info->lastmodifiedby, sizeof(char), FILE_NAME_SIZE, file);

    linkedlist_t *users_with_access = (linkedlist_t *)f->info->users_with_access;
    fwrite(&users_with_access->size, sizeof(size_t), 1, file);

    node_t *current = (node_t *)users_with_access->head;
    while (current)
    {
        user_access *ua = (user_access *)current->data;
        if (ua) {
            // Write username length and username
            size_t user_len = strlen(ua->username) + 1;
            fwrite(&user_len, sizeof(size_t), 1, file); 
            fwrite(ua->username, sizeof(char), user_len, file);
            // Write access type
            fwrite(&ua->access_type, sizeof(int), 1, file);
            // Write last access time
            fwrite(&ua->last_access, sizeof(time_t), 1, file);
        }
        current = current->next;
    }

    linkedlist_t *data = (linkedlist_t *)f->data;
    fwrite(&data->size, sizeof(size_t), 1, file);

    node_t *data_current = (node_t *)data->head;
    while (data_current)
    {
        sentence *s = (sentence *)data_current->data;
        size_t sentence_len = s->data->size;
        fwrite(&sentence_len, sizeof(size_t), 1, file);

        node_t *current_word = (node_t *)s->data->head;
        for (current_word = s->data->head; current_word != NULL; current_word = current_word->next)
        {
            char *word = (char *)current_word->data;
            size_t word_len = strlen(word) + 1; // /0
            fwrite(&word_len, sizeof(size_t), 1, file);
            fwrite(word, sizeof(char), word_len, file);
        }

        data_current = data_current->next;
    }

    fclose(file);
    remove_struct_from_htable(f->info->filename, name_to_ptr);
    free_file(f);
    return 0;
}

/**
 * Save file structure to disk without removing from hash table or freeing
 * This is used for persisting active files that should remain in memory
 * 
 * @param f - File structure to save
 * @return 0 on success, -1 on failure
 */
int save_file_to_disk(file *f)
{
    if (!f || !f->info)
    {
        return -1;
    }

    // Construct full file path in storage directory
    char filepath[FILEPATH_SIZE];
    snprintf(filepath, sizeof(filepath), STORAGE_DIRECTORY "/%s", f->info->filename);
    
    FILE *file = fopen(filepath, "wb");
    if (file == NULL)
    {
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
    while (current)
    {
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

    node_t *data_current = (node_t *)data->head;
    while (data_current)
    {
        sentence *s = (sentence *)data_current->data;
        size_t sentence_len = s->data->size;
        fwrite(&sentence_len, sizeof(size_t), 1, file);

        node_t *current_word = (node_t *)s->data->head;
        for (current_word = s->data->head; current_word != NULL; current_word = current_word->next)
        {
            char *word = (char *)current_word->data;
            size_t word_len = strlen(word) + 1;
            fwrite(&word_len, sizeof(size_t), 1, file);
            fwrite(word, sizeof(char), word_len, file);
        }

        data_current = data_current->next;
    }

    fclose(file);
    // NOTE: We do NOT remove from hash table or free the structure
    // This function is for persisting active files that should remain in memory
    return 0;
}

file *file_to_struct(const char *filename)
{
    FILE *fileptr = fopen(filename, "rb");
    if (fileptr == NULL)
    {
        perror("[SS] file_to_struct: fopen");
        return NULL;
    }

    file *f = create_file_struct(filename);
    if (f == NULL)
    {
        fclose(fileptr);
        return NULL;
    }

    char magic[4];
    fread(magic, sizeof(char), 4, fileptr);
    if (strncmp(magic, MAGIC, 4) != 0)
    {
        perror("[SS] file_to_struct: Invalid file format");
        fclose(fileptr);
        free_file(f);
        return NULL;
    }

    fread((char *)f->info->filename, sizeof(char), FILE_NAME_SIZE, fileptr);
    // Ensure filename is null-terminated and trim trailing whitespace
    f->info->filename[FILE_NAME_SIZE - 1] = '\0';
    size_t filename_len = strlen(f->info->filename);
    while (filename_len > 0 && (f->info->filename[filename_len-1] == ' ' || 
                                f->info->filename[filename_len-1] == '\t' || 
                                f->info->filename[filename_len-1] == '\n' || 
                                f->info->filename[filename_len-1] == '\r')) {
        f->info->filename[--filename_len] = '\0';
    }
    fread(&f->info->created, sizeof(time_t), 1, fileptr);
    fread(&f->info->modified, sizeof(time_t), 1, fileptr);
    
    // Check if file has new format with last_accessed field
    // Try to read last_accessed - if it fails, file is in old format
    long pos_before = ftell(fileptr);
    if (fread(&f->info->last_accessed, sizeof(time_t), 1, fileptr) != 1) {
        // Old file format - rewind and initialize last_accessed to modified time
        fseek(fileptr, pos_before, SEEK_SET);
        f->info->last_accessed = f->info->modified;
    }
    
    fread(f->info->owner, sizeof(char), FILE_NAME_SIZE, fileptr);
    fread(&f->info->wordcount, sizeof(size_t), 1, fileptr);
    fread(&f->info->charcount, sizeof(size_t), 1, fileptr);
    fread(f->info->lastmodifiedby, sizeof(char), FILE_NAME_SIZE, fileptr);
    size_t access_list_size;
    fread(&access_list_size, sizeof(size_t), 1, fileptr);

    for(size_t i = 0; i < access_list_size; i++)
    {
        size_t user_len;
        fread(&user_len, sizeof(size_t), 1, fileptr);

        // Allocate user_access structure
        user_access *ua = (user_access *)malloc(sizeof(user_access));
        if (ua == NULL)
        {
            fclose(fileptr);
            free_file(f);
            return NULL;
        }
        
        // Read username
        if (user_len > FILE_NAME_SIZE) {
            user_len = FILE_NAME_SIZE - 1;
        }
        fread(ua->username, sizeof(char), user_len, fileptr);
        ua->username[user_len] = '\0';
        
        // Read access type
        fread(&ua->access_type, sizeof(int), 1, fileptr);
        
        // Read last access time
        fread(&ua->last_access, sizeof(time_t), 1, fileptr);

        insert_at_n(f->info->users_with_access, ua, f->info->users_with_access->size);
    }

    size_t size;
    fread(&size, sizeof(size_t), 1, fileptr);
    // Don't set f->data->size here - let insert_at_n manage it
    // f->data->size will be updated by insert_at_n as we add elements
    for (size_t i = 0; i < size; i++)
    {
        sentence *s = (sentence *)malloc(sizeof(sentence));
        if (s == NULL)
        {
            fclose(fileptr);
            free_file(f);
            return NULL;
        }

        pthread_mutex_init(&s->wrt, NULL);

        size_t sentence_len;
        fread(&sentence_len, sizeof(size_t), 1, fileptr);

        s->data = (linkedlist_t *)malloc(sizeof(linkedlist_t));
        if (s->data == NULL)
        {
            fclose(fileptr);
            free_file(f);
            return NULL;
        }
        init_linkedlist(s->data);
        // Don't set s->data->size here - let insert_at_n manage it
        // s->data->size will be updated by insert_at_n as we add words

        for (size_t j = 0; j < sentence_len; j++)
        {
            size_t word_len;
            fread(&word_len, sizeof(size_t), 1, fileptr);

            char *word = (char *)malloc(word_len * sizeof(char));
            if (word == NULL)
            {
                fclose(fileptr);
                free_file(f);
                return NULL;
            }
            fread(word, sizeof(char), word_len, fileptr);

            // Insert at the current size (which is j, since we're inserting sequentially)
            insert_at_n(s->data, word, j);
        }
        // Insert at the current size (which is i, since we're inserting sequentially)
        insert_at_n(f->data, s, i);
    }

    return f;
}