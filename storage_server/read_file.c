#include "storage_server.h"

// Helper function to calculate the total size of the file content
static size_t get_content_size(file *f, const char *delimiter)
{
    size_t total_len = 0;
    bool first_sentence = true;
    for (node_t *current = f->data->head; current != NULL; current = current->next)
    {
        sentence *s = (sentence *)current->data;
        if (s == NULL || s->data == NULL || s->data->size == 0)
        {
            continue;
        }

        if (!first_sentence)
        {
            total_len += strlen(delimiter); // For space or newline between sentences
        }

        bool first_word = true;
        for (node_t *word = s->data->head; word != NULL; word = word->next)
        {
            char *w = (char *)word->data;
            if (w != NULL)
            {
                if (!first_word)
                {
                    total_len++; // For space between words
                }
                total_len += strlen(w);
                first_word = false;
            }
        }
        first_sentence = false;
    }
    return total_len;
}

// Generic function to read file content with a specified delimiter
static char *read_file_with_delimiter(const char *filename, struct hsearch_data *name_to_ptr, const char *delimiter)
{
    file *f = in_htable(filename, name_to_ptr);
    if (f == NULL)
    {
        // The file must be in memory to be read. The caller should handle loading if necessary.
        return NULL;
    }

    // Use a reader-writer lock for better concurrency.
    pthread_rwlock_rdlock(&f->rwlock);

    // Calculate required size and allocate buffer
    size_t total_len = get_content_size(f, delimiter);
    char *buffer = calloc(1, total_len + 1); // +1 for null terminator
    if (buffer == NULL)
    {
        pthread_rwlock_unlock(&f->rwlock);
        return NULL; // Allocation failed
    }

    // Construct the string efficiently in a single pass
    char *ptr = buffer;
    bool first_sentence = true;
    for (node_t *current = f->data->head; current != NULL; current = current->next)
    {
        sentence *s = (sentence *)current->data;
        if (s == NULL || s->data == NULL || s->data->size == 0)
        {
            continue;
        }

        if (!first_sentence)
        {
            ptr += sprintf(ptr, "%s", delimiter);
        }

        bool first_word = true;
        for (node_t *word = s->data->head; word != NULL; word = word->next)
        {
            char *w = (char *)word->data;
            if (w != NULL)
            {
                if (!first_word)
                {
                    *ptr++ = ' ';
                }
                ptr += sprintf(ptr, "%s", w);
                first_word = false;
            }
        }
        first_sentence = false;
    }

    // Release the lock
    pthread_rwlock_unlock(&f->rwlock);

    return buffer;
}

char *read_file(const char *filename, struct hsearch_data *name_to_ptr)
{
    return read_file_with_delimiter(filename, name_to_ptr, " ");
}

char *read_file_for_exec(const char *filename, struct hsearch_data *name_to_ptr)
{
    return read_file_with_delimiter(filename, name_to_ptr, "\n");
}
