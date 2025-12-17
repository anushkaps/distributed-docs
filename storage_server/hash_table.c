#include "../storage_server/storage_server.h"

int init_struct_table(struct hsearch_data *htable, size_t size)
{
    if (hcreate_r(size, htable) == 0)
    {
        fprintf(stderr, "Error creating hashtable\n");
        return -1;
    }
    return 0;
}

int add_struct_to_htable(file *f, struct hsearch_data *htable)
{
    if (!f || !htable || !f->info)
    {
        return -1;
    }

    ENTRY item;
    ENTRY *found;

    // Use the filename from the file structure (which is persistent)
    // hsearch_r stores the key pointer, so we must use the persistent filename
    // Don't modify the filename in place - use it as-is
    // The filename should already be properly formatted when the file structure is created
    char *key = f->info->filename;
    
    // Ensure the filename is null-terminated (it should be, but be safe)
    // Don't trim here - trimming should happen when the file structure is created
    // or when looking up, not when storing (to avoid modifying persistent data)

    item.key = key;
    item.data = NULL;

    // Check if entry already exists (e.g., from a previous DELETE that set data to NULL)
    if (hsearch_r(item, FIND, &found, htable) != 0 && found != NULL)
    {
        // Entry exists - update its data pointer
        found->data = (void *)f;
        return 0;
    }

    // Entry doesn't exist - create new entry
    item.data = (void *)f;

    // DEBUG: Print what we're adding
    fprintf(stderr, "[SS DEBUG] add_struct_to_htable: Adding key='%s' (len=%zu)\n", 
            item.key, strlen(item.key));

    if (hsearch_r(item, ENTER, &found, htable) == 0)
    {
        fprintf(stderr, "Error adding file to hashtable\n");
        return -1;
    }

    // DEBUG: Verify it was added
    if (found && found->key) {
        fprintf(stderr, "[SS DEBUG] add_struct_to_htable: Added successfully, stored key='%s' (len=%zu)\n",
                found->key, strlen(found->key));
    }

    return 0;
}

void *in_htable(const char *filename, struct hsearch_data *htable)
{
    if (!filename || !htable)
    {
        return false;
    }

    ENTRY item;
    ENTRY *found;

    // Trim whitespace from filename and ensure null termination
    // This prevents lookup failures due to trailing spaces
    char trimmed[FILE_NAME_SIZE];
    size_t len = strlen(filename);
    if (len >= FILE_NAME_SIZE) len = FILE_NAME_SIZE - 1;
    
    // Copy and trim trailing whitespace
    strncpy(trimmed, filename, len);
    trimmed[len] = '\0';
    
    // Trim trailing whitespace
    while (len > 0 && (trimmed[len-1] == ' ' || trimmed[len-1] == '\t' || trimmed[len-1] == '\n' || trimmed[len-1] == '\r')) {
        trimmed[--len] = '\0';
    }

    item.key = trimmed;
    item.data = NULL;

    // DEBUG: Print what we're looking for
    fprintf(stderr, "[SS DEBUG] in_htable: Looking for key='%s' (len=%zu, original='%s')\n",
            trimmed, strlen(trimmed), filename);

    if (hsearch_r(item, FIND, &found, htable) == 0 || found == NULL)
    {
        fprintf(stderr, "[SS DEBUG] in_htable: NOT FOUND\n");
        return NULL;
    }

    // DEBUG: Print what we found
    if (found && found->key) {
        fprintf(stderr, "[SS DEBUG] in_htable: FOUND! stored key='%s' (len=%zu)\n",
                found->key, strlen(found->key));
    }

    return found->data;
}

void remove_struct_from_htable(const char *filename, struct hsearch_data *htable)
{
    if (!filename || !htable)
    {
        return;
    }

    ENTRY item;
    ENTRY *found;

    // Trim filename for lookup (same as in_htable)
    char trimmed[FILE_NAME_SIZE];
    size_t len = strlen(filename);
    if (len >= FILE_NAME_SIZE) len = FILE_NAME_SIZE - 1;
    
    strncpy(trimmed, filename, len);
    trimmed[len] = '\0';
    
    // Trim trailing whitespace
    while (len > 0 && (trimmed[len-1] == ' ' || trimmed[len-1] == '\t' || trimmed[len-1] == '\n' || trimmed[len-1] == '\r')) {
        trimmed[--len] = '\0';
    }

    item.key = trimmed;
    item.data = NULL;

    if (hsearch_r(item, FIND, &found, htable) == 0 || found == NULL)
    {
        fprintf(stderr, "File not found in hashtable\n");
        return;  // Early return to avoid segfault
    }

    // Clear the data pointer to mark as removed
    // Note: hsearch_r doesn't have a DELETE operation, so we just clear the data
    found->data = NULL;
}
