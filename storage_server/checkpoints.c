#include "storage_server.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Helper: allocate a checkpoint key string (caller must free) */
static char* alloc_checkpoint_key(const char *filename, const char *checkpoint_name) {
    if (!filename || !checkpoint_name) return NULL;
    size_t need = strlen(filename) + 1 + strlen(checkpoint_name) + 1;
    char *key = malloc(need);
    if (!key) return NULL;
    snprintf(key, need, "%s|%s", filename, checkpoint_name);
    return key;
}

/* Helper: build checkpoint filename into provided buffer */
static void make_checkpoint_filename(const char *filename, const char *checkpoint_name, char *out, size_t outsz) {
    snprintf(out, outsz, "%s.checkpoint.%s", filename, checkpoint_name);
}

/* Helper: try to load checkpoint from hashtable, otherwise from disk */
static file* load_checkpoint(const char *filename, const char *checkpoint_name) {
    if (!filename || !checkpoint_name) return NULL;

    char keybuf[512];
    snprintf(keybuf, sizeof(keybuf), "%s|%s", filename, checkpoint_name);
    ENTRY e, *ep;
    e.key = keybuf;
    e.data = NULL;
    hsearch_r(e, FIND, &ep, checkpoints);
    if (ep) return (file *)ep->data;

    char checkpoint_filename[512];
    make_checkpoint_filename(filename, checkpoint_name, checkpoint_filename, sizeof(checkpoint_filename));
    return file_to_struct(checkpoint_filename);
}

/* Helper: persist a file struct to a specific filename on disk (temporarily set filename) */
static int save_struct_to_filename(file *f, const char *checkpoint_filename) {
    if (!f || !checkpoint_filename) return -1;
    char original_filename[FILE_NAME_SIZE];
    strncpy(original_filename, f->info->filename, sizeof(original_filename));
    strncpy((char*)f->info->filename, checkpoint_filename, FILE_NAME_SIZE);
    struct_to_file(f);
    strncpy((char*)f->info->filename, original_filename, FILE_NAME_SIZE);
    return 0;
}

/* Helper: flatten file struct content into a buffer */
static void file_struct_to_content(file *f, char *out, size_t outsz) {
    if (!f || !out || outsz == 0) return;
    size_t pos = 0;
    node_t *sent_node = f->data ? f->data->head : NULL;
    bool first_sentence = true;
    while (sent_node && pos < outsz - 1) {
        sentence *s = (sentence *)sent_node->data;
        if (!first_sentence && pos < outsz - 1) out[pos++] = ' ';
        first_sentence = false;
        node_t *word_node = s->data ? s->data->head : NULL;
        bool first_word = true;
        while (word_node && pos < outsz - 1) {
            char *word = (char *)word_node->data;
            if (!first_word && pos < outsz - 1) out[pos++] = ' ';
            first_word = false;
            size_t word_len = strlen(word);
            if (pos + word_len < outsz - 1) {
                strncpy(out + pos, word, word_len);
                pos += word_len;
            }
            word_node = word_node->next;
        }
        sent_node = sent_node->next;
    }
    out[pos] = '\0';
}

// Deep copy a file structure for checkpoint
static file* copy_file_struct(file *src) {
    if (!src) return NULL;
    
    file *dest = create_file_struct(src->info->filename);
    if (!dest) return NULL;
    
    // Copy metadata
    memcpy(dest->info, src->info, sizeof(meta_data));
    
    // Copy users_with_access
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
    
    // Copy sentences
    current = src->data->head;
    while (current) {
        sentence *src_s = (sentence *)current->data;
        sentence *dest_s = (sentence *)malloc(sizeof(sentence));
        if (!dest_s) {
            free_file(dest);
            return NULL;
        }
        pthread_mutex_init(&dest_s->wrt, NULL);
        dest_s->data = (linkedlist_t *)malloc(sizeof(linkedlist_t));
        if (!dest_s->data) {
            free(dest_s);
            free_file(dest);
            return NULL;
        }
        init_linkedlist(dest_s->data);
        
        // Copy words
        node_t *word_node = src_s->data->head;
        while (word_node) {
            char *word = (char *)word_node->data;
            char *word_copy = strdup(word);
            if (word_copy) {
                insert_at_n(dest_s->data, word_copy, dest_s->data->size);
            }
            word_node = word_node->next;
        }
        
        insert_at_n(dest->data, dest_s, dest->data->size);
        current = current->next;
    }
    
    return dest;
}

int create_checkpoint(const char *filename, const char *checkpoint_name, const char *username, struct hsearch_data *name_to_ptr) {
    if (!filename || !checkpoint_name || !username) return -1;
    
    file *f = in_htable(filename, name_to_ptr);
    if (!f) return -1;
    
    // Create a deep copy of the file
    file *checkpoint_copy = copy_file_struct(f);
    if (!checkpoint_copy) return -1;
    
    /* store checkpoint in hashtable (key owned by hashtable on success) */
    char *key = alloc_checkpoint_key(filename, checkpoint_name);
    if (!key) {
        free_file(checkpoint_copy);
        return -1;
    }
    ENTRY e, *ep;
    e.key = key;
    e.data = checkpoint_copy;
    if (hsearch_r(e, ENTER, &ep, checkpoints) == 0) {
        free_file(checkpoint_copy);
        free(key);
        return -1;
    }

    /* persist checkpoint on disk */
    char checkpoint_filename[512];
    make_checkpoint_filename(filename, checkpoint_name, checkpoint_filename, sizeof(checkpoint_filename));
    save_struct_to_filename(checkpoint_copy, checkpoint_filename);
    return 0;
}

int list_checkpoints(const char *filename, int client_fd) {
    if (!filename) return -1;
    
    // Search for all checkpoints for this file
    // Since we can't iterate hashtable easily, we'll use a different approach
    // For now, check disk for checkpoint files
    char pattern[512];
    snprintf(pattern, sizeof(pattern), "%s.checkpoint.*", filename);
    
    dprintf(client_fd, "[SS] Checkpoints for %s:\n", filename);
    dprintf(client_fd, "Note: Use VIEWCHECKPOINT <filename> <checkpoint_name> to view a checkpoint\n");
    
    // Try to find checkpoint files on disk
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ls -1 %s.checkpoint.* 2>/dev/null | sed 's/.*checkpoint\\.//'", filename);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\r\n")] = 0;
            if (strlen(line) > 0) {
                dprintf(client_fd, "  - %s\n", line);
            }
        }
        pclose(fp);
    }
    
    return 0;
}

int view_checkpoint(const char *filename, const char *checkpoint_name, int client_fd) {
    if (!filename || !checkpoint_name) return -1;
    file *checkpoint = load_checkpoint(filename, checkpoint_name);
    if (!checkpoint) {
        dprintf(client_fd, "[SS] Checkpoint '%s' not found.\n", checkpoint_name);
        return -1;
    }

    char content[8192] = {0};
    file_struct_to_content(checkpoint, content, sizeof(content));
    dprintf(client_fd, "[SS] Checkpoint '%s' content:\n%s\n", checkpoint_name, content);
    return 0;
}

int revert_to_checkpoint(const char *filename, const char *checkpoint_name, const char *username, struct hsearch_data *name_to_ptr) {
    if (!filename || !checkpoint_name || !username) return -1;
    
    file *f = in_htable(filename, name_to_ptr);
    if (!f) return -1;
    
    // Check if user is owner
    if (strcmp(f->info->owner, username) != 0) return -1;
    
    file *checkpoint = load_checkpoint(filename, checkpoint_name);
    if (!checkpoint) return -1;
    
    // Save current version as previous (for undo)
    file *current = in_htable(filename, name_to_ptr);
    if (current) {
        ENTRY prev_e, *prev_ep;
        prev_e.key = strdup(filename);
        prev_e.data = current;
        hsearch_r(prev_e, ENTER, &prev_ep, curr_to_prev);
    }
    
    // Create a copy of checkpoint and restore
    file *restored = copy_file_struct(checkpoint);
    if (!restored) return -1;
    
    // Update filename in restored copy
    strncpy((char*)restored->info->filename, filename, FILE_NAME_SIZE);
    restored->info->modified = time(NULL);
    strncpy(restored->info->lastmodifiedby, username, FILE_NAME_SIZE);
    
    // Remove old file from hashtable and replace
    remove_struct_from_htable(filename, name_to_ptr);
    free_file(current);
    
    add_struct_to_htable(restored, name_to_ptr);
    struct_to_file(restored);
    
    return 0;
}

