#include "storage_server.h"

int view_all_files(int client_fd, char* user, mode_t mode)
{
    bool show_all = false;
    bool show_details = false;
    
    // Parse mode flags according to common.h definitions:
    // VIEW_USER_ONLY = 0 (default: show only user's files)
    // VIEW_ALL = 1 (-a: show all files)
    // VIEW_LONG = 2 (-l: show user's files with details)
    // VIEW_ALL_LONG = 3 (-al: show all files with details)
    if (mode == VIEW_ALL || mode == VIEW_ALL_LONG) show_all = true;  // -a or -al
    if (mode == VIEW_LONG || mode == VIEW_ALL_LONG) show_details = true;  // -l or -al
    
    // Debug: Count files in list
    int total_files = 0;
    for (node_t *debug = file_list.head; debug != NULL; debug = debug->next) {
        total_files++;
    }
    fprintf(stderr, "[SS DEBUG] view_all_files: file_list.size=%zu, actual nodes=%d, user='%s', show_all=%d\n",
            file_list.size, total_files, user, show_all);
    
    int file_count = 0;
    
    // Print header if detailed mode
    if (show_details) {
        dprintf(client_fd, "---------------------------------------------------------\n");
        dprintf(client_fd, "|  Filename  | Words | Chars | Last Access Time | Owner |\n");
        dprintf(client_fd, "|------------|-------|-------|------------------|-------|\n");
    }
    
    // Track filenames we've already seen to avoid duplicates
    char seen_filenames[1000][FILE_NAME_SIZE];
    int seen_count = 0;
    
    for (node_t *current = file_list.head; current != NULL; current = current->next)
    {
        file *f = (file *)current->data;
        
        // Skip if file structure or metadata is invalid
        if (!f || !f->info) {
            fprintf(stderr, "[SS DEBUG] view_all_files: Skipping invalid entry (f=%p, info=%p)\n", f, f ? f->info : NULL);
            continue;
        }
        
        // Skip if filename is empty or invalid (garbage entries)
        // Also skip undo files (they should never be in file_list)
        if (strlen(f->info->filename) == 0 || f->info->filename[0] == '\0') {
            fprintf(stderr, "[SS DEBUG] view_all_files: Skipping entry with empty filename\n");
            continue;
        }
        
        // Skip undo files - they should only be in curr_to_prev hash table, not file_list
        size_t name_len = strlen(f->info->filename);
        if (name_len > 5 && strcmp(f->info->filename + name_len - 5, ".undo") == 0) {
            fprintf(stderr, "[SS DEBUG] view_all_files: Skipping undo file entry\n");
            continue;
        }
        
        // Skip if we've already seen this filename (handle duplicates)
        int already_seen = 0;
        for (int i = 0; i < seen_count; i++) {
            if (strcmp(seen_filenames[i], f->info->filename) == 0) {
                already_seen = 1;
                break;
            }
        }
        if (already_seen) {
            continue;
        }
        
        // Add to seen list
        if (seen_count < 1000) {
            strncpy(seen_filenames[seen_count], f->info->filename, FILE_NAME_SIZE - 1);
            seen_filenames[seen_count][FILE_NAME_SIZE - 1] = '\0';
            seen_count++;
        }
        
        fprintf(stderr, "[SS DEBUG] view_all_files: Processing file='%s', owner='%s'\n", 
                f->info->filename, f->info->owner);

        // Filter by access if not showing all
        // Check if user is owner or has access
        bool has_access = false;
        if (strcmp(f->info->owner, user) == 0) {
            has_access = true;
        } else if (f->info->users_with_access) {
            node_t *ua_current = f->info->users_with_access->head;
            while (ua_current) {
                user_access *ua = (user_access *)ua_current->data;
                if (ua && strcmp(ua->username, user) == 0) {
                    has_access = true;
                    break;
                }
                ua_current = ua_current->next;
            }
        }
        if (!show_all && !has_access) {
            continue;
        }

        if (show_details) {
            // Detailed view with table
            char time_str[64];
            // Use last_accessed time as per requirements (shows "Last Access Time")
            time_t access_time = f->info->last_accessed > 0 ? f->info->last_accessed : f->info->modified;
            struct tm *tm_info = localtime(&access_time);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", tm_info);
            
            dprintf(client_fd, "| %-10s | %5zu | %5zu | %16s | %-5s |\n",
                    f->info->filename,
                    f->info->wordcount,
                    f->info->charcount,
                    time_str,
                    f->info->owner);
        } else {
            // Simple list
            dprintf(client_fd, "--> %s\n", f->info->filename);
        }
        file_count++;
    }
    
    if (show_details && file_count > 0) {
        dprintf(client_fd, "---------------------------------------------------------\n");
    }

    return 0;
}

int printf_additional_file_info(int client_fd, file* f)
{
    // Note: struct_to_file is not needed here unless saving changes
    dprintf(client_fd, "--> File: %s\n", f->info->filename);
    
    FILE * file = fopen(f->info->filename, "rb");
    if (file == NULL)
    {
        return -1;
    }
    fseek(file, 0, SEEK_END);
    size_t sz = ftell(file);
    fseek(file, 0, SEEK_SET);
    fclose(file);
    
    char time_str[64];
    struct tm *tm_info;
    
    tm_info = localtime(&f->info->created);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", tm_info);
    dprintf(client_fd, "--> Created: %s\n", time_str);
    
    tm_info = localtime(&f->info->modified);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", tm_info);
    dprintf(client_fd, "--> Last Modified: %s\n", time_str);
    
    dprintf(client_fd, "--> Owner: %s\n", f->info->owner);
    dprintf(client_fd, "--> Size: %zu bytes\n", sz);
    dprintf(client_fd, "--> Word Count: %zu\n", f->info->wordcount);
    dprintf(client_fd, "--> Character Count: %zu\n", f->info->charcount);
    dprintf(client_fd, "--> Last Modified By: %s\n", f->info->lastmodifiedby);
    
    dprintf(client_fd, "--> Access: ");
    bool first = true;
    // Owner always has RW access
    dprintf(client_fd, "%s (RW)", f->info->owner);
    first = false;
    
    // List other users with access and their access types
    if (f->info->users_with_access) {
        for (node_t *current = f->info->users_with_access->head; current != NULL; current = current->next)
        {
            user_access *ua = (user_access *)current->data;
            if (ua && strcmp(ua->username, f->info->owner) != 0) {
                if (!first) dprintf(client_fd, ", ");
                const char *access_str = (ua->access_type == ACCESS_WRITE) ? "RW" : "R";
                dprintf(client_fd, "%s (%s)", ua->username, access_str);
                
                // Show last access time if available
                if (ua->last_access > 0) {
                    char time_str[64];
                    struct tm *tm_info = localtime(&ua->last_access);
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", tm_info);
                    dprintf(client_fd, " [last: %s]", time_str);
                }
                first = false;
            }
        }
    }
    dprintf(client_fd, "\n");
    
    return 0;
}