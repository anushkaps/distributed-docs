/**
 * ============================================================================
 * folder_handlers.c - Folder Command Handlers for Storage Server
 * ============================================================================
 * 
 * PURPOSE:
 * Handles CREATEFOLDER and MOVE commands for folder management
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
extern int save_file_to_disk(file *f);
extern void *in_htable(const char *filename, struct hsearch_data *htable);
extern int save_folders(void);

/**
 * Handle CREATEFOLDER command - Create a new folder
 */
void handle_createfolder_command(int client_fd, Packet *p, const char *username,
                                 const char *client_ip, int client_port, const char *op_name)
{
    // Normalize folder path - must start with "/"
    char folder_path[FILE_NAME_SIZE];
    if (p->filename[0] == '/') {
        strncpy(folder_path, p->filename, FILE_NAME_SIZE - 1);
        folder_path[FILE_NAME_SIZE - 1] = '\0';
    } else {
        snprintf(folder_path, sizeof(folder_path), "/%s", p->filename);
    }
    
    // Trim trailing whitespace
    size_t folder_len = strlen(folder_path);
    while (folder_len > 0 && (folder_path[folder_len-1] == ' ' || 
                              folder_path[folder_len-1] == '\t' || 
                              folder_path[folder_len-1] == '\n' || 
                              folder_path[folder_len-1] == '\r')) {
        folder_path[--folder_len] = '\0';
    }
    
    // Validate folder name
    if (strlen(folder_path) <= 1 || strcmp(folder_path, "/") == 0) {
        dprintf(client_fd, "[SS] ERROR: Invalid folder name. Error code: %d - %s\n",
                ERR_INVALID_FOLDER_NAME, get_error_message(ERR_INVALID_FOLDER_NAME));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Invalid folder name");
        return;
    }
    
    // Check if folder already exists by checking if any file is in this folder
    // For simplicity, we'll use a file-based approach: create a marker file
    char folder_marker[FILEPATH_SIZE];
    snprintf(folder_marker, sizeof(folder_marker), STORAGE_DIRECTORY "/.folder_%s", folder_path);
    // Replace "/" with "_" in filename to avoid filesystem issues
    for (char *c = folder_marker; *c; c++) {
        if (*c == '/') *c = '_';
    }
    
    // Check if folder marker exists
    FILE *marker = fopen(folder_marker, "r");
    if (marker) {
        fclose(marker);
        dprintf(client_fd, "[SS] ERROR: Folder already exists. Error code: %d - %s\n",
                ERR_FOLDER_ALREADY_EXISTS, get_error_message(ERR_FOLDER_ALREADY_EXISTS));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Folder exists");
        return;
    }
    
    // Create folder marker file
    marker = fopen(folder_marker, "w");
    if (!marker) {
        dprintf(client_fd, "[SS] ERROR: Failed to create folder. Error code: %d - %s\n",
                ERR_FOLDER_CREATE_FAILED, get_error_message(ERR_FOLDER_CREATE_FAILED));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Create error");
        return;
    }
    
    // Write folder metadata to marker file
    fprintf(marker, "FOLDER|%s|%s|%ld\n", folder_path, username, (long)time(NULL));
    fclose(marker);
    
    // Save folder structure to persistence file
    save_folders();
    
    dprintf(client_fd, "[SS] Folder created successfully.\n");
    send(client_fd, "[SS] ACK: Folder created successfully.\n", 38, 0);
    send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
    log_response_ss(op_name, username, client_ip, client_port, "OK");
    log_file_operation_ss("CREATEFOLDER", folder_path, username, "Folder created");
}

/**
 * Handle MOVE command - Move file to a different folder
 */
void handle_move_command(int client_fd, Packet *p, const char *username,
                        const char *client_ip, int client_port, const char *op_name)
{
    // Look up file
    extern struct hsearch_data *name_to_ptr;
    file *f = in_htable(p->filename, name_to_ptr);
    if (!f) {
        dprintf(client_fd, "[SS] ERROR: File not found. Error code: %d - %s\n",
                ERR_FILE_NOT_FOUND, get_error_message(ERR_FILE_NOT_FOUND));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: File not found");
        return;
    }
    
    // Check if user is owner (only owner can move files)
    if (strcmp(f->info->owner, username) != 0) {
        dprintf(client_fd, "[SS] ERROR: Not file owner. Error code: %d - %s\n",
                ERR_NOT_OWNER, get_error_message(ERR_NOT_OWNER));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Not owner");
        return;
    }
    
    // Normalize target folder path
    char target_folder[FILE_NAME_SIZE];
    if (p->payload[0] == '/') {
        strncpy(target_folder, p->payload, FILE_NAME_SIZE - 1);
        target_folder[FILE_NAME_SIZE - 1] = '\0';
    } else {
        snprintf(target_folder, sizeof(target_folder), "/%s", p->payload);
    }
    
    // Trim trailing whitespace
    size_t folder_len = strlen(target_folder);
    while (folder_len > 0 && (target_folder[folder_len-1] == ' ' || 
                              target_folder[folder_len-1] == '\t' || 
                              target_folder[folder_len-1] == '\n' || 
                              target_folder[folder_len-1] == '\r')) {
        target_folder[--folder_len] = '\0';
    }
    
    // Validate target folder
    if (strlen(target_folder) <= 1) {
        strncpy(target_folder, "/", FILE_NAME_SIZE - 1);
        target_folder[FILE_NAME_SIZE - 1] = '\0';
    }
    
    // Check if moving to the same folder
    if (strcmp(f->info->folder, target_folder) == 0) {
        dprintf(client_fd, "[SS] ERROR: Cannot move to the same folder. Error code: %d - %s\n",
                ERR_CANNOT_MOVE_TO_SAME_FOLDER, get_error_message(ERR_CANNOT_MOVE_TO_SAME_FOLDER));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Same folder");
        return;
    }
    
    // Update folder in file metadata
    strncpy(f->info->folder, target_folder, FILE_NAME_SIZE - 1);
    f->info->folder[FILE_NAME_SIZE - 1] = '\0';
    
    // Update modified time
    f->info->modified = time(NULL);
    strncpy(f->info->lastmodifiedby, username, FILE_NAME_SIZE - 1);
    f->info->lastmodifiedby[FILE_NAME_SIZE - 1] = '\0';
    
    // Persist changes to disk
    if (save_file_to_disk(f) != 0) {
        dprintf(client_fd, "[SS] ERROR: Failed to save file changes. Error code: %d - %s\n",
                ERR_DATA_PERSISTENCE_FAILED, get_error_message(ERR_DATA_PERSISTENCE_FAILED));
        send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
        log_response_ss(op_name, username, client_ip, client_port, "FAILED: Save error");
        return;
    }
    
    dprintf(client_fd, "[SS] File moved successfully.\n");
    send(client_fd, "[SS] ACK: File moved successfully.\n", 36, 0);
    send(client_fd, PROTOCOL_STOP, PROTOCOL_STOP_LEN, 0);
    log_response_ss(op_name, username, client_ip, client_port, "OK");
    log_file_operation_ss("MOVE", p->filename, username, "Moved to folder");
}

