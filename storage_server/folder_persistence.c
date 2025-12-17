/**
 * ============================================================================
 * folder_persistence.c - Folder Structure Persistence
 * ============================================================================
 * 
 * PURPOSE:
 * Manages persistence of folder structure to disk
 * Stores folder metadata in a simple JSON-like format for easy parsing
 * 
 * ARCHITECTURE:
 * - save_folders(): Saves folder structure to disk
 * - load_folders(): Loads folder structure from disk on startup
 * 
 * SPECIFICATION:
 * - Folders are stored in folders.dat (simple text format)
 * - Format: "FOLDER|path|creator|created_timestamp\n"
 * - Backward compatible: if file doesn't exist, assume no folders (root only)
 * 
 * ============================================================================
 */

#include "storage_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define FOLDERS_FILE STORAGE_DIRECTORY "/folders.dat"
#define FOLDER_MARKER_PREFIX ".folder_"

/**
 * Save folder structure to disk
 * Scans for folder marker files and writes them to folders.dat
 * 
 * @return 0 on success, -1 on failure
 */
int save_folders(void) {
    FILE *folders_file = fopen(FOLDERS_FILE, "w");
    if (!folders_file) {
        perror("[SS] save_folders: fopen");
        return -1;
    }
    
    // Scan storage directory for folder marker files
    DIR *dir = opendir(STORAGE_DIRECTORY);
    if (!dir) {
        perror("[SS] save_folders: opendir");
        fclose(folders_file);
        return -1;
    }
    
    struct dirent *entry;
    int folder_count = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strncmp(entry->d_name, FOLDER_MARKER_PREFIX, strlen(FOLDER_MARKER_PREFIX)) == 0) {
            // This is a folder marker file
            char marker_path[FILEPATH_SIZE];
            snprintf(marker_path, sizeof(marker_path), STORAGE_DIRECTORY "/%s", entry->d_name);
            
            FILE *marker = fopen(marker_path, "r");
            if (marker) {
                char line[FILEPATH_SIZE];
                if (fgets(line, sizeof(line), marker)) {
                    // Write folder info to folders.dat
                    fprintf(folders_file, "%s", line);
                    folder_count++;
                }
                fclose(marker);
            }
        }
    }
    
    closedir(dir);
    fclose(folders_file);
    
    printf("[SS] Saved %d folders to %s\n", folder_count, FOLDERS_FILE);
    return 0;
}

/**
 * Load folder structure from disk
 * Reads folders.dat and recreates folder marker files
 * 
 * @return 0 on success, -1 on failure (non-fatal - file may not exist)
 */
int load_folders(void) {
    FILE *folders_file = fopen(FOLDERS_FILE, "r");
    if (!folders_file) {
        // File doesn't exist - this is OK (backward compatibility)
        // No folders exist yet, only root "/"
        return 0;
    }
    
    char line[FILEPATH_SIZE];
    int folder_count = 0;
    
    while (fgets(line, sizeof(line), folders_file)) {
        // Parse: "FOLDER|path|creator|created_timestamp\n"
        if (strncmp(line, "FOLDER|", 7) == 0) {
            char *fields = line + 7;  // Skip "FOLDER|"
            char *saveptr;
            char *path = strtok_r(fields, "|", &saveptr);
            char *creator = strtok_r(NULL, "|", &saveptr);
            char *timestamp_str = strtok_r(NULL, "|\n", &saveptr);
            
            if (path && creator && timestamp_str) {
                // Recreate folder marker file
                char marker_path[FILEPATH_SIZE];
                snprintf(marker_path, sizeof(marker_path), STORAGE_DIRECTORY "/.folder_%s", path);
                // Replace "/" with "_" in filename
                for (char *c = marker_path; *c; c++) {
                    if (*c == '/') *c = '_';
                }
                
                FILE *marker = fopen(marker_path, "w");
                if (marker) {
                    fprintf(marker, "FOLDER|%s|%s|%s\n", path, creator, timestamp_str);
                    fclose(marker);
                    folder_count++;
                }
            }
        }
    }
    
    fclose(folders_file);
    printf("[SS] Loaded %d folders from %s\n", folder_count, FOLDERS_FILE);
    return 0;
}

