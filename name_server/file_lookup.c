/**
 * ============================================================================
 * file_lookup.c - Efficient File Location Lookup with Hash Table and LRU Cache
 * ============================================================================
 * 
 * PURPOSE:
 * Implements efficient O(1) filename -> Storage Server mapping using a hash table
 * and LRU cache for recent lookups to meet the "Efficient Search + caching" requirement.
 * 
 * ARCHITECTURE:
 * - Hash table (hsearch_r): Primary storage for filename -> SS mapping
 * - LRU cache: Fast lookup for recently accessed files
 * - Lookup flow: Check cache first, then hash table, update cache on hit
 * 
 * SPECIFICATION:
 * - Name Server must implement efficient search (faster than O(N))
 * - Caching should be implemented for recent searches
 * - Supports multiple Storage Servers with files distributed across them
 * 
 * ============================================================================
 */

#include "name_server.h"
#include <search.h>
#include <string.h>
#include <time.h>

/**
 * Lookup filename in LRU cache
 * Returns ss_index if found, -1 otherwise
 */
int cache_lookup(const char *filename) {
    if (!filename) return -1;
    
    pthread_mutex_lock(&lock);
    time_t now = time(NULL);
    
    // Search cache for filename
    for (int i = 0; i < cache_size; i++) {
        if (strcmp(file_cache[i].filename, filename) == 0) {
            // Cache hit - update access time and return
            file_cache[i].access_time = now;
            int ss_index = file_cache[i].ss_index;
            pthread_mutex_unlock(&lock);
            return ss_index;
        }
    }
    
    pthread_mutex_unlock(&lock);
    return -1;  // Cache miss
}

/**
 * Insert or update entry in LRU cache
 * If cache is full, evict least recently used entry
 */
void cache_insert(const char *filename, int ss_index) {
    if (!filename || ss_index < 0) return;
    
    pthread_mutex_lock(&lock);
    time_t now = time(NULL);
    
    // Check if entry already exists in cache
    for (int i = 0; i < cache_size; i++) {
        if (strcmp(file_cache[i].filename, filename) == 0) {
            // Update existing entry
            file_cache[i].ss_index = ss_index;
            file_cache[i].access_time = now;
            pthread_mutex_unlock(&lock);
            return;
        }
    }
    
    // Entry doesn't exist - add new entry
    if (cache_size < NS_CACHE_SIZE) {
        // Cache has space - add to end
        strncpy(file_cache[cache_size].filename, filename, FILE_NAME_SIZE - 1);
        file_cache[cache_size].filename[FILE_NAME_SIZE - 1] = '\0';
        file_cache[cache_size].ss_index = ss_index;
        file_cache[cache_size].access_time = now;
        cache_size++;
    } else {
        // Cache is full - find LRU entry and replace it
        int lru_index = 0;
        time_t oldest_time = file_cache[0].access_time;
        for (int i = 1; i < NS_CACHE_SIZE; i++) {
            if (file_cache[i].access_time < oldest_time) {
                oldest_time = file_cache[i].access_time;
                lru_index = i;
            }
        }
        // Replace LRU entry
        strncpy(file_cache[lru_index].filename, filename, FILE_NAME_SIZE - 1);
        file_cache[lru_index].filename[FILE_NAME_SIZE - 1] = '\0';
        file_cache[lru_index].ss_index = ss_index;
        file_cache[lru_index].access_time = now;
    }
    
    pthread_mutex_unlock(&lock);
}

/**
 * Find Storage Server index for a given filename
 * Uses cache first, then hash table lookup
 * Returns ss_index or -1 if not found
 */
int find_ss_for_file(const char *filename) {
    if (!filename || !file_location_hash) return -1;
    
    // First check cache (fast path)
    int cached_index = cache_lookup(filename);
    if (cached_index >= 0) {
        return cached_index;  // Cache hit
    }
    
    // Cache miss - lookup in hash table
    pthread_mutex_lock(&lock);
    
    ENTRY e, *ep;
    e.key = (char *)filename;
    e.data = NULL;
    
    if (hsearch_r(e, FIND, &ep, file_location_hash) == 0 || ep == NULL) {
        pthread_mutex_unlock(&lock);
        return -1;  // Not found in hash table
    }
    
    // Found in hash table - check if data is valid (not NULL)
    // This can happen if file was deleted (remove_file_location sets ep->data = NULL)
    if (ep->data == NULL) {
        pthread_mutex_unlock(&lock);
        return -1;  // Entry exists but data was freed (file deleted)
    }
    
    // Found in hash table
    file_location *loc = (file_location *)ep->data;
    int ss_index = loc->ss_index;
    
    pthread_mutex_unlock(&lock);
    
    // Update cache for future lookups
    cache_insert(filename, ss_index);
    
    return ss_index;
}

/**
 * Add file location mapping to hash table
 * Creates entry mapping filename -> SS info
 */
int add_file_location(const char *filename, const char *ss_ip, int ss_port, int ss_index, meta_data *meta) {
    if (!filename || !ss_ip || !file_location_hash || ss_index < 0) return -1;
    
    pthread_mutex_lock(&lock);
    
    // Check if entry already exists
    ENTRY e, *ep;
    e.key = (char *)filename;
    e.data = NULL;
    if (hsearch_r(e, FIND, &ep, file_location_hash) != 0 && ep != NULL) {
        // Entry exists - check if data is NULL (was deleted)
        if (ep->data != NULL) {
            // Entry exists with valid data - update it
            file_location *loc = (file_location *)ep->data;
            strncpy(loc->ss_ip, ss_ip, sizeof(loc->ss_ip) - 1);
            loc->ss_ip[sizeof(loc->ss_ip) - 1] = '\0';
            loc->ss_port = ss_port;
            loc->ss_index = ss_index;
            loc->meta = meta;
            pthread_mutex_unlock(&lock);
            /* Keep cache in sync with updated location */
            cache_insert(filename, ss_index);
            return 0;
        }
        // Entry exists but data is NULL (was deleted) - create new structure
        file_location *loc = (file_location *)malloc(sizeof(file_location));
        if (!loc) {
            pthread_mutex_unlock(&lock);
            return -1;
        }
        
        strncpy(loc->filename, filename, FILE_NAME_SIZE - 1);
        loc->filename[FILE_NAME_SIZE - 1] = '\0';
        strncpy(loc->ss_ip, ss_ip, sizeof(loc->ss_ip) - 1);
        loc->ss_ip[sizeof(loc->ss_ip) - 1] = '\0';
        loc->ss_port = ss_port;
        loc->ss_index = ss_index;
        loc->meta = meta;
        
        // Set data pointer directly (entry already exists in hash table)
        ep->data = loc;
        pthread_mutex_unlock(&lock);
        /* Update cache for faster subsequent lookups */
        cache_insert(filename, ss_index);
        return 0;
    }
    
    // Create new entry (entry doesn't exist in hash table)
    file_location *loc = (file_location *)malloc(sizeof(file_location));
    if (!loc) {
        pthread_mutex_unlock(&lock);
        return -1;
    }
    
    strncpy(loc->filename, filename, FILE_NAME_SIZE - 1);
    loc->filename[FILE_NAME_SIZE - 1] = '\0';
    strncpy(loc->ss_ip, ss_ip, sizeof(loc->ss_ip) - 1);
    loc->ss_ip[sizeof(loc->ss_ip) - 1] = '\0';
    loc->ss_port = ss_port;
    loc->ss_index = ss_index;
    loc->meta = meta;
    
    // Add to hash table
    e.key = strdup(filename);
    e.data = loc;
    if (hsearch_r(e, ENTER, &ep, file_location_hash) == 0) {
        free(loc);
        free(e.key);
        pthread_mutex_unlock(&lock);
        return -1;
    }
    
    pthread_mutex_unlock(&lock);
    /* Update cache for faster subsequent lookups */
    cache_insert(filename, ss_index);
    return 0;
}

/**
 * Remove file location mapping from hash table
 */
int remove_file_location(const char *filename) {
    if (!filename || !file_location_hash) return -1;
    
    pthread_mutex_lock(&lock);
    
    ENTRY e, *ep;
    e.key = (char *)filename;
    e.data = NULL;
    
    if (hsearch_r(e, FIND, &ep, file_location_hash) == 0 || ep == NULL) {
        pthread_mutex_unlock(&lock);
        return -1;  // Not found
    }
    
    // Free the file_location structure
    file_location *loc = (file_location *)ep->data;
    if (loc) {
        // Free metadata if it exists
        if (loc->meta) {
            if (loc->meta->users_with_access) {
                node_t *ua_node = loc->meta->users_with_access->head;
                while (ua_node) {
                    free(ua_node->data);
                    ua_node = ua_node->next;
                }
                free(loc->meta->users_with_access);
            }
            free(loc->meta);
        }
        free(loc);
    }
    
    // Remove from hash table: clear data pointer (mark as deleted)
    // NOTE: Do NOT free ep->key - it's managed by the hash table internally
    // The hash table will handle key cleanup when the table is destroyed
    ep->data = NULL;
    
    // Also remove from cache if present
    for (int i = 0; i < cache_size; i++) {
        if (strcmp(file_cache[i].filename, filename) == 0) {
            // Shift remaining entries
            for (int j = i; j < cache_size - 1; j++) {
                file_cache[j] = file_cache[j + 1];
            }
            cache_size--;
            break;
        }
    }
    
    pthread_mutex_unlock(&lock);
    return 0;
}

/**
 * Update file location mapping (e.g., when SS reconnects)
 */
void update_file_location(const char *filename, const char *ss_ip, int ss_port, int ss_index) {
    if (!filename || !ss_ip || !file_location_hash) return;
    
    pthread_mutex_lock(&lock);
    
    ENTRY e, *ep;
    e.key = (char *)filename;
    e.data = NULL;
    
    if (hsearch_r(e, FIND, &ep, file_location_hash) != 0 && ep != NULL && ep->data != NULL) {
        file_location *loc = (file_location *)ep->data;
        if (loc) {
            strncpy(loc->ss_ip, ss_ip, sizeof(loc->ss_ip) - 1);
            loc->ss_ip[sizeof(loc->ss_ip) - 1] = '\0';
            loc->ss_port = ss_port;
            loc->ss_index = ss_index;
            
            // Update cache if present
            cache_insert(filename, ss_index);
        }
    }
    
    pthread_mutex_unlock(&lock);
}

/**
 * Get file metadata from hash table
 * Returns meta_data pointer or NULL if not found
 */
meta_data* get_file_metadata(const char *filename) {
    if (!filename || !file_location_hash) return NULL;
    
    pthread_mutex_lock(&lock);
    
    ENTRY e, *ep;
    e.key = (char *)filename;
    e.data = NULL;
    
    if (hsearch_r(e, FIND, &ep, file_location_hash) == 0 || ep == NULL) {
        pthread_mutex_unlock(&lock);
        return NULL;
    }
    
    // Check if data is valid (not NULL) - can happen if file was deleted
    if (ep->data == NULL) {
        pthread_mutex_unlock(&lock);
        return NULL;  // Entry exists but data was freed (file deleted)
    }
    
    file_location *loc = (file_location *)ep->data;
    meta_data *meta = loc ? loc->meta : NULL;
    
    pthread_mutex_unlock(&lock);
    return meta;
}

