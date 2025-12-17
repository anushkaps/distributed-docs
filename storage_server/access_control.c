#include "../storage_server/storage_server.h"
#include <time.h>

// Helper function to find user access entry
static user_access* find_user_access(const char* user, file* f) {
    if (!f || !f->info->users_with_access || !user) {
        return NULL;
    }
    
    node_t *current = f->info->users_with_access->head;
    while (current) {
        user_access *ua = (user_access*)current->data;
        if (ua && strcmp(ua->username, user) == 0) {
            return ua;
        }
        current = current->next;
    }
    return NULL;
}

// Check if user has the required access type
// access_type: ACCESS_READ (0) or ACCESS_WRITE (1)
// Returns true if user has access, false otherwise
// Owner always has both read and write access
bool check_access(const char* user, file* f, int access_type)
{
    if (!user || !f) { return false;}

    // Owner always has both read and write access
    if (strcmp(f->info->owner, user) == 0) {
        return true;
    }
    
    // Find user access entry
    user_access *ua = find_user_access(user, f);
    if (!ua) {
        return false;
    }
    
    // Check access type
    if (access_type == ACCESS_READ) {
        // Read access: user needs at least read access (R or W)
        return (ua->access_type == ACCESS_READ || ua->access_type == ACCESS_WRITE);
    } else if (access_type == ACCESS_WRITE) {
        // Write access: user needs write access
        return (ua->access_type == ACCESS_WRITE);
    }
    
    return false;
}

// Add access for a user with specified type
// If access_type is ACCESS_WRITE, it automatically grants read access too
// If user already exists, update their access type (upgrade if needed)
// Returns: 0 = success (new access), 1 = user already has access, -1 = error, -2 = user is owner
int add_access(const char* user, file *f, int access_type)
{
    if (!user || !f) {
        return -1;
    }
    
    // Check if user is the owner - owners already have all access
    if (strcmp(f->info->owner, user) == 0) {
        return -2;  // User is owner
    }
    
    // Find existing user access
    user_access *ua = find_user_access(user, f);
    
    if (ua) {
        // User already has access - update it
        // If granting write access, upgrade from read to write
        if (access_type == ACCESS_WRITE && ua->access_type == ACCESS_READ) {
            ua->access_type = ACCESS_WRITE;  // Upgrade from read to write
            return 0;  // Success - access upgraded
        }
        // If user already has write access, no change needed
        // If granting read access and user already has write, keep write
        // (write access is already better than read)
        return 1;  // User already has access (no upgrade needed)
    }
    
    // Create new user access entry
    user_access *new_ua = (user_access*)malloc(sizeof(user_access));
    if (!new_ua) {
        return -1;
    }
    
    strncpy(new_ua->username, user, FILE_NAME_SIZE - 1);
    new_ua->username[FILE_NAME_SIZE - 1] = '\0';
    new_ua->access_type = access_type;
    new_ua->last_access = 0;  // Will be set on first access
    
    insert_at_n(f->info->users_with_access, new_ua, f->info->users_with_access->size);
    return 0;  // Success - new access granted
}

// Remove access for a user
int remove_access(const char* user, file *f)
{
    if (!user || !f || !f->info->users_with_access) { return -1;}
    
    node_t *current = f->info->users_with_access->head;
    size_t idx = 0;
    while (current) {
        user_access *ua = (user_access*)current->data;
        if (ua && strcmp(ua->username, user) == 0) {
            // Found user - remove from list
            remove_at_n(f->info->users_with_access, idx);
            free(ua);
            return 0;
        }
        current = current->next;
        idx++;
    }
    
    return 0;  // User not found, but that's okay
}

// Update last access time for a user
void update_last_access(const char* user, file* f) {
    if (!user || !f) {
        return;
    }
    
    time_t now = time(NULL);
    
    // Update user-specific last access time
    user_access *ua = find_user_access(user, f);
    if (ua) {
        ua->last_access = now;
    }
    
    // Also update file-level last_accessed time (most recent access by any user)
    f->info->last_accessed = now;
}

bool is_user_owner(char* user, file* f)
{
    if (!user || !f) {
        return false;
    }
    if (strcmp(f->info->owner, user) == 0)
    {
        return true;
    }
    return false;
}