#include "storage_server.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>

int request_access(const char *filename, const char *requester, int access_type) {
    if (!filename || !requester) return -1;
    
    // Check if request already exists
    node_t *current = access_requests.head;
    while (current) {
        access_request *req = (access_request *)current->data;
        if (strcmp(req->filename, filename) == 0 && 
            strcmp(req->requester, requester) == 0) {
            return 0; // Request already exists
        }
        current = current->next;
    }
    
    // Create new request
    access_request *req = (access_request *)malloc(sizeof(access_request));
    if (!req) return -1;
    
    strncpy(req->filename, filename, FILE_NAME_SIZE);
    strncpy(req->requester, requester, FILE_NAME_SIZE);
    req->requested_at = time(NULL);
    req->access_type = access_type;
    
    insert_at_n(&access_requests, req, access_requests.size);
    return 0;
}

int view_requests(const char *filename, const char *owner, int client_fd) {
    if (!filename || !owner) return -1;
    
    // Verify user is owner
    file *f = in_htable(filename, name_to_ptr);
    if (!f || strcmp(f->info->owner, owner) != 0) {
        dprintf(client_fd, "[SS] Access denied: Not the owner of %s\n", filename);
        return -1;
    }
    
    dprintf(client_fd, "[SS] Pending access requests for %s:\n", filename);
    int count = 0;
    
    node_t *current = access_requests.head;
    while (current) {
        access_request *req = (access_request *)current->data;
        if (strcmp(req->filename, filename) == 0) {
            count++;
            char ts[64];
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&req->requested_at));
            const char *access_str = (req->access_type == ACCESS_READ) ? "READ" : "WRITE";
            dprintf(client_fd, "  %d. User: %s | Type: %s | Requested: %s\n", 
                    count, req->requester, access_str, ts);
        }
        current = current->next;
    }
    
    if (count == 0) {
        dprintf(client_fd, "  No pending requests.\n");
    }
    
    return 0;
}

int approve_request(const char *filename, const char *requester, const char *owner) {
    if (!filename || !requester || !owner) return -1;
    
    // Verify user is owner
    file *f = in_htable(filename, name_to_ptr);
    if (!f || strcmp(f->info->owner, owner) != 0) return -1;
    
    // Find and remove request
    node_t *current = access_requests.head;
    size_t idx = 0;
    while (current) {
        access_request *req = (access_request *)current->data;
        if (strcmp(req->filename, filename) == 0 && 
            strcmp(req->requester, requester) == 0) {
            // Grant access with the requested access type
            add_access(requester, f, req->access_type);
            // Grant access
            char *user_copy = strdup(requester);
            if (user_copy) {
                insert_at_n(f->info->users_with_access, user_copy, f->info->users_with_access->size);
            }
            
            // Remove request
            remove_at_n(&access_requests, idx);
            free(req);
            return 0;
        }
        current = current->next;
        idx++;
    }
    
    return -1; // Request not found
}

int reject_request(const char *filename, const char *requester) {
    if (!filename || !requester) return -1;
    
    // Find and remove request
    node_t *current = access_requests.head;
    size_t idx = 0;
    while (current) {
        access_request *req = (access_request *)current->data;
        if (strcmp(req->filename, filename) == 0 && 
            strcmp(req->requester, requester) == 0) {
            remove_at_n(&access_requests, idx);
            free(req);
            return 0;
        }
        current = current->next;
        idx++;
    }
    
    return -1; // Request not found
}

