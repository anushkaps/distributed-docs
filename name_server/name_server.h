#ifndef NAME_SERVER_H
#define NAME_SERVER_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include "../common.h"

// ======== Constants ========
#define CLIENT_PORT 8080      // Port for client connections
#define SS_PORT     8081      // Port for storage server connections
#define MAX_CLIENTS 20
#define MAX_FILES   200
#define MAX_SS      10

// === Buffer Sizes ===
#define NS_BUFFER_SIZE_4096 4096
#define NS_BUFFER_SIZE_512 512
#define NS_BUFFER_SIZE_256 256
#define NS_BUFFER_SIZE_64 64

// === String Length Constants ===
#define NS_FILENAME_SIZE 256
#define NS_USERNAME_SIZE 64
#define NS_IP_SIZE 32
#define NS_TIMESTAMP_SIZE 64
#define NS_FIRST_MSG_SIZE 256
#define NS_FILE_MSG_SIZE 4096
#define NS_DETAILS_SIZE 256
#define NS_LINE_SIZE 256
#define NS_OUTPUT_SIZE 512

// === Timeout Constants ===
#define NS_REGISTRATION_TIMEOUT_SEC 1
#define NS_REGISTRATION_MAX_TIMEOUTS 10
#define NS_MAIN_THREAD_SLEEP_SEC 1

// === Hash Table and Cache Constants ===
#define NS_FILE_HASH_TABLE_SIZE 1000  // Size of hash table for filename -> SS mapping
#define NS_CACHE_SIZE 20              // LRU cache size (recent lookups)

// ======== Type Definitions ========
typedef struct {
    int fd;
    char ip[32];
    int port;
} storage_server_info;

// Structure for file location mapping (filename -> SS info)
typedef struct {
    char filename[FILE_NAME_SIZE];
    char ss_ip[32];
    int ss_port;
    int ss_index;  // Index in ss_list array
    meta_data *meta;  // File metadata (owner, access control, etc.)
} file_location;

typedef struct {
    char ss_ip[32];
    int ss_port;
    meta_data *meta;
} file_meta;

typedef struct {
    int fd;
    struct sockaddr_in addr;
} client_conn;

// LRU Cache entry for recent file lookups
typedef struct {
    char filename[FILE_NAME_SIZE];
    int ss_index;  // Index in ss_list
    time_t access_time;  // Last access time for LRU eviction
} cache_entry;

// ======== Global Variables (extern declarations) ========
extern file_meta file_table[MAX_FILES];  // Legacy array (kept for compatibility)
extern int file_count;
extern storage_server_info ss_list[MAX_SS];
extern int ss_count;
extern char active_users[MAX_CLIENTS][64];
extern int user_count;
extern pthread_mutex_t lock;

// Efficient data structures for filename -> SS mapping
extern struct hsearch_data *file_location_hash;  // Hash table: filename -> file_location
extern cache_entry file_cache[NS_CACHE_SIZE];     // LRU cache for recent lookups
extern int cache_size;                            // Current number of entries in cache

// ======== Function Declarations ========

// Utility functions
void log_event(const char *msg, const char *user);
void log_request(const char *op, const char *user, const char *ip, int port, const char *details);
void log_response(const char *op, const char *user, const char *ip, int port, const char *status);
void log_exec_command(const char *username, const char *filename, const char *command);

// Command handlers
void handle_view(int fd, Packet p);
void handle_list(int fd);
void handle_info(int fd, Packet p);
int handle_addaccess(Packet p);  // Returns 0 on success, -1 if file not found, -2 if not owner
int handle_remaccess(Packet p);  // Returns 0 on success, -1 if file not found, -2 if not owner
void handle_exec(int fd, Packet p);

// SS forwarding functions
void return_ss_info(int fd, Packet p);
void forward_create_delete(int fd, Packet p);
void forward_to_ss(int fd, Packet p);

// File location lookup functions (using hashtable and cache)
int find_ss_for_file(const char *filename);  // Returns ss_index or -1
int add_file_location(const char *filename, const char *ss_ip, int ss_port, int ss_index, meta_data *meta);
int remove_file_location(const char *filename);
void update_file_location(const char *filename, const char *ss_ip, int ss_port, int ss_index);

// Cache functions
int cache_lookup(const char *filename);  // Returns ss_index from cache or -1
void cache_insert(const char *filename, int ss_index);  // Add/update cache entry

// Helper function to get file metadata
meta_data* get_file_metadata(const char *filename);  // Returns meta_data pointer or NULL

// Helper function to check read access
int user_has_read_access(const char *username, meta_data *meta);  // Returns 1 if user has read access, 0 otherwise

// Client handler
void* client_handler(void *arg);

#endif // NAME_SERVER_H
