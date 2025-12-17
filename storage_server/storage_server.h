#ifndef STORAGE_SERVER_H
#define STORAGE_SERVER_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <search.h>
#include <pthread.h>
#include <stdbool.h>
#include "../linkedlist.h"
#include "queue.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "../common.h"
#include "connection.h"
#include <dirent.h>
#include <arpa/inet.h>

// Manager for tracking locks held by a single client thread to prevent deadlocks
typedef struct {
    linkedlist_t *held_sentence_locks; // list of sentence* that are locked
} thread_lock_manager_t;

// Structure to hold a word update during WRITE operation
// Used for queuing word updates before applying them atomically
typedef struct {
    int word_index;
    char *content;
} word_update_t;

#define MAGIC "FOSN"
#define SS_CLIENT_PORT 9090

// === Buffer Sizes ===
#define BUFFER_SIZE_2048 2048
#define BUFFER_SIZE_4096 4096
#define BUFFER_SIZE_512 512
#define BUFFER_SIZE_256 256
#define BUFFER_SIZE_128 128
#define BUFFER_SIZE_64 64
#define BUFFER_SIZE_8192 8192

// === Timeout Constants ===
#define STREAM_WORD_DELAY_US 100000  // 0.1 seconds in microseconds
#define SS_REGISTRATION_TIMEOUT_SEC 1
#define SS_REGISTRATION_MAX_TIMEOUTS 10

// === File System Constants ===
#define STORAGE_DIRECTORY "./storage_current"
#define SS_INFO_FILENAME "storage_server_info.txt"
#define DIRECTORY_PERMISSIONS 0755

// === Network Constants ===
#define SS_LISTEN_BACKLOG 100000

// === String Length Constants ===
#define USERNAME_SIZE 64
#define TIMESTAMP_SIZE 64
#define DETAILS_BUFFER_SIZE 512
#define FILEPATH_SIZE 512
#define RESPONSE_BUFFER_SIZE 256

// === Hash Table Constants ===
#define HASH_TABLE_SIZE 1000  // Size of hash table for file lookups

typedef struct sentence
{
    pthread_mutex_t wrt;
    linkedlist_t *data;
} sentence;

typedef struct file
{
    pthread_mutex_t mutex;
    pthread_rwlock_t rwlock;
    unsigned long readcount;
    unsigned long writecount;
    meta_data *info;
    linkedlist_t *data;
} file;

struct list_entry{
    char filename[FILE_NAME_SIZE];
    meta_data *info;
};

extern linkedlist_t file_list;
extern struct hsearch_data *name_to_ptr;
extern struct hsearch_data *curr_to_prev;
extern struct hsearch_data *checkpoints; // hashtable mapping "filename|checkpoint_name" to checkpoint file struct ptr

typedef struct {
    char checkpoint_name[256];
    char filename[FILE_NAME_SIZE];
    time_t created;
    char created_by[FILE_NAME_SIZE];
} checkpoint_meta;

// Access request structure
typedef struct {
    char filename[FILE_NAME_SIZE];
    char requester[FILE_NAME_SIZE];
    time_t requested_at;
    int access_type; // ACCESS_READ or ACCESS_WRITE
} access_request;

extern linkedlist_t access_requests; // global list of pending access requests
extern queue_t thread_queue;


int struct_to_file(file *f);  // Saves to disk, removes from hash table, and frees structure
int save_file_to_disk(file *f);  // Saves to disk without removing/freeing (for active files)
file *file_to_struct(const char *filename);

void free_file(file *f);
file *create_file_struct(const char *filename);

char *read_file(const char *filename, struct hsearch_data *name_to_ptr); // Read file
char *read_file_for_exec(const char *filename, struct hsearch_data *name_to_ptr); // Read file with newlines between sentences (for EXEC)
int write_file(const char *filename, int sentence_index, int word_index, const char *data, struct hsearch_data *name_to_ptr); // write file
int finalize_write_atomic(const char *filename, struct hsearch_data *name_to_ptr); // finalize write with atomic swap file mechanism
int apply_queued_updates(file *f, int sentence_index, linkedlist_t *updates); // Apply all queued word updates as one operation (sentence must be locked by caller)
int view_all_files(int client_fd, char* user, mode_t mode); //Read Folder
int printf_additional_file_info(int client_fd, file* f);
bool check_access(const char* user, file* f, int access_type);  // access_type: ACCESS_READ or ACCESS_WRITE
int add_access(const char* user, file *f, int access_type);  // access_type: ACCESS_READ or ACCESS_WRITE (W grants R automatically)
int remove_access(const char* user, file *f);
void update_last_access(const char* user, file* f);  // Update last access time for user

int init_struct_table(struct hsearch_data *htable, size_t size);
int add_struct_to_htable(file *f, struct hsearch_data *htable);
void *in_htable(const char *filename, struct hsearch_data *htable);
void remove_struct_from_htable(const char *filename, struct hsearch_data *htable);

int create_checkpoint(const char *filename, const char *checkpoint_name, const char *username, struct hsearch_data *name_to_ptr);
int list_checkpoints(const char *filename, int client_fd);
int view_checkpoint(const char *filename, const char *checkpoint_name, int client_fd);
int revert_to_checkpoint(const char *filename, const char *checkpoint_name, const char *username, struct hsearch_data *name_to_ptr);
int save_undo_state(const char *filename);  // Save current file state before write (for undo)
int undo_last_change(const char *filename);
int delete_file(const char *filename);

int request_access(const char *filename, const char *requester, int access_type);
int view_requests(const char *filename, const char *owner, int client_fd);
int approve_request(const char *filename, const char *requester, const char *owner);
int reject_request(const char *filename, const char *requester);
int save_access_requests_for_file(const char *filename);
int load_access_requests_for_file(const char *filename);

// Logging functions (logging.c)
void log_request_ss(const char *op, const char *user, const char *ip, int port, const char *details);
void log_response_ss(const char *op, const char *user, const char *ip, int port, const char *status);
void log_file_operation_ss(const char *event_type, const char *filename, const char *user, const char *details);

// Name Server registration (ns_registration.c)
int register_with_ns(const char *ns_ip, int ns_port, int client_port, char *filepath);
int server_init(const char *ns_ip, int ns_port, int client_port);

// Client connection handler (client_handler_ss.c)
void *client_connection_handler(void *arg);

// Command handlers (command_handlers_ss.c)
void handle_read_command(int client_fd, Packet *p, const char *username, 
                         const char *client_ip, int client_port, const char *op_name);
void handle_create_command(int client_fd, Packet *p, const char *username,
                           const char *client_ip, int client_port, const char *op_name);
void handle_write_command(int client_fd, Packet *p, const char *username,
                          const char *client_ip, int client_port, const char *op_name,
                          thread_lock_manager_t *lock_manager);
void handle_undo_command(int client_fd, Packet *p, const char *username,
                          const char *client_ip, int client_port, const char *op_name);
void handle_info_command(int client_fd, Packet *p, const char *username,
                         const char *client_ip, int client_port, const char *op_name);
void handle_delete_command(int client_fd, Packet *p, const char *username,
                            const char *client_ip, int client_port, const char *op_name);
void handle_stream_command(int client_fd, Packet *p, const char *username,
                            const char *client_ip, int client_port, const char *op_name);
void handle_addaccess_command(int client_fd, Packet *p, const char *username,
                               const char *client_ip, int client_port, const char *op_name);
void handle_remaccess_command(int client_fd, Packet *p, const char *username,
                               const char *client_ip, int client_port, const char *op_name);
void handle_exec_command_ss(int client_fd, Packet *p, const char *username,
                            const char *client_ip, int client_port, const char *op_name);
void handle_checkpoint_command(int client_fd, Packet *p, const char *username,
                                const char *client_ip, int client_port, const char *op_name);
void handle_listcheckpoints_command(int client_fd, Packet *p, const char *username,
                                     const char *client_ip, int client_port, const char *op_name);
void handle_viewcheckpoint_command(int client_fd, Packet *p, const char *username,
                                    const char *client_ip, int client_port, const char *op_name);
void handle_revert_command(int client_fd, Packet *p, const char *username,
                            const char *client_ip, int client_port, const char *op_name);
void handle_requestaccess_command(int client_fd, Packet *p, const char *username,
                                   const char *client_ip, int client_port, const char *op_name);
void handle_viewrequests_command(int client_fd, Packet *p, const char *username,
                                  const char *client_ip, int client_port, const char *op_name);
void handle_approve_command(int client_fd, Packet *p, const char *username,
                             const char *client_ip, int client_port, const char *op_name);
void handle_reject_command(int client_fd, Packet *p, const char *username,
                           const char *client_ip, int client_port, const char *op_name);
void handle_createfolder_command(int client_fd, Packet *p, const char *username,
                                 const char *client_ip, int client_port, const char *op_name);
void handle_move_command(int client_fd, Packet *p, const char *username,
                        const char *client_ip, int client_port, const char *op_name);

#endif // STORAGE_SERVER_H
