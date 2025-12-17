#include "name_server.h"
#include "client_handler.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <search.h>

// ======== Global Variables ========
// Name Server maintains the central file metadata table
// This maps file names to their storage locations and access control information
file_meta file_table[MAX_FILES];
int file_count = 0;

// List of registered Storage Servers
// Storage Servers register with NS upon initialization and can reconnect dynamically
storage_server_info ss_list[MAX_SS];
int ss_count = 0;

// Active users currently connected to the system
// Used for LIST command to show all users in the system
char active_users[MAX_CLIENTS][64];
int user_count = 0;

// Mutex lock for thread-safe access to shared data structures
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

// Efficient data structures for filename -> SS mapping
struct hsearch_data *file_location_hash = NULL;  // Hash table: filename -> file_location
cache_entry file_cache[NS_CACHE_SIZE];           // LRU cache for recent lookups
int cache_size = 0;                               // Current number of entries in cache

// Socket file descriptors for cleanup on exit
static int client_fd_global = -1;
static int ss_fd_global = -1;
static volatile int running = 1;

// ======== Signal Handler ========
// Handles Ctrl+C (SIGINT) and SIGTERM to gracefully shutdown the server
// Closes all sockets and exits cleanly
void cleanup_and_exit(int sig) {
    printf("\n[NS] Received signal %d, shutting down gracefully...\n", sig);
    
    // Close sockets
    if (client_fd_global >= 0) {
        close(client_fd_global);
        printf("[NS] Closed client socket (port %d)\n", CLIENT_PORT);
    }
    if (ss_fd_global >= 0) {
        close(ss_fd_global);
        printf("[NS] Closed storage server socket (port %d)\n", SS_PORT);
    }
    
    printf("[NS] Name Server stopped.\n");
    exit(0);
}

// ======== Main ========
// Name Server initialization and main accept loops
// Acts as the central coordinator: handles client connections and storage server registrations
// Specification: Single instance of NS runs, multiple SS and clients can connect/disconnect
// Uses separate ports: CLIENT_PORT for clients, SS_PORT for storage servers

/**
 * Accept loop for storage server connections
 * Runs in a separate thread to handle SS registrations concurrently
 */
void* ss_accept_loop(void *arg) {
    int ss_fd = *(int*)arg;
    free(arg);
    
    while (running) {
        client_conn *conn = malloc(sizeof(client_conn));
        socklen_t addr_len = sizeof(conn->addr);
        conn->fd = accept(ss_fd, (struct sockaddr*)&conn->addr, &addr_len);
        if (conn->fd < 0) {
            free(conn);
            continue;
        }
        
        // All SS connections go through client_handler
        // Handler identifies them by the "REGISTER SS" message
        pthread_t tid;
        pthread_create(&tid, NULL, client_handler, conn);
        pthread_detach(tid);
    }
    return NULL;
}

/**
 * Accept loop for client connections
 * Runs in a separate thread to handle client requests concurrently
 */
void* client_accept_loop(void *arg) {
    int client_fd = *(int*)arg;
    free(arg);
    
    while (running) {
        client_conn *conn = malloc(sizeof(client_conn));
        socklen_t addr_len = sizeof(conn->addr);
        conn->fd = accept(client_fd, (struct sockaddr*)&conn->addr, &addr_len);
        if (conn->fd < 0) {
            free(conn);
            continue;
        }
        
        // All client connections go through client_handler
        // Handler identifies them by username message format
        pthread_t tid;
        pthread_create(&tid, NULL, client_handler, conn);
        pthread_detach(tid);
    }
    return NULL;
}

int main() {
    // Register signal handlers for graceful shutdown
    signal(SIGINT, cleanup_and_exit);   // Ctrl+C
    // signal(SIGTERM, cleanup_and_exit);  // test script
    
    // Create socket for client connections
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("socket"); exit(1);
    }
    
    // Set SO_REUSEADDR to allow immediate port reuse after restart
    // This fixes "Address already in use" error when restarting quickly
    int opt = 1;
    if (setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR (client)"); exit(1);
    }
    
    struct sockaddr_in client_addr = {0};
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(CLIENT_PORT); //NS client port 8080

    if (bind(client_fd, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
        perror("bind client port"); exit(1);
    }
    
    // Store globally for signal handler
    client_fd_global = client_fd;
    
    // Create socket for storage server connections
    int ss_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ss_fd < 0) {
        perror("socket"); exit(1);
    }
    
    // Set SO_REUSEADDR for SS socket as well
    if (setsockopt(ss_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR (SS)"); exit(1);
    }
    
    struct sockaddr_in ss_addr = {0};
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_addr.s_addr = INADDR_ANY;
    ss_addr.sin_port = htons(SS_PORT);

    if (bind(ss_fd, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) < 0) {
        perror("bind SS port"); exit(1);
    }
    
    // Store globally for signal handler
    ss_fd_global = ss_fd;
    
    // Get server IP address
    char ns_ip[INET_ADDRSTRLEN];
    socklen_t len = sizeof(client_addr);
    getsockname(client_fd, (struct sockaddr*)&client_addr, &len);
    inet_ntop(AF_INET, &client_addr.sin_addr, ns_ip, sizeof(ns_ip));
    
    // Print formatted startup message
    printf("\n"); 
    printf(" Name Server is running at:\n");
    printf("     %s", ns_ip);
    if (strcmp(ns_ip, "0.0.0.0") == 0) {
        printf("  (all interfaces)\n");
    } else {
        printf("\n");
    }
    
    printf("\n Available interfaces:\n");
    system("hostname -I 2>/dev/null || echo '127.0.0.1'");
    
    printf("\n Port Configuration:\n");
    printf("     Client Port: %d\n", CLIENT_PORT);
    printf("     Storage Server Port: %d\n", SS_PORT);
    
    printf("\n Use these ports when starting:\n");
    printf("     ./client <ip> %d\n", CLIENT_PORT);
    printf("     ./storage_server <ip> %d\n", SS_PORT);
    
    // Initialize hash table for efficient file location lookups
    // This enables O(1) filename -> SS mapping instead of O(N) linear search
    file_location_hash = (struct hsearch_data *)malloc(sizeof(struct hsearch_data));
    if (!file_location_hash) {
        perror("[NS] malloc file_location_hash");
        exit(1);
    }
    if (hcreate_r(NS_FILE_HASH_TABLE_SIZE, file_location_hash) == 0) {
        fprintf(stderr, "[NS] Failed to create file location hash table\n");
        free(file_location_hash);
        exit(1);
    }
    
    // Initialize LRU cache for recent file lookups
    // Cache speeds up repeated lookups for the same files
    memset(file_cache, 0, sizeof(file_cache));
    cache_size = 0;
    
    listen(client_fd, MAX_CLIENTS);
    listen(ss_fd, MAX_SS);
    printf("\n[NS] Listening for clients on port %d...\n", CLIENT_PORT);
    printf("[NS] Listening for storage servers on port %d...\n", SS_PORT);
    printf("[NS] File location hash table initialized (size: %d)\n", NS_FILE_HASH_TABLE_SIZE);
    printf("[NS] LRU cache initialized (size: %d)\n", NS_CACHE_SIZE);

    // Start accept loops in separate threads
    // This allows both client and SS connections to be handled concurrently
    pthread_t client_thread, ss_thread;
    
    int *client_fd_ptr = malloc(sizeof(int));
    *client_fd_ptr = client_fd;
    pthread_create(&client_thread, NULL, client_accept_loop, client_fd_ptr);
    pthread_detach(client_thread);
    
    int *ss_fd_ptr = malloc(sizeof(int));
    *ss_fd_ptr = ss_fd;
    pthread_create(&ss_thread, NULL, ss_accept_loop, ss_fd_ptr);
    pthread_detach(ss_thread);
    
    // Main thread waits indefinitely
    // Both accept loops run in background threads
    // Loop until signal handler sets running = 0
    while (running) {
        sleep(NS_MAIN_THREAD_SLEEP_SEC);  // Keep main thread alive
    }
    
    // Cleanup (shouldn't reach here normally, but good practice)
    cleanup_and_exit(0);
    return 0;
}
