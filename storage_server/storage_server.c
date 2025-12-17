/**
 * ============================================================================
 * storage_server.c - Storage Server Main Entry Point
 * ============================================================================
 * 
 * PURPOSE:
 * This is the main entry point for the Storage Server. It initializes the
 * server, sets up the listening socket, and accepts client connections.
 * Each client connection is handled in a separate thread.
 * 
 * ARCHITECTURE:
 * - main(): Entry point, parses arguments, initializes server, accepts connections
 * - server_init(): Initializes data structures and registers with Name Server
 * - client_connection_handler(): Handles each client connection (in separate thread)
 * 
 * SPECIFICATION:
 * - SS takes NS IP and port as command-line arguments
 * - SS listens on a port for client connections
 * - Each client connection runs in a separate thread for concurrency
 * 
 * ============================================================================
 */

#include "storage_server.h"
#include "connection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// Global variable definitions (declared as extern in storage_server.h)
linkedlist_t file_list;
struct hsearch_data *name_to_ptr;
struct hsearch_data *curr_to_prev;
struct hsearch_data *checkpoints;
linkedlist_t access_requests;
queue_t thread_queue;

// External variables
int ss_port;
int ss_client_port;  // Port for client connections (from command line)
char *ss_ip;

// External functions
extern int server_init(const char *ns_ip, int ns_port, int client_port);
extern void *client_connection_handler(void *arg);

// Connection structure for client connections
typedef struct {
    int fd;                      // Socket file descriptor
    struct sockaddr_in addr;     // Client address information
} client_conn_ss;

/**
 * Main entry point for Storage Server
 * 
 * WHAT: Initializes server, listens for client connections, spawns handler threads
 * WHERE: Entry point of the program
 * WHY: Sets up the server infrastructure to handle client requests
 * 
 * @param argc - Number of command-line arguments
 * @param argv - Command-line arguments: [program_name] <ns_ip> <ns_port>
 * @return 0 on success, 1 on failure
 */
int main(int argc, char *argv[])
{
    // Validate command-line arguments
    // SS needs NS IP, NS port, and client port to register itself
    // NOTE: Storage servers should connect to SS_PORT (8081), not CLIENT_PORT
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ns_ip> <ns_port> <client_port>\n", argv[0]);
        fprintf(stderr, "  ns_ip      - IP address of the Name Server\n");
        fprintf(stderr, "  ns_port    - Port number for Storage Server connections (typically 8081)\n");
        fprintf(stderr, "  client_port - Port number for client connections (e.g., 9100, 9101, etc.)\n");
        return 1;
    }

    // Parse and validate NS port number
    errno = 0;
    int ns_port = strtol(argv[2], NULL, 10);
    if (errno != 0 || ns_port < MIN_PORT_NUMBER || ns_port > MAX_PORT_NUMBER) {
        fprintf(stderr, "Invalid NS port number: %s (must be %d-%d)\n", argv[2], MIN_PORT_NUMBER, MAX_PORT_NUMBER);
        return 1;
    }

    // Parse and validate client port number
    errno = 0;
    ss_client_port = strtol(argv[3], NULL, 10);
    if (errno != 0 || ss_client_port < MIN_PORT_NUMBER || ss_client_port > MAX_PORT_NUMBER) {
        fprintf(stderr, "Invalid client port number: %s (must be %d-%d)\n", argv[3], MIN_PORT_NUMBER, MAX_PORT_NUMBER);
        return 1;
    }

    // Get NS IP address from arguments
    char *ns_ip = argv[1];

    // Allocate memory for SS IP string
    // This will be populated during registration
    ss_ip = malloc(INET_ADDRSTRLEN);
    if (!ss_ip) {
        perror("[SS] malloc failed");
        return 1;
    }

    // Initialize Storage Server
    // This sets up data structures, loads existing files, and registers with NS
    if (server_init(ns_ip, ns_port, ss_client_port) != 0) {
        fprintf(stderr, "[SS] Server initialization failed\n");
        free(ss_ip);
        return 1;
    }

    // Create listening socket for client connections
    // SS listens on ss_client_port for client connections
    // Note: ss_port from registration is the ephemeral connection port, not the listening port
    int ss_fd = net_listen(ss_client_port, SS_LISTEN_BACKLOG);
    if (ss_fd < 0) {
        perror("[SS] net_listen failed");
        free(ss_ip);
        return 1;
    }

    printf("[SS] Storage Server listening on port %d\n", ss_client_port);
    printf("[SS] Registered with Name Server at %s:%d\n", ns_ip, ns_port);
    printf("[SS] Ready to accept client connections...\n\n");

    // Main accept loop
    // Continuously accepts new client connections and spawns handler threads
    while (1) {
        // Accept incoming client connection
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(ss_fd, (struct sockaddr *)&client_addr, &addr_len);
        
        if (client_fd < 0) {
            perror("[SS] accept failed");
            continue;  // Continue accepting other connections even if one fails
        }

        // Allocate connection structure for the new client
        // This structure is passed to the handler thread
        client_conn_ss *conn = malloc(sizeof(client_conn_ss));
        if (!conn) {
            perror("[SS] malloc failed");
            close(client_fd);
            continue;
        }
        
        // Store connection information
        conn->fd = client_fd;
        conn->addr = client_addr;

        // Create thread to handle this client connection
        // Each client gets its own thread for concurrent processing
        pthread_t tid;
        if (pthread_create(&tid, NULL, client_connection_handler, (void *)conn) != 0) {
            perror("[SS] pthread_create failed");
            close(client_fd);
            free(conn);
            continue;
        }
        
        // Detach thread so it cleans up automatically when done
        // This prevents thread resource leaks
        pthread_detach(tid);
    }

    // Cleanup (unreachable in normal operation, but good practice)
    net_close(ss_fd);
    free(ss_ip);
    return 0;
}
