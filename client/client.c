#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  // For strcasecmp, strncasecmp
#include <unistd.h>
#include <fcntl.h>    // For fcntl, O_NONBLOCK
#include <sys/time.h> // For struct timeval
#include <sys/socket.h> // For setsockopt
#include <arpa/inet.h>
#include <errno.h>
#include "../common.h"
#include "client.h"

// ======== Helper Functions ========
// Client helper functions for communicating with Name Server and Storage Servers
// Specification: Client initiates communication with NS, which routes requests appropriately

// Get Storage Server info from Name Server
// Specification: For READ/WRITE/STREAM operations, NS returns SS IP:port for direct connection
// Returns 0 on success, -1 on failure
// On success, ss_ip and ss_port are populated
int get_ss_info(int ns_sock, char *ss_ip, int *ss_port) {
    char ss_info[CLIENT_SS_INFO_SIZE];
    int n = recv(ns_sock, ss_info, sizeof(ss_info)-1, 0);
    if (n <= 0) {
        printf("[Client] Failed to get SS info from NS.\n");
        return -1;
    }
    ss_info[n] = 0;
    
    // Parse SS info: "SS_INFO|ip|port"
    if (strncmp(ss_info, PROTOCOL_SS_INFO_PREFIX, PROTOCOL_SS_INFO_PREFIX_LEN) != 0) {
        // This is an error message, print it with newline (preserve original formatting)
        printf("%s", ss_info);
        // Ensure newline if message doesn't end with one
        if (n > 0 && ss_info[n-1] != '\n') {
            printf("\n");
        }
        return -1;
    }
    
    // For valid SS_INFO, strip newline for parsing
    ss_info[strcspn(ss_info, "\n")] = 0;
    
    if (sscanf(ss_info, "SS_INFO|%[^|]|%d", ss_ip, ss_port) != 2) {
        printf("[Client] Invalid SS info format.\n");
        return -1;
    }
    return 0;
}

// Connect to Storage Server and send username
// Specification: Client establishes direct connection with SS for READ/WRITE/STREAM operations
// Username is sent first for access control on SS side
// Returns socket fd on success, or -1 on failure
int connect_to_ss(const char *ss_ip, int ss_port, const char *username) {
    int ss_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (ss_sock < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_in ss_addr = {0};
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(ss_port);
    inet_pton(AF_INET, ss_ip, &ss_addr.sin_addr);
    
    if (connect(ss_sock, (struct sockaddr*)&ss_addr, sizeof(ss_addr)) < 0) {
        printf("[Client] Could not connect to SS %s:%d\n", ss_ip, ss_port);
        close(ss_sock);
        return -1;
    }
    
    // Send username followed by newline (SS expects username\n)
    send(ss_sock, username, strlen(username), 0);
    send(ss_sock, "\n", 1, 0);
    return ss_sock;
}

// Receive data from Storage Server until STOP packet is received
// Specification: Client continuously receives information packets from SS until "STOP" packet
// This is the protocol for READ, STREAM, and other direct SS operations
// Handles SS disconnection mid-stream with clear error message
void receive_until_stop(int ss_sock) {
    char data[CLIENT_BUFFER_SIZE_4096];
    int n;
    int stop_received = 0;
    
    while (!stop_received) {
        n = recv(ss_sock, data, sizeof(data)-1, 0);
        
        if (n < 0) {
            // Error receiving data (connection error)
            printf("\n[Client] ERROR: Connection error while receiving data from Storage Server. Error code: %d - %s\n", 
                    ERR_CONNECTION_LOST, get_error_message(ERR_CONNECTION_LOST));
            printf("[Client] The Storage Server may have gone down mid-operation.\n");
            break;
        } else if (n == 0) {
            // Connection closed by SS (SS went down mid-stream)
            printf("\n[Client] ERROR: Storage Server connection closed unexpectedly. Error code: %d - %s\n", 
                    ERR_CONNECTION_LOST, get_error_message(ERR_CONNECTION_LOST));
            printf("[Client] The Storage Server may have gone down mid-operation.\n");
            break;
        }
        
        // Null-terminate received data
        data[n] = 0;
        
        // Check if STOP is in the received data (might be combined with content)
        char *stop_pos = strstr(data, PROTOCOL_STOP);
        if (stop_pos) {
            // Print content before STOP
            size_t content_len = stop_pos - data;
            if (content_len > 0) {
                // Temporarily null-terminate at STOP position to print only content
                char saved = *stop_pos;
                *stop_pos = '\0';
                printf("%s", data);
                fflush(stdout);
                *stop_pos = saved;  // Restore (though we're breaking anyway)
            }
            stop_received = 1;
            break;  // Found STOP, exit loop
        }
        
        // No STOP found, print all data
        printf("%s", data);
        fflush(stdout);
    }
}

// Receive data from Name Server until STOP packet is received
void receive_from_ns_until_stop(int ns_sock) {
    char data[CLIENT_BUFFER_SIZE_4096];
    int n;
    int stop_received = 0;
    
    while (!stop_received) {
        n = recv(ns_sock, data, sizeof(data)-1, 0);
        
        if (n < 0) {
            // Error receiving data (connection error)
            printf("\n[Client] ERROR: Connection error while receiving data from Name Server. Error code: %d - %s\n", 
                    ERR_CONNECTION_LOST, get_error_message(ERR_CONNECTION_LOST));
            break;
        } else if (n == 0) {
            // Connection closed by NS
            printf("\n[Client] ERROR: Name Server connection closed unexpectedly. Error code: %d - %s\n", 
                    ERR_CONNECTION_LOST, get_error_message(ERR_CONNECTION_LOST));
            break;
        }
        
        // Null-terminate received data
        data[n] = 0;
        
        // Check if STOP is in the received data (might be combined with content)
        char *stop_pos = strstr(data, PROTOCOL_STOP);
        if (stop_pos) {
            // Print content before STOP
            size_t content_len = stop_pos - data;
            if (content_len > 0) {
                // Temporarily null-terminate at STOP position to print only content
                char saved = *stop_pos;
                *stop_pos = '\0';
                printf("%s", data);
                fflush(stdout);
                *stop_pos = saved;  // Restore (though we're breaking anyway)
            }
            stop_received = 1;
            break;  // Found STOP, exit loop
        }
        
        // No STOP found, print all data
        printf("%s", data);
        fflush(stdout);
    }
}

// Handle direct SS operation (READ, STREAM)
// Specification: For READ/WRITE/STREAM, NS returns SS info and client connects directly
// Protocol: Client sends request to NS -> NS returns SS IP:port -> Client connects to SS
void handle_direct_ss_operation(int ns_sock, Packet *p, const char *username) {
    // Step 1: Send request to Name Server
    send(ns_sock, p, sizeof(*p), 0);
    
    // Step 2: Get Storage Server info from NS
    char ss_ip[INET_ADDRSTRLEN];
    int ss_port;
    if (get_ss_info(ns_sock, ss_ip, &ss_port) != 0) {
        return;
    }
    
    // Step 3: Connect directly to Storage Server
    int ss_sock = connect_to_ss(ss_ip, ss_port, username);
    if (ss_sock < 0) {
        return;
    }
    
    // Step 4: Send operation packet to SS
    send(ss_sock, p, sizeof(*p), 0);
    
    // Step 5: Receive data until STOP packet
    receive_until_stop(ss_sock);
    
    close(ss_sock);
}

// Handle WRITE operation (special case with multiple packets)
// Specification: WRITE operation consists of multiple packets:
// - First packet: sentence_index (in flag1)
// - Subsequent packets: word_index (in flag2) and content (in payload)
// - Final packet: "ETIRW" to signal end of write operation and release sentence lock
void handle_write_operation(int ns_sock, Packet *p, const char *username, char *buffer) {
    // Step 1: Send request to Name Server
    send(ns_sock, p, sizeof(*p), 0);
    
    // Step 2: Get Storage Server info from NS
    char ss_ip[INET_ADDRSTRLEN];
    int ss_port;
    if (get_ss_info(ns_sock, ss_ip, &ss_port) != 0) {
        return;
    }
    
    // Step 3: Connect directly to Storage Server
    int ss_sock = connect_to_ss(ss_ip, ss_port, username);
    if (ss_sock < 0) {
        return;
    }
    
    // Step 4: Send first packet with sentence_index in flag1
    send(ss_sock, p, sizeof(*p), 0);
    
    // Step 5: Get write data from user (multiple word updates)
    // Specification: User can update multiple words in a single WRITE operation
    // All updates are considered a single operation (for UNDO purposes)
    printf("Enter <word_index> <content> lines (type ETIRW to finish):\n");
    while (1) {
        printf("> ");
        fflush(stdout);
        if (!fgets(buffer, BUF_SIZE, stdin)) break;
        buffer[strcspn(buffer, "\n")] = 0;
        if (strcasecmp(buffer, PROTOCOL_ETIRW) == 0) {
            // Send ETIRW to signal end of write operation
            strcpy(p->payload, PROTOCOL_ETIRW);
            send(ss_sock, p, sizeof(*p), 0);
            break;
        }
        // Parse word_index and content, send as packet
        if (sscanf(buffer, "%d %[^\n]", &p->flag2, p->payload) == 2) {
            send(ss_sock, p, sizeof(*p), 0);
        } else {
            printf("Invalid format. Use: <word_index> <content>\n");
        }
    }
    
    // Step 6: Receive response until STOP packet
    receive_until_stop(ss_sock);
    
    close(ss_sock);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        fprintf(stderr, "  server_ip   - IP address of the Name Server\n");
        fprintf(stderr, "  server_port - Port number for Client connections (typically 8080)\n");
        exit(1);
    }

    char *server_ip = argv[1];

    char* pEND = NULL;
    errno = 0;
    long lport = strtol(argv[2], &pEND, 10);
    if (errno != 0 || *pEND != '\0' || lport < MIN_PORT_NUMBER || lport > MAX_PORT_NUMBER) {
        fprintf(stderr, "Invalid port number: %s (must be %d-%d)\n", argv[2], MIN_PORT_NUMBER, MAX_PORT_NUMBER);
        exit(1);
    }
    int port = (int) lport;

    // Client initialization: Ask for username
    // Specification: Client asks user for username on bootup
    // Username is used for all file access control operations
    // Username is relayed to NS, which stores it until client disconnects
    char username[CLIENT_USERNAME_SIZE];
    printf("Enter your username: ");
    fflush(stdout);
    if (!fgets(username, sizeof(username), stdin)) {
        fprintf(stderr, "Failed to read username\n");
        exit(1);
    }
    username[strcspn(username, "\n")] = '\0'; // Remove newline
    // Trim leading and trailing whitespace
    char *start = username;
    while (*start == ' ' || *start == '\t' || *start == '\r') start++;
    char *end = username + strlen(username) - 1;
    while (end >= username && (*end == ' ' || *end == '\t' || *end == '\r')) end--;
    *(end + 1) = '\0';
    if (start != username) {
        memmove(username, start, strlen(start) + 1);
    }
    if (strlen(username) == 0) {
        fprintf(stderr, "Username cannot be empty\n");
        exit(1);
    }

    int sock;
    struct sockaddr_in serv_addr;
    char input[BUF_SIZE], buffer[BUF_SIZE];
    Packet p;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(1); }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(port);
    inet_pton(AF_INET, server_ip, &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect"); exit(1);
    }

    // Get client's local IP and port
    struct sockaddr_in local_addr;
    socklen_t len = sizeof(local_addr);
    getsockname(sock, (struct sockaddr*)&local_addr, &len);
    char local_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, INET_ADDRSTRLEN);
    int local_port = ntohs(local_addr.sin_port);

    // Send username, IP, and port on connect (format: "username|ip|port")
    char client_info[CLIENT_BUFFER_SIZE_256];
    snprintf(client_info, sizeof(client_info), "%s|%s|%d", username, local_ip, local_port);
    send(sock, client_info, strlen(client_info), 0);
    printf("Connected to Name Server %s:%d as '%s' (from %s:%d)\n", server_ip, port, username, local_ip, local_port);
    printf("Type commands (VIEW, READ, CREATE, WRITE, etc.) or QUIT to exit.\n\n");

    while (1) {
        printf("> ");
        fflush(stdout);
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = 0;
        if (strcasecmp(input, "QUIT") == 0) break;

        memset(&p, 0, sizeof(p));
        strcpy(p.username, username);

        // ---------- VIEW ----------
        if (strncasecmp(input, "VIEW", 4) == 0) {
            p.opcode = CMD_VIEW;
            int mode = VIEW_USER_ONLY;
            // Check for combined flag first (-al or -la), then individual flags
            // This handles both "view -al" and "view -a -l" formats
            if (strstr(input, "-al") || strstr(input, "-la") || 
                (strstr(input, "-a") && strstr(input, "-l"))) {
                mode = VIEW_ALL_LONG;
            } else if (strstr(input, "-a")) {
                mode = VIEW_ALL;
            } else if (strstr(input, "-l")) {
                mode = VIEW_LONG;
            }
            p.flag1 = mode;
        }

        // ---------- READ ----------
        else if (strncasecmp(input, "READ", 4) == 0) {
            p.opcode = CMD_READ;
            sscanf(input, "%*s %255s", p.filename);
            handle_direct_ss_operation(sock, &p, username);
            continue;
        }

        // ---------- CREATE ----------
        else if (strncasecmp(input, "CREATE", 6) == 0) {
            p.opcode = CMD_CREATE;
            sscanf(input, "%*s %255s", p.filename);
        }

        // ---------- WRITE ----------
        else if (strncasecmp(input, "WRITE", 5) == 0) {
            p.opcode = CMD_WRITE;
            sscanf(input, "%*s %255s %d", p.filename, &p.flag1);
            handle_write_operation(sock, &p, username, buffer);
            continue;
        }

        // ---------- UNDO ----------
        else if (strncasecmp(input, "UNDO", 4) == 0) {
            p.opcode = CMD_UNDO;
            sscanf(input, "%*s %255s", p.filename);
        }

        // ---------- INFO ----------
        else if (strncasecmp(input, "INFO", 4) == 0) {
            p.opcode = CMD_INFO;
            sscanf(input, "%*s %255s", p.filename);
            send(sock, &p, sizeof(p), 0);
            receive_from_ns_until_stop(sock);
            continue;
        }

        // ---------- DELETE ----------
        else if (strncasecmp(input, "DELETE", 6) == 0) {
            p.opcode = CMD_DELETE;
            sscanf(input, "%*s %255s", p.filename);
        }

        // ---------- STREAM ----------
        else if (strncasecmp(input, "STREAM", 6) == 0) {
            p.opcode = CMD_STREAM;
            sscanf(input, "%*s %255s", p.filename);
            handle_direct_ss_operation(sock, &p, username);
            continue;
        }

        // ---------- LIST ----------
        else if (strncasecmp(input, "LIST", 4) == 0) {
            p.opcode = CMD_LIST;
        }

        // ---------- ADDACCESS ----------
        else if (strncasecmp(input, "ADDACCESS", 9) == 0) {
            p.opcode = CMD_ADDACCESS;
            // Parse: ADDACCESS -R <filename> <username> or ADDACCESS -W <filename> <username>
            char flag[10];
            if (sscanf(input, "%*s %9s %255s %1023s", flag, p.filename, p.payload) == 3) {
                if (strcmp(flag, "-R") == 0) {
                    p.flag1 = ACCESS_READ;
                } else if (strcmp(flag, "-W") == 0) {
                    p.flag1 = ACCESS_WRITE;
                } else {
                    printf("Invalid flag. Use -R or -W.\n");
                    continue;
                }
            } else {
                printf("Invalid format. Use: ADDACCESS -R <filename> <username> or ADDACCESS -W <filename> <username>\n");
                continue;
            }
        }

        // ---------- REMACCESS ----------
        else if (strncasecmp(input, "REMACCESS", 9) == 0) {
            p.opcode = CMD_REMACCESS;
            // Parse: REMACCESS <filename> <username> or REMACCESS -R/-W <filename> <username>
            char flag[10], filename[FILE_NAME_SIZE], username_payload[FILE_NAME_SIZE];
            if (sscanf(input, "%*s %9s %255s %255s", flag, filename, username_payload) == 3) {
                // Check if first token is a flag (-R or -W)
                if (strcmp(flag, "-R") == 0 || strcmp(flag, "-W") == 0) {
                    // Flag present: REMACCESS -R/-W <filename> <username>
                    strncpy(p.filename, filename, FILE_NAME_SIZE - 1);
                    p.filename[FILE_NAME_SIZE - 1] = '\0';
                    strncpy(p.payload, username_payload, FILE_NAME_SIZE - 1);
                    p.payload[FILE_NAME_SIZE - 1] = '\0';
                } else {
                    // No flag: REMACCESS <filename> <username> <extra>
                    // flag is actually filename, filename is username
                    strncpy(p.filename, flag, FILE_NAME_SIZE - 1);
                    p.filename[FILE_NAME_SIZE - 1] = '\0';
                    strncpy(p.payload, filename, FILE_NAME_SIZE - 1);
                    p.payload[FILE_NAME_SIZE - 1] = '\0';
                }
            } else if (sscanf(input, "%*s %255s %1023s", p.filename, p.payload) == 2) {
                // Standard format: REMACCESS <filename> <username>
            } else {
                printf("Invalid format. Use: REMACCESS <filename> <username>\n");
                continue;
            }
        }

        // ---------- EXEC ----------
        else if (strncasecmp(input, "EXEC", 4) == 0) {
            p.opcode = CMD_EXEC;
            sscanf(input, "%*s %255s", p.filename);
        }

        // ---------- CHECKPOINT ----------
        else if (strncasecmp(input, "CHECKPOINT", 10) == 0) {
            p.opcode = CMD_CHECKPOINT;
            sscanf(input, "%*s %255s %1023s", p.filename, p.payload);
        }

        // ---------- LISTCHECKPOINTS ----------
        else if (strncasecmp(input, "LISTCHECKPOINTS", 15) == 0) {
            p.opcode = CMD_LISTCHECKPOINTS;
            sscanf(input, "%*s %255s", p.filename);
        }

        // ---------- VIEWCHECKPOINT ----------
        else if (strncasecmp(input, "VIEWCHECKPOINT", 14) == 0) {
            p.opcode = CMD_VIEWCHECKPOINT;
            sscanf(input, "%*s %255s %1023s", p.filename, p.payload);
        }

        // ---------- REVERT ----------
        else if (strncasecmp(input, "REVERT", 6) == 0) {
            p.opcode = CMD_REVERT;
            sscanf(input, "%*s %255s %1023s", p.filename, p.payload);
        }

        // ---------- REQUESTACCESS ----------
        else if (strncasecmp(input, "REQUESTACCESS", 13) == 0) {
            p.opcode = CMD_REQUESTACCESS;
            if (strstr(input, "-R")) p.flag1 = ACCESS_READ;
            else if (strstr(input, "-W")) p.flag1 = ACCESS_WRITE;
            sscanf(input, "%*s %*s %255s", p.filename);
        }

        // ---------- VIEWREQUESTS ----------
        else if (strncasecmp(input, "VIEWREQUESTS", 12) == 0) {
            p.opcode = CMD_VIEWREQUESTS;
            sscanf(input, "%*s %255s", p.filename);
        }

        // ---------- APPROVE ----------
        else if (strncasecmp(input, "APPROVE", 7) == 0) {
            p.opcode = CMD_APPROVE;
            sscanf(input, "%*s %255s %1023s", p.filename, p.payload);
        }

        // ---------- REJECT ----------
        else if (strncasecmp(input, "REJECT", 6) == 0) {
            p.opcode = CMD_REJECT;
            sscanf(input, "%*s %255s %1023s", p.filename, p.payload);
        }

        else {
            printf("Unknown command.\n");
            continue;
        }

        // send structured packet
        send(sock, &p, sizeof(p), 0);

        // receive response - read all available data
        // Some responses may be multi-line (INFO, VIEW, etc.), so we need to read until no more data
        memset(buffer, 0, sizeof(buffer));
        int total_received = 0;
        int n;
        
        // For EXEC command, read continuously until connection closes or timeout
        // EXEC streams output as commands execute, so we need to read continuously
        if (p.opcode == CMD_EXEC) {
            // Set a longer timeout for EXEC (commands may take time to execute)
            struct timeval timeout;
            timeout.tv_sec = 5;  // 5 second timeout for EXEC
            timeout.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            
            // Read continuously and print as we receive
            char chunk[4096];
            while ((n = recv(sock, chunk, sizeof(chunk) - 1, 0)) > 0) {
                chunk[n] = '\0';
                printf("%s", chunk);
                fflush(stdout);
            }
            
            // Restore no timeout
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        } else {
            // For other commands, use original logic
            // Read response in chunks until no more data is available
            // Use a small timeout to avoid blocking indefinitely
            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000;  // 100ms timeout
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            
            // First read (blocking with timeout)
            n = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (n > 0) {
                total_received = n;
                
                // Try to read more data (non-blocking check)
                int flags = fcntl(sock, F_GETFL, 0);
                fcntl(sock, F_SETFL, flags | O_NONBLOCK);
                
                // Read any additional data that might be available
                while ((n = recv(sock, buffer + total_received, sizeof(buffer) - total_received - 1, 0)) > 0) {
                    total_received += n;
                    if (total_received >= (int)(sizeof(buffer) - 1)) break;
                }
                
                // Restore blocking mode
                fcntl(sock, F_SETFL, flags);
            }
            
            // Remove timeout (restore blocking with no timeout)
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            
            if (total_received > 0) {
                buffer[total_received] = 0;
                printf("%s", buffer);
                fflush(stdout);  // Ensure output is flushed immediately
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                perror("recv");
            }
        }
    }

    close(sock);
    return 0;
}
