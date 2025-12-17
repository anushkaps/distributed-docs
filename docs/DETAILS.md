# Detailed Documentation

This document contains comprehensive details about the LangOS distributed document collaboration system, including architecture, examples, testing scenarios, and advanced features.

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [System Features](#system-features)
- [Testing Scenarios](#testing-scenarios)
- [Example Workflows](#example-workflows)
- [Troubleshooting](#troubleshooting)
- [File Storage](#file-storage)
- [Advanced Features](#advanced-features)

---

## Project Overview

LangOS is a distributed document collaboration system designed for concurrent multi-user file editing. The system supports:

- **Concurrent Access**: Multiple users can read and write files simultaneously
- **Sentence-level Locking**: Prevents conflicts when editing the same sentence
- **Access Control**: Fine-grained read/write permissions per user
- **Data Persistence**: Files survive server restarts
- **Efficient Search**: O(1) file lookups using hash tables
- **Comprehensive Logging**: All operations are logged with timestamps and user information

---

## Architecture

The system follows a client-server architecture with three main components:

- **Name Server (NS)** - Central registry that manages file metadata and routes client requests to appropriate Storage Servers
- **Storage Server (SS)** - Stores files and handles file operations (READ, WRITE, CREATE, DELETE, etc.)
- **Client** - Command-line interface for users to interact with the system

### Component Details

#### Name Server

- Acts as the central coordinator of the system
- Handles all communication between clients and storage servers
- Maintains the mapping between file names and their storage locations
- Ensures efficient and correct access to files across the system
- Listens on port 9000 for Storage Server registrations
- Listens on port 8080 for client connections

#### Storage Servers

- Responsible for storing and retrieving file data
- Ensure durability, persistence, and efficient access to files
- Support concurrent access by multiple clients, including both reads and writes
- Each Storage Server can run on a unique client port (e.g., 9100, 9101, 9102)
- Files are stored locally in `./storage_current/` directory

#### Client

- Command-line interface for users to interact with the system
- Prompts for username on startup
- Connects to Name Server on port 8080
- Multiple clients can connect simultaneously

---

## System Features

### Core Requirements (Implemented)

- ✅ **Concurrent Access:** Multiple clients and Storage Servers running simultaneously
  - Each client connection runs in its own thread
  - Thread-safe locking mechanisms ensure data consistency
  - Sentence-level locking prevents write conflicts
  - Multiple users can read/write files concurrently
- ✅ **Data Persistence:** All files and metadata are stored persistently
  - Files survive Storage Server restarts
  - Metadata (access control, timestamps) is preserved
  - Files stored in `./storage_current/` directory
- ✅ **Access Control:** Fine-grained permissions per user
  - Read and write access can be granted separately
  - Owner always has full access
  - Access control enforced at Storage Server level
- ✅ **Efficient Search:** O(1) file lookups using hash tables
  - Hash table implementation for fast file location
  - Caching for recent searches
- ✅ **Comprehensive Logging:** All operations logged with details
  - Timestamps, IP addresses, ports, usernames
  - Request/response logging
  - Logs written to `name_server.log` and `storage_server.log`
- ✅ **Error Handling:** Comprehensive error codes and messages
  - Universal error codes throughout the system
  - Clear error messages for all failure scenarios

### Bonus Features (Implemented)

- ✅ **Checkpoints:** Save and revert file states

  - Create checkpoints with custom names
  - View checkpoint content
  - Revert files to previous checkpoints
  - List all checkpoints for a file

- ✅ **Access Requests:** Request-based access control
  - Users can request read/write access
  - Owners can view and approve/reject requests
  - No push notifications needed

### Architecture Notes

- **Multiple Storage Servers:** Can run simultaneously on different ports for distributed storage
- **Multiple Clients:** Can connect simultaneously to the same Name Server
  - Each client can have a different username
  - All clients share the same file system view
  - Access control ensures users only see/modify files they have permission for
- **File Structure:** Files consist of sentences (separated by `.`, `!`, `?`) and words (separated by spaces)
- **Sentence Locking:** When editing a sentence, it's locked until the write operation completes (`ETIRW`)
- The Name Server routes requests to the appropriate Storage Server

---

## Testing Scenarios

### Basic File Operations

**Test 1: Create and Read a File**

```bash
# In client terminal
> CREATE test.txt
> WRITE test.txt 0
> 0 Hello
> 1 World
> ETIRW
> READ test.txt
```

**Test 2: Multiple Concurrent Clients**

The system supports **multiple clients connected simultaneously**. Start multiple clients in different terminals - they can all work at the same time!

**Client 1 (Terminal 5 - Alice):**

```bash
cd client
./client 127.0.0.1 8080
# Enter username: alice
> CREATE document.txt
> WRITE document.txt 0
> 0 This is a test document
> ETIRW
```

**Client 2 (Terminal 6 - Bob):**

```bash
cd client
./client 127.0.0.1 8080
# Enter username: bob
> READ document.txt
# Should fail - no access
> ADDACCESS document.txt bob -R
# Should fail - bob is not owner
```

**Client 3 (Terminal 7 - Charlie - optional):**

```bash
cd client
./client 127.0.0.1 8080
# Enter username: charlie
> VIEW -a
# Can see all files but may not have access
```

**Client 1 (alice) - while other clients are still connected:**

```bash
> ADDACCESS document.txt bob -R
> ADDACCESS document.txt charlie -R
# Now both bob and charlie can read
```

**Client 2 (bob) - can now read:**

```bash
> READ document.txt
# Should succeed now - can read while alice is still connected
```

**Client 3 (charlie) - can also read:**

```bash
> READ document.txt
# Should succeed - multiple clients can read simultaneously
```

**Key Points:**

- All three clients are connected **at the same time**
- They can all perform operations concurrently
- Access control works correctly across all clients
- Each client maintains its own session independently

### Testing Multiple Storage Servers

**Test 3: Files Distributed Across Servers**

1. Create files from different clients connected to different Storage Servers
2. Use `VIEW -a` to see all files across all Storage Servers
3. Verify files are accessible regardless of which Storage Server they're on

**Test 4: Storage Server Failure Simulation**

1. Start two Storage Servers (ports 9100 and 9101)
2. Create files on both
3. Stop one Storage Server (Ctrl+C)
4. Verify files on the remaining Storage Server are still accessible
5. Restart the stopped Storage Server
6. Verify it re-registers and files are still accessible

### Access Control Testing

**Test 5: Access Request Workflow**

```bash
# User alice creates a file
> CREATE private.txt
> WRITE private.txt 0
> 0 Private content
> ETIRW

# User bob requests access
# (In bob's client)
> REQUESTACCESS -R private.txt

# User alice views and approves
# (In alice's client)
> VIEWREQUESTS private.txt
> APPROVE private.txt bob

# User bob can now read
# (In bob's client)
> READ private.txt
```

### Checkpoint Testing

**Test 6: Create and Revert Checkpoint**

```bash
> CREATE version.txt
> WRITE version.txt 0
> 0 Version 1
> ETIRW
> CHECKPOINT version.txt v1
> WRITE version.txt 0
> 0 Version 2
> ETIRW
> VIEWCHECKPOINT version.txt v1
> REVERT version.txt v1
> READ version.txt
# Should show Version 1
```

---

## Example Workflows

### Complete Example: Collaborative Document Editing

**Setup:**

1. Start Name Server (port 9000)
2. Start Storage Server 1 (port 9100)
3. Start Storage Server 2 (port 9101) - optional, for distributed storage
4. Start Client 1 as "alice" (Terminal 5)
5. Start Client 2 as "bob" (Terminal 6)
6. Start Client 3 as "charlie" (Terminal 7) - optional, for more collaboration

**Note:** All clients connect to the same Name Server (port 8080) and can work simultaneously!

**Workflow:**

**Alice (Client 1):**

```bash
> CREATE project.txt
> WRITE project.txt 0
> 0 Project Plan
> 1 Phase 1: Design
> 2 Phase 2: Implementation
> ETIRW
> ADDACCESS project.txt bob -W
> CHECKPOINT project.txt initial
```

**Bob (Client 2):**

```bash
> READ project.txt
> WRITE project.txt 1
> 0 Project Plan
> 1 Phase 1: Design - Completed
> 2 Phase 2: Implementation
> ETIRW
```

**Alice:**

```bash
> READ project.txt
> VIEWCHECKPOINT project.txt initial
> LISTCHECKPOINTS project.txt
```

---

## Troubleshooting

### Port Already in Use

If you see "port already in use" errors:

1. **Storage Server:** Make sure each Storage Server uses a unique client port:

   ```bash
   ./storage_server 127.0.0.1 9000 9100  # First SS
   ./storage_server 127.0.0.1 9000 9101  # Second SS (different port!)
   ```

2. **Name Server:** Make sure port 9000 and 8080 are not in use:
   ```bash
   lsof -i :9000
   lsof -i :8080
   ```

### Storage Server Not Registering

- Verify Name Server is running first
- Check that you're using the correct NS IP and port (127.0.0.1 9000)
- Check firewall settings

### File Not Found

- Use `VIEW -a` to see all files across all Storage Servers
- Verify the file was created successfully
- Check Storage Server logs for errors

### Access Denied

- Verify you have the correct permissions (owner or granted access)
- Use `INFO <filename>` to check file ownership and access list
- Request access using `REQUESTACCESS` if you're not the owner

---

## File Storage

- Storage Servers store files in `./storage_current/` directory
- Each Storage Server has its own `storage_current/` directory
- File metadata is stored in binary format with `.dat` extension
- Checkpoints are stored as separate files
- Logs are written to `name_server.log` and `storage_server.log`

### Cleanup

To clean up all build artifacts and generated files:

```bash
make clean
rm -rf storage_server/storage_current
rm -f name_server.log storage_server.log
rm -f storage_server/storage_server_info.txt
```

---

## Advanced Features

### Checkpoints

Checkpoints allow you to save file states at specific points in time and revert to them if needed. This is useful for version control and recovery.

**Usage:**

- `CHECKPOINT <filename> <checkpoint_name>` - Create a checkpoint
- `LISTCHECKPOINTS <filename>` - List all checkpoints
- `VIEWCHECKPOINT <filename> <checkpoint_name>` - View checkpoint content
- `REVERT <filename> <checkpoint_name>` - Revert to checkpoint

### Access Requests

The access request system allows users to request access to files they don't own. Owners can view and approve/reject these requests.

**Usage:**

- `REQUESTACCESS -R <filename>` - Request read access
- `REQUESTACCESS -W <filename>` - Request write access
- `VIEWREQUESTS <filename>` - View pending requests (owner only)
- `APPROVE <filename> <username>` - Approve a request (owner only)
- `REJECT <filename> <username>` - Reject a request (owner only)

### Sentence-Level Locking

When a user starts editing a sentence with `WRITE`, that sentence is locked until the user sends `ETIRW`. This prevents conflicts when multiple users try to edit the same sentence simultaneously.

**Important Notes:**

- Multiple users can read the same file concurrently
- Multiple users can edit different sentences concurrently
- Only one user can edit a specific sentence at a time
- The lock is released when `ETIRW` is sent

### File Structure

Files are structured as:

- **Sentences**: Separated by `.`, `!`, or `?`
- **Words**: Separated by spaces within sentences

**Example:**

```
Hello world. How are you? I'm fine!
```

This file has 3 sentences:

1. "Hello world."
2. "How are you?"
3. "I'm fine!"

---

## Command Reference Details

### WRITE Command Details

The WRITE command allows word-level updates to files:

```bash
> WRITE filename.txt 0    # Start editing sentence 0
> 0 Hello                # Update word at index 0
> 1 World                # Update word at index 1
> ETIRW                  # Finish editing and release lock
```

**Important:**

- Sentence index updates after each WRITE completion
- Content may contain sentence delimiters (`.`, `!`, `?`) which create new sentences
- Multiple word updates in a single WRITE are considered one operation (for UNDO)
- Updates are applied in order received

### UNDO Command Details

- Only one undo operation per file is supported
- Undo operates at the Storage Server level
- Undo reverts the most recent change, regardless of who made it
- If user A makes a change, user B can undo it

---

## Error Codes

The system uses comprehensive error codes for all failure scenarios:

- **Access Control Errors (100-199)**: Unauthorized access, access denied, etc.
- **File Operation Errors (200-299)**: File not found, already exists, etc.
- **Sentence/Word Operation Errors (300-399)**: Index out of range, sentence locked, etc.
- **Resource Contention Errors (400-499)**: Resource locked, concurrent write conflict, etc.
- **System/Network Errors (500-599)**: Server unavailable, connection failed, etc.
- **Validation Errors (600-699)**: Invalid command, invalid parameters, etc.
- **Data/State Errors (700-799)**: No undo history, checkpoint not found, etc.
- **Access Request Errors (800-899)**: Request not found, already exists, etc.

All error codes include human-readable error messages.

---

## Logging

Both Name Server and Storage Server maintain comprehensive logs:

- **Name Server Log**: `name_server.log`
- **Storage Server Log**: `storage_server.log`

Each log entry includes:

- Timestamp
- IP address
- Port number
- Username
- Operation details
- Status (request/response)

Logs are written to files and also displayed on stdout for real-time monitoring.
