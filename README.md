# Distributed Document Collaboration System (C)

This repository contains **my original implementation** of a distributed document collaboration system written in C.

The system follows a **Name Server – Storage Server – Client** architecture and supports concurrent multi-user access to shared text files with sentence-level locking.

---

## Components

- **Name Server (NS)**  
  Central coordinator that manages file metadata, access control, and routes requests.

- **Storage Servers (SS)**  
  Store files persistently and serve read/write/stream requests.

- **Client**  
  Command-line interface for users to interact with the system.

---

## Build

```bash
make
```

This builds:

- `name_server/name_server`
- `storage_server/storage_server`
- `client/client`

---

## How to Run

Use separate terminals for each component.

### 1️⃣ Start Name Server

```bash
cd name_server
./name_server 9000
```

### 2️⃣ Start one or more Storage Servers

```bash
cd storage_server
./storage_server 127.0.0.1 9000 9100
```

(Optional additional servers)

```bash
./storage_server 127.0.0.1 9000 9101
./storage_server 127.0.0.1 9000 9102
```

### 3️⃣ Start Client(s)

```bash
cd client
./client 127.0.0.1 8080
```

You will be prompted for a username.  
Multiple clients can be started simultaneously in different terminals.

---

## Supported Commands

### File Operations

| Command    | Syntax                              | Description                                                |
| ---------- | ----------------------------------- | ---------------------------------------------------------- |
| **VIEW**   | `VIEW [-a] [-l]`                    | List files. `-a` shows all files, `-l` shows detailed info |
| **CREATE** | `CREATE <filename>`                 | Create a new empty file                                    |
| **READ**   | `READ <filename>`                   | Read and display file content                              |
| **WRITE**  | `WRITE <filename> <sentence_index>` | Write/update words in a sentence                           |
| **DELETE** | `DELETE <filename>`                 | Delete a file (owner only)                                 |
| **INFO**   | `INFO <filename>`                   | Display file metadata                                      |
| **STREAM** | `STREAM <filename>`                 | Stream file content word-by-word                           |
| **UNDO**   | `UNDO <filename>`                   | Undo the last change to a file                             |

### Access Control

| Command           | Syntax                                       | Description                               |
| ----------------- | -------------------------------------------- | ----------------------------------------- |
| **ADDACCESS**     | `ADDACCESS <filename> <username> -R` or `-W` | Grant read (-R) or write (-W) access      |
| **REMACCESS**     | `REMACCESS <filename> <username>`            | Revoke user access                        |
| **REQUESTACCESS** | `REQUESTACCESS -R <filename>` or `-W`        | Request access to a file                  |
| **VIEWREQUESTS**  | `VIEWREQUESTS <filename>`                    | View pending access requests (owner only) |
| **APPROVE**       | `APPROVE <filename> <username>`              | Approve an access request (owner only)    |
| **REJECT**        | `REJECT <filename> <username>`               | Reject an access request (owner only)     |

### Checkpoint Operations

| Command             | Syntax                                        | Description                     |
| ------------------- | --------------------------------------------- | ------------------------------- |
| **CHECKPOINT**      | `CHECKPOINT <filename> <checkpoint_name>`     | Create a checkpoint (snapshot)  |
| **LISTCHECKPOINTS** | `LISTCHECKPOINTS <filename>`                  | List all checkpoints for a file |
| **VIEWCHECKPOINT**  | `VIEWCHECKPOINT <filename> <checkpoint_name>` | View a specific checkpoint      |
| **REVERT**          | `REVERT <filename> <checkpoint_name>`         | Revert file to a checkpoint     |

### Execution

| Command  | Syntax            | Description                            |
| -------- | ----------------- | -------------------------------------- |
| **EXEC** | `EXEC <filename>` | Execute file content as shell commands |

### Other

| Command  | Syntax | Description                  |
| -------- | ------ | ---------------------------- |
| **LIST** | `LIST` | List all users in the system |
| **QUIT** | `QUIT` | Exit the client              |

---

## Notes

- Files are text-only and sentence-delimited (`.`, `!`, `?`)
- Sentence-level locking prevents conflicting writes
- Multiple clients and storage servers are supported concurrently
- Data persists across Storage Server restarts

---

## Project Origin

This project was designed and implemented by me as part of the **CS3 – Operating Systems & Networks** coursework.

A more detailed explanation of architecture, examples, and advanced features is available in [`docs/DETAILS.md`](docs/DETAILS.md).
