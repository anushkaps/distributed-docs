#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "linkedlist.h"

#define MAX_DATA 2048

// === Protocol Constants ===
// String constants used in network communication
#define PROTOCOL_STOP "STOP"
#define PROTOCOL_STOP_LEN 4
#define PROTOCOL_ETIRW "ETIRW"
#define PROTOCOL_ETIRW_LEN 5
#define PROTOCOL_REGISTERED "REGISTERED"
#define PROTOCOL_REGISTERED_LEN 10
#define PROTOCOL_SS_INFO_PREFIX "SS_INFO|"
#define PROTOCOL_SS_INFO_PREFIX_LEN 8
#define PROTOCOL_REGISTER_SS "REGISTER SS"
#define PROTOCOL_REGISTER_SS_LEN 11
#define PROTOCOL_FILE_LIST "FILE_LIST"
#define PROTOCOL_FILE_LIST_LEN 9
#define PROTOCOL_FILE "FILE"
#define PROTOCOL_FILE_LEN 4
#define PROTOCOL_END_FILE_LIST "END_FILE_LIST"
#define PROTOCOL_END_FILE_LIST_LEN 13
#define PROTOCOL_METADATA "METADATA"
#define PROTOCOL_METADATA_LEN 7
#define PROTOCOL_METADATA_SUCCESS "SUCCESS"
#define PROTOCOL_METADATA_SUCCESS_LEN 7
#define PROTOCOL_METADATA_FAILURE "FAILURE"
#define PROTOCOL_METADATA_FAILURE_LEN 6

// === Network Constants ===
#define MAX_PORT_NUMBER 65535
#define MIN_PORT_NUMBER 1

#define FILE_NAME_SIZE 256

typedef struct meta_data
{
    char filename[FILE_NAME_SIZE];  // Changed from const char to char for mutability
    time_t created;
    time_t modified;
    time_t last_accessed;  // File-level last access time (most recent access by any user)
    char owner[FILE_NAME_SIZE];
    size_t wordcount;
    size_t charcount;
    char lastmodifiedby[FILE_NAME_SIZE];
    linkedlist_t *users_with_access;  // Now stores user_access structures
} meta_data;

// Structure to store user access information with type and last access time
typedef struct {
    char username[FILE_NAME_SIZE];
    int access_type;  // ACCESS_READ (0) or ACCESS_WRITE (1)
    time_t last_access;  // Last time user accessed the file
} user_access;

// === Command opcodes ===
enum COMMAND_CODE {
    CMD_VIEW = 1,
    CMD_READ,
    CMD_CREATE,
    CMD_WRITE,
    CMD_UNDO,
    CMD_INFO,
    CMD_DELETE,
    CMD_STREAM,
    CMD_LIST,
    CMD_ADDACCESS,
    CMD_REMACCESS,
    CMD_EXEC,
    // Checkpoint commands
    CMD_CHECKPOINT,
    CMD_LISTCHECKPOINTS,
    CMD_VIEWCHECKPOINT,
    CMD_REVERT,
    // Access request commands
    CMD_REQUESTACCESS,
    CMD_VIEWREQUESTS,
    CMD_APPROVE,
    CMD_REJECT
};

// === Error Codes ===
// Universal error codes used throughout the system
// Format: ERR_<CATEGORY>_<SPECIFIC>
enum ERROR_CODE {
    // Success (no error)
    ERR_SUCCESS = 0,
    
    // Access Control Errors (100-199)
    ERR_UNAUTHORIZED_ACCESS = 100,
    ERR_READ_ACCESS_DENIED = 101,
    ERR_WRITE_ACCESS_DENIED = 102,
    ERR_NOT_OWNER = 103,
    ERR_ACCESS_ALREADY_GRANTED = 104,
    ERR_ACCESS_NOT_FOUND = 105,
    ERR_USER_IS_OWNER = 106,
    ERR_USER_NOT_FOUND = 107,
    
    // File Operation Errors (200-299)
    ERR_FILE_NOT_FOUND = 200,
    ERR_FILE_ALREADY_EXISTS = 201,
    ERR_FILE_CREATE_FAILED = 202,
    ERR_FILE_DELETE_FAILED = 203,
    ERR_FILE_READ_FAILED = 204,
    ERR_FILE_WRITE_FAILED = 205,
    ERR_FILE_LOCKED = 206,
    ERR_INVALID_FILENAME = 207,
    ERR_FILE_IS_BEING_WRITTEN = 208,
    
    // Sentence/Word Operation Errors (300-399)
    ERR_SENTENCE_INDEX_OUT_OF_RANGE = 300,
    ERR_WORD_INDEX_OUT_OF_RANGE = 301,
    ERR_SENTENCE_LOCKED = 302,
    ERR_INVALID_SENTENCE_INDEX = 303,
    ERR_INVALID_WORD_INDEX = 304,
    ERR_SENTENCE_INDEX_NEGATIVE = 305,
    
    // Resource Contention Errors (400-499)
    ERR_RESOURCE_LOCKED = 400,
    ERR_CONCURRENT_WRITE_CONFLICT = 401,
    ERR_OPERATION_TIMEOUT = 402,
    
    // System/Network Errors (500-599)
    ERR_STORAGE_SERVER_UNAVAILABLE = 500,
    ERR_NAME_SERVER_UNAVAILABLE = 501,
    ERR_CONNECTION_FAILED = 502,
    ERR_CONNECTION_LOST = 503,
    ERR_NETWORK_ERROR = 504,
    ERR_SERVER_ERROR = 505,
    ERR_MEMORY_ALLOCATION_FAILED = 506,
    
    // Validation Errors (600-699)
    ERR_INVALID_COMMAND = 600,
    ERR_INVALID_PARAMETERS = 601,
    ERR_INVALID_OPERATION = 602,
    ERR_MISSING_PARAMETERS = 603,
    ERR_INVALID_USERNAME = 604,
    ERR_INVALID_ACCESS_MODE = 605,
    
    // Data/State Errors (700-799)
    ERR_NO_UNDO_HISTORY = 700,
    ERR_CHECKPOINT_NOT_FOUND = 701,
    ERR_CHECKPOINT_CREATE_FAILED = 702,
    ERR_CHECKPOINT_REVERT_FAILED = 703,
    ERR_FILE_METADATA_CORRUPT = 704,
    ERR_DATA_PERSISTENCE_FAILED = 705,
    ERR_FOLDER_CREATE_FAILED = 706,
    ERR_FOLDER_ALREADY_EXISTS = 707,
    ERR_INVALID_FOLDER_NAME = 708,
    
    // Access Request Errors (800-899)
    ERR_ACCESS_REQUEST_NOT_FOUND = 800,
    ERR_ACCESS_REQUEST_ALREADY_EXISTS = 801,
    ERR_CANNOT_REQUEST_OWN_ACCESS = 802,
    
    // General/Unknown Errors (900-999)
    ERR_UNKNOWN_ERROR = 900,
    ERR_OPERATION_FAILED = 901,
    ERR_INTERNAL_ERROR = 902,
    ERR_NOT_IMPLEMENTED = 903
};

/**
 * Get human-readable error message from error code
 * Specification: All operations return error code + human-readable message
 * 
 * @param error_code - Error code from ERROR_CODE enum
 * @return Human-readable error message string
 */
static inline const char* get_error_message(int error_code) {
    switch (error_code) {
        case ERR_SUCCESS: return "Operation successful";
        case ERR_UNAUTHORIZED_ACCESS: return "Unauthorized access";
        case ERR_READ_ACCESS_DENIED: return "Read access denied";
        case ERR_WRITE_ACCESS_DENIED: return "Write access denied";
        case ERR_NOT_OWNER: return "Not file owner";
        case ERR_ACCESS_ALREADY_GRANTED: return "Access already granted";
        case ERR_ACCESS_NOT_FOUND: return "Access not found";
        case ERR_USER_IS_OWNER: return "User is already the owner";
        case ERR_USER_NOT_FOUND: return "User not found";
        case ERR_FILE_NOT_FOUND: return "File not found";
        case ERR_FILE_ALREADY_EXISTS: return "File already exists";
        case ERR_FILE_CREATE_FAILED: return "File creation failed";
        case ERR_FILE_DELETE_FAILED: return "File deletion failed";
        case ERR_FILE_READ_FAILED: return "File read failed";
        case ERR_FILE_WRITE_FAILED: return "File write failed";
        case ERR_FILE_LOCKED: return "File is locked";
        case ERR_INVALID_FILENAME: return "Invalid filename";
        case ERR_FILE_IS_BEING_WRITTEN: return "File is being written";
        case ERR_SENTENCE_INDEX_OUT_OF_RANGE: return "Sentence index out of range";
        case ERR_WORD_INDEX_OUT_OF_RANGE: return "Word index out of range";
        case ERR_SENTENCE_LOCKED: return "Sentence is locked";
        case ERR_INVALID_SENTENCE_INDEX: return "Invalid sentence index";
        case ERR_INVALID_WORD_INDEX: return "Invalid word index";
        case ERR_SENTENCE_INDEX_NEGATIVE: return "Sentence index cannot be negative";
        case ERR_RESOURCE_LOCKED: return "Resource is locked";
        case ERR_CONCURRENT_WRITE_CONFLICT: return "Concurrent write conflict";
        case ERR_OPERATION_TIMEOUT: return "Operation timeout";
        case ERR_STORAGE_SERVER_UNAVAILABLE: return "Storage server unavailable";
        case ERR_NAME_SERVER_UNAVAILABLE: return "Name server unavailable";
        case ERR_CONNECTION_FAILED: return "Connection failed";
        case ERR_CONNECTION_LOST: return "Connection lost";
        case ERR_NETWORK_ERROR: return "Network error";
        case ERR_SERVER_ERROR: return "Server error";
        case ERR_MEMORY_ALLOCATION_FAILED: return "Memory allocation failed";
        case ERR_INVALID_COMMAND: return "Invalid command";
        case ERR_INVALID_PARAMETERS: return "Invalid parameters";
        case ERR_INVALID_OPERATION: return "Invalid operation";
        case ERR_MISSING_PARAMETERS: return "Missing parameters";
        case ERR_INVALID_USERNAME: return "Invalid username";
        case ERR_INVALID_ACCESS_MODE: return "Invalid access mode";
        case ERR_NO_UNDO_HISTORY: return "No undo history available";
        case ERR_CHECKPOINT_NOT_FOUND: return "Checkpoint not found";
        case ERR_CHECKPOINT_CREATE_FAILED: return "Checkpoint creation failed";
        case ERR_CHECKPOINT_REVERT_FAILED: return "Checkpoint revert failed";
        case ERR_FILE_METADATA_CORRUPT: return "File metadata corrupt";
        case ERR_DATA_PERSISTENCE_FAILED: return "Data persistence failed";
        case ERR_FOLDER_CREATE_FAILED: return "Folder creation failed";
        case ERR_FOLDER_ALREADY_EXISTS: return "Folder already exists";
        case ERR_INVALID_FOLDER_NAME: return "Invalid folder name";
        case ERR_ACCESS_REQUEST_NOT_FOUND: return "Access request not found";
        case ERR_ACCESS_REQUEST_ALREADY_EXISTS: return "Access request already exists";
        case ERR_CANNOT_REQUEST_OWN_ACCESS: return "Cannot request own access";
        case ERR_UNKNOWN_ERROR: return "Unknown error";
        case ERR_OPERATION_FAILED: return "Operation failed";
        case ERR_INTERNAL_ERROR: return "Internal error";
        case ERR_NOT_IMPLEMENTED: return "Not implemented";
        default: return "Unknown error code";
    }
}

// === VIEW mode flags ===
#define VIEW_USER_ONLY 0
#define VIEW_ALL       1
#define VIEW_LONG      2
#define VIEW_ALL_LONG  3

// === Access flags ===
#define ACCESS_READ  0
#define ACCESS_WRITE 1

// === Packet structure ===
typedef struct {
    int  opcode;           // command code
    char username[64];
    char filename[256];
    int  flag1;            // meaning depends on opcode
    int  flag2;
    char payload[MAX_DATA];
} Packet;

#endif

