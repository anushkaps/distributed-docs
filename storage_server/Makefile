# Makefile for Storage Server
# Compiles all storage server modules into a single executable

CC = gcc
CFLAGS = -Wall -Wextra -g -std=c11 -D_GNU_SOURCE
LDFLAGS = -lpthread

# Source files
SRCS = storage_server.c \
       logging.c \
       client_handler_ss.c \
       command_handlers_ss.c \
       exec_handler_ss.c \
       ns_registration.c \
       access_control.c \
       access_requests.c \
       checkpoints.c \
       file_conversion.c \
       file_creation.c \
       hash_table.c \
       queue.c \
       read_file.c \
       undo_last_change.c \
       view_file.c \
       write_file.c \
       misc.c \
       connection.c

# Linkedlist library (compiled from parent directory)
LINKEDLIST_OBJ = ../linkedlist.o

# Object files
OBJS = $(SRCS:.c=.o)

# Target executable
TARGET = storage_server

# Include directory (for common.h)
INCLUDES = -I..

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(OBJS) $(LINKEDLIST_OBJ)
	$(CC) $(CFLAGS) $(OBJS) $(LINKEDLIST_OBJ) -o $(TARGET) $(LDFLAGS)
	@echo "Storage Server built successfully: $(TARGET)"

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET) a.out
	@echo "Cleaned storage server build files"

# Rebuild everything
rebuild: clean all

# Phony targets
.PHONY: all clean rebuild

