# Makefile for Name Server
# Compiles all name server modules into a single executable

CC = gcc
CFLAGS = -Wall -Wextra -g -std=c11 -D_GNU_SOURCE
LDFLAGS = -lpthread

# Linkedlist library (compiled from parent directory)
LINKEDLIST_OBJ = ../linkedlist.o

# Source files
SRCS = name_server.c \
       client_handler.c \
       handlers.c \
       forwarding.c \
       utils.c \
       file_lookup.c

# Object files
OBJS = $(SRCS:.c=.o)

# Target executable
TARGET = name_server

# Include directory (for common.h)
INCLUDES = -I..

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(OBJS) $(LINKEDLIST_OBJ)
	$(CC) $(CFLAGS) $(OBJS) $(LINKEDLIST_OBJ) -o $(TARGET) $(LDFLAGS)
	@echo "Name Server built successfully: $(TARGET)"

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET) a.out
	@echo "Cleaned name server build files"

# Rebuild everything
rebuild: clean all

# Phony targets
.PHONY: all clean rebuild

