# Makefile for Client
# Compiles the client application

CC = gcc
CFLAGS = -Wall -Wextra -g -std=c11
LDFLAGS = 

# Source files
SRCS = client.c

# Object files
OBJS = $(SRCS:.c=.o)

# Target executable
TARGET = client

# Include directory (for common.h)
INCLUDES = -I..

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo "Client built successfully: $(TARGET)"

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET) a.out
	@echo "Cleaned client build files"

# Rebuild everything
rebuild: clean all

# Phony targets
.PHONY: all clean rebuild

