#ifndef QUEUE_H
#define QUEUE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

// Use node_t from linkedlist.h if available, otherwise define our own
// This avoids redefinition when both headers are included
// Since storage_server.h includes linkedlist.h before queue.h,
// node_t will be available from linkedlist.h
#ifndef LINKEDLIST_H
typedef struct node
{
    struct node * next;
    void * data;
} node_t;
#endif

typedef struct{
    node_t * head;
    size_t size;
}queue_t;

void init_queue(queue_t *q);
void enqueue(queue_t *q, void *data);
bool isEmpty(queue_t *q);
void *dequeue(queue_t *q);
void *peek(queue_t *q);
void free_queue(queue_t *q);

#endif //QUEUE_H