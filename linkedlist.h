#ifndef LINKEDLIST_H
#define LINKEDLIST_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

typedef struct node
{
    struct node *next;
    void *data;
} node_t;

typedef struct linkedlist_t
{
    node_t *head;
    size_t size;
} linkedlist_t;

void init_linkedlist(linkedlist_t *ll);
void free_linkedlist(linkedlist_t *ll);
void insert_at_n(linkedlist_t *ll, void *data, size_t n);
void remove_at_n(linkedlist_t *ll, size_t n);
void remove_all(linkedlist_t *ll);
bool in_linkedlist(linkedlist_t *ll, void *data);

#endif // LINKEDLIST_H