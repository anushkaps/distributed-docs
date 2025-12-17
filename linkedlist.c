#include "linkedlist.h"
#include <string.h>

void init_linkedlist(linkedlist_t *ll)
{
    ll->head = NULL;
    ll->size = 0;
}

void insert_at_n(linkedlist_t *ll, void *data, size_t n) //  0 indexed linkedlist inserts new node at the nth position
{
    if (!ll) {
        return;  // Safety check
    }
    
    node_t *new_node = (node_t *)malloc(sizeof(node_t));
    if (!new_node) {
        return;  // Memory allocation failed
    }
    new_node->data = data;
    new_node->next = NULL;
    
    // If list is empty or inserting at position 0, insert at head
    if (n == 0 || ll->head == NULL)
    {
        new_node->next = ll->head;
        ll->head = new_node;
    }
    else
    {
        node_t *current = ll->head;
        // Traverse to position n-1, but don't go beyond the end of the list
        for (size_t i = 0; i < n - 1 && current != NULL && current->next != NULL; i++)
        {
            current = current->next;
        }
        
        // Safety check: if current is NULL, insert at head instead
        if (current == NULL) {
            new_node->next = ll->head;
            ll->head = new_node;
        } else {
            new_node->next = current->next;
            current->next = new_node;
        }
    }
    ll->size++;
}

void remove_at_n(linkedlist_t *ll, size_t n) // 0 indexed linkedlist removes node from the nth position
{
    if (n >= ll->size || ll->head == NULL)
    {
        return;
    }
    
    // Special case: removing head node (index 0)
    if (n == 0)
    {
        node_t *temp = ll->head;
        ll->head = ll->head->next;
        free(temp);
        temp = NULL;
        ll->size--;
        return;
    }
    
    node_t *current = ll->head;
    for (size_t i = 0; i < n - 1 && current->next != NULL; i++)
    {
        current = current->next;
    }
    if (current->next == NULL)
    {
        return;
    }
    node_t *temp = current->next;
    current->next = temp->next;
    free(temp);
    temp = NULL;
    ll->size--;
    return;
}

void remove_all(linkedlist_t *ll)
{
    while (ll->head != NULL)
    {
        node_t *temp = ll->head;
        ll->head = ll->head->next;
        free(temp);
        temp = NULL;
    }
    ll->size = 0;
}

bool in_linkedlist(linkedlist_t *ll, void *data)
{
    node_t *current = ll->head;
    while (current != NULL)
    {
        if (strcmp((char*)current->data, (char*)data) == 0)
        {
            return true;
        }
        current = current->next;
    }
    return false;
}

void free_linkedlist(linkedlist_t *ll)
{
    remove_all(ll);
    free(ll);
    ll = NULL;
}