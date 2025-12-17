#include "../storage_server/queue.h"

void init_queue(queue_t *q)
{
    q->head = NULL;
    q->size = 0;
}

void enqueue(queue_t *q, void *data)
{
    node_t *new_node = (node_t *)malloc(sizeof(node_t));
    new_node->next = NULL;
    new_node->data = data;
    if (q->head == NULL)
    {
        q->head = new_node;
    }
    else
    {
        node_t *current = q->head;
        while (current->next != NULL)
        {
            current = current->next;
        }
        current->next = new_node;
    }
    q->size++;
}

bool isEmpty(queue_t *q)
{
    if (q->size == 0)
    {
        return true;
    }
    return false;
}

void *dequeue(queue_t *q)
{
    if (isEmpty(q))
    {
        return NULL;
    }
    node_t *temp = q->head;
    q->head = q->head->next;
    void *data = temp->data;
    free(temp);
    q->size--;
    return data;
}

void *peek(queue_t *q)
{
    if (isEmpty(q))
    {
        return NULL;
    }
    return q->head->data;
}

void free_queue(queue_t *q)
{
    while (!isEmpty(q))
    {
        dequeue(q);
    }
}