/*
 * queue.c  –  Simple linked-list queue for BOF use
 *
 * Compiles into the BOF itself, not into the loader.
 * Uses intAlloc/intFree which resolve through beacon_compatibility.h.
 *
 * Not thread-safe (original comment preserved — intentional, BOFs are
 * single-threaded by design).
 *
 * Change from original: bofdefs.h → beacon_compatibility.h
 */

#include "loader/beacon_compatibility.h"

typedef struct _item {
    void*         elem;
    struct _item* next;
} item, *Pitem;

typedef struct _queue {
    Pitem  head;
    Pitem  tail;
    void   (*push)(struct _queue*, void*);
    void*  (*pop) (struct _queue*);
    void   (*free)(struct _queue*);
} queue, *Pqueue;

static void _push(Pqueue q, void* v) {
    Pitem i = (Pitem)intAlloc(sizeof(item));
    if (!i) return;
    i->elem = v;
    i->next = NULL;
    if (q->head == NULL && q->tail == NULL) {
        q->head = i;
        q->tail = i;
    } else {
        q->tail->next = i;
        q->tail       = i;
    }
}

static void* _pop(Pqueue q) {
    if (q->head == NULL) return NULL;

    void*  retval = q->head->elem;
    Pitem  old    = q->head;

    if (q->head == q->tail) {
        q->head = NULL;
        q->tail = NULL;
    } else {
        q->head = q->head->next;
    }
    intFree(old);
    return retval;
}

static void _free(Pqueue q) {
    /* Drain any remaining items before freeing the queue struct */
    while (q->head) {
        Pitem next = q->head->next;
        intFree(q->head);
        q->head = next;
    }
    q->tail = NULL;
    intFree(q);
}

Pqueue queueInit(void) {
    Pqueue q = (Pqueue)intAlloc(sizeof(queue));
    if (!q) return NULL;
    q->head = NULL;
    q->tail = NULL;
    q->push = _push;
    q->pop  = _pop;
    q->free = _free;
    return q;
}