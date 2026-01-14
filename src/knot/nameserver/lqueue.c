#include <stddef.h>
#include "knot/include/lqueue.h"
#include <assert.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Watomic-alignment"

int knotd_lockless_queue_create(knotd_lockless_queue_t **queue, KNOTD_LOCKLESS_QUEUE_COUNT_TYPE size) {
    assert(size < 0xFFFFU);
    size_t size_to_alloc = sizeof(knotd_lockless_queue_t) + ((size + 1) * sizeof(void*));
	if (posix_memalign( (void**)queue, 16, size_to_alloc) != 0) {
		return ENOMEM;
	}

	memset((void*)*queue, 0, sizeof(knotd_lockless_queue_t));
    (*queue)->size = size + 1;
	return 0;
}

void knotd_lockless_queue_delete(knotd_lockless_queue_t *queue)
{
    free(queue);
}

int knotd_lockless_queue_enqueue(knotd_lockless_queue_t *queue, void *item, bool *first)
{
    // Make a reservation
    knotd_lockless_queue_state_t state, target_state;
    KNOTD_LOCKLESS_QUEUE_COUNT_TYPE prev_head, insert_pos;

    KNOT_ATOMIC_GET_RELAXED(&queue->state, state);
    do
    {
        insert_pos = (state.head_reserved + 1) % queue->size;
        if (insert_pos == state.tail)
        {
            return ENOMEM; // queue is full
        }

        prev_head = state.head_reserved;
        target_state = state;
        target_state.head_reserved = insert_pos;
    } while (!KNOT_ATOMIC_COMPARE_EXCHANGE_WEAK(&queue->state, state, target_state));

    // save the object in reserved position
    queue->items[insert_pos] = item;

    // Commit the progress, only if all previous reservations have committed
    do
    {
        KNOT_ATOMIC_GET_RELAXED(&queue->state, state);
    } while (state.head != prev_head); // Prev reservation is not yet committed

    do
    {
        target_state = state;
        target_state.head = insert_pos;
    } while (!KNOT_ATOMIC_COMPARE_EXCHANGE_WEAK(&queue->state, state, target_state));

    *first = state.head == state.tail;

    return 0;
}

void* knotd_lockless_queue_dequeue(knotd_lockless_queue_t *queue) {
    knotd_lockless_queue_state_t state, target_state;
    void *item;

    KNOT_ATOMIC_GET_RELAXED(&queue->state, state);

    do
    {
        if (state.head == state.tail)
        {
            return NULL;
        }

        target_state = state;
        target_state.tail = (target_state.tail + 1) % queue->size;
        item = queue->items[target_state.tail];
    } while (!KNOT_ATOMIC_COMPARE_EXCHANGE_WEAK(&queue->state, state, target_state));

    return item;
}

KNOTD_LOCKLESS_QUEUE_COUNT_TYPE knotd_lockless_queue_count(knotd_lockless_queue_t *queue) {
    knotd_lockless_queue_state_t state;
    KNOT_ATOMIC_GET_RELAXED(&queue->state, state);

    return (queue->size + state.head - state.tail) % queue->size;
}