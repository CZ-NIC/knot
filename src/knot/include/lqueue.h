#pragma once
#include "knot/include/atomic.h"

#pragma pack(push, 1)
/*!
 * \brief To maintain performance, size is setup to uint16_t to keep atomic operation to 8 byte.
 * This allows the size of the queue to be restricted to 2^16 - 2. If larger size is needed, the type needs to be changed.
 */
#define KNOTD_LOCKLESS_QUEUE_COUNT_TYPE uint16_t

/*!
 * \brief Queue state.
 */
typedef struct knotd_lockless_queue_state {
	KNOT_ALIGN(sizeof(KNOTD_LOCKLESS_QUEUE_COUNT_TYPE) * 4)
    KNOTD_LOCKLESS_QUEUE_COUNT_TYPE head;               /*!< Head where insertion can be performed. */
    KNOTD_LOCKLESS_QUEUE_COUNT_TYPE tail;               /*!< Tail where removal can be performed. */
    KNOTD_LOCKLESS_QUEUE_COUNT_TYPE head_reserved;      /*!< Head reservation to insert. */
    KNOTD_LOCKLESS_QUEUE_COUNT_TYPE unused;             /*!< To ensure queue state size is in power of 2 for atomic operation. */
} knotd_lockless_queue_state_t;

/*!
 * \brief The lockless queue structure. Allocate the queue by calling knotd_lockless_queue_create.
 *
 * The queue is implemented using circular queue. The only variation is insertion cannot be performed atomically for following reason.
 * If an item need to be inserted at head+1 position and update the head to head+1, these two operation have to performed in two location.
 * The object insertion needs to be performed on item[head+1], but update to head need to be performed in state.
 * These two memory are located too far apart to be used in single atomic memory operation.
 * Performing these operation independently will cause race condition.
 * If we write to array before incrementing head, two threads can write to items array in head+1, say thread1 followed by thread2, but head could be incremented by thread1.
 * But what is left in item[head+1] is from thread2. So thread1's object is lost when it completes, but thread2 object may be duplicated as it retries and inserts again.
 * if we write to array after incrementing head, a pop operation might see the head != tail, and hence assume head has the data and consume it before it is initialized.
 *
 * To eliminate the race condition, create a reservation first by incrementing head_reserved.
 * This guarantees that no one will use the insertion position other than the thread that reserved it. Also pop will not consider reserved areas, but only committed areas (i.e. head).
 * After reserving and setting the memory, the head needs to be moved. But the current thread can not move the head to its reserved position for following reason.
 *
 * Lets say initial state is (head=1, tail=1, head_reserved=1).
 * Thread 1 reserves position 2. (head=1, tail=1, head_reserved=2).
 * Thread 2 reserves position 3. (head=1, tail=1, head_reserved=3).
 * Thread 1 has not yet finished assigning value to array item at 2. If thread 2 completes assinging value to 3.
 * At this stage, if the head was set to 3. The pop operation will assume that memory in array index 2 is valid, which is still not assigned.
 * To overcome this issue, the threads are allowed to move the head to head_reserved only if head is one before reserved.
 * With this logic, thread 2 will spin until head = 2. Only thread that can make head to 2 is thread 1. Thread 1 will increment head to 2 only after setting array object at index 2.
 * This ensures the thread safety with added atomic operation and potential spin by a thread for another thread.
 */
typedef struct {
    KNOT_ATOMIC knotd_lockless_queue_state_t state;
    KNOTD_LOCKLESS_QUEUE_COUNT_TYPE size;
    void* items[];
} knotd_lockless_queue_t;
#pragma pack(pop)

/*!
 * \brief Create lockless queue structure.
 *
 * \param queue Queue to be initialized.
 * \param size Size of the max number of objects in queue to be supported. This is limited to 2^16 - 2.
 *
 * \retval 0 if successful.
 */
int knotd_lockless_queue_create(knotd_lockless_queue_t **queue, KNOTD_LOCKLESS_QUEUE_COUNT_TYPE size);

/*!
 * \brief Frees lockless queue structure.
 *
 * \param queue Queue previously created using call to knotd_lockless_queue_create.
 * \param size Size of the max number of objects in queue to be supported. This is limited to 2^16 - 2.
 *
 * \retval 0 if successful.
 */
void knotd_lockless_queue_delete(knotd_lockless_queue_t *queue);

/*!
 * \brief Enqueue an object into a queue.
 *
 * \param queue Queue previously created using call to knotd_lockless_queue_create.
 * \param item Item to be inserted.
 * \param first On return, if it is true, the object inserted is the first item in the queue currently.
 *
 * \retval 0 if successful.
 */
int knotd_lockless_queue_enqueue(knotd_lockless_queue_t *queue, void *item, bool *first);

/*!
 * \brief Dequeues an object from queue.
 *
 * \param queue Queue previously created using call to knotd_lockless_queue_create.
 *
 * \retval Item retrieved from queue, NULL if no object found.
 */
void* knotd_lockless_queue_dequeue(knotd_lockless_queue_t *queue);

/*!
 * \brief Get the number of objects in the queue.
 *
 * \param queue Queue previously created using call to knotd_lockless_queue_create.
 *
 * \retval Number of objects in the queue.
 */
KNOTD_LOCKLESS_QUEUE_COUNT_TYPE knotd_lockless_queue_count(knotd_lockless_queue_t *queue);
