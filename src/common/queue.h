/*
 * Circular semi-lockless queue from Rusty Russel <rusty@rustcorp.com.au>
 * https://github.com/rustyrussell/ccan/tree/antithread
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifndef CCAN_ANTITHREAD_QUEUE_H
#define CCAN_ANTITHREAD_QUEUE_H
#include <stdlib.h>
#include <pthread.h>

#define QUEUE_ELEMS 32
struct queue {
	unsigned int head;
	unsigned int prod_waiting;
	unsigned int prod_lock;
	void *elems[QUEUE_ELEMS];
	unsigned int tail;
	unsigned int cons_waiting;
	pthread_mutex_t mx;
	pthread_cond_t cond;
};
typedef struct queue queue_t;

/**
 * queue_size - get queue size in bytes for given number of elements.
 * @num: number of elements.
 */
size_t queue_size(size_t num);

/**
 * queue_init - initialize queue in memory
 * @q: the memory.
 */
void queue_init(struct queue *q);

/**
 * queue_deinit - deinitialize queue
 * @q: the memory.
 */
void queue_deinit(struct queue *q);

/**
 * queue_insert - add an element to the queue
 * @q: the queue
 * @ptr: the pointer to add
 */
void queue_insert(struct queue *q, void *elem);

/**
 * queue_remove - remove an element to the queue
 * @q: the queue
 */
void *queue_remove(struct queue *q);

#endif /* CCAN_ANTITHREAD_QUEUE_H */
