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

#include <config.h>
#include "common.h"
#include "queue.h"
#include "atomic.h"
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

static void wait_for_change(unsigned int *ptr, unsigned int val)
{
	while (read_once(ptr, __ATOMIC_RELAXED) == val);
}

static void sleep_consumer(struct queue *q)
{
	pthread_mutex_lock(&q->mx);
	pthread_cond_wait(&q->cond, &q->mx);
	pthread_mutex_unlock(&q->mx);
}

static void sleep_producer(struct queue *q)
{
	UNUSED(q);
	/* sleep_consumer(q); */
}

static void wake_consumer(struct queue *q)
{
	pthread_mutex_lock(&q->mx);
	pthread_cond_signal(&q->cond);
	pthread_mutex_unlock(&q->mx);
}

static void wake_producer(struct queue *q)
{
	UNUSED(q);
	/* wake_consumer(q); */
}

void queue_init(struct queue *q)
{
	memset(q->elems, 0xFF, sizeof(q->elems));
	q->prod_waiting = q->prod_lock = 0;
	q->tail = q->cons_waiting = 0;
	/* We need at least one barrier here. */
	store_once(&q->head, 0, __ATOMIC_SEQ_CST);
	pthread_mutex_init(&q->mx, NULL);
	pthread_cond_init(&q->cond, NULL);
}

void queue_deinit(struct queue *q)
{
	pthread_mutex_destroy(&q->mx);
	pthread_cond_destroy(&q->cond);
}

void queue_insert(struct queue *q, void *elem)
{
	unsigned int t, h;

again:
	/* Bottom bit means someone is updating now. */
	while ((h = read_once(&q->head, __ATOMIC_RELAXED)) & 1) {
		atomic_inc(&q->prod_waiting, __ATOMIC_SEQ_CST);
		wait_for_change(&q->head, h);
		atomic_dec(&q->prod_waiting, __ATOMIC_RELAXED);
	}
	t = read_once(&q->tail, __ATOMIC_RELAXED);

	if (h == t + QUEUE_ELEMS * 2) {
		/* Full.  Wait. */
		atomic_inc(&q->prod_waiting, __ATOMIC_SEQ_CST);
		sleep_producer(q);
		wait_for_change(&q->tail, t);
		atomic_dec(&q->prod_waiting, __ATOMIC_RELAXED);
		goto again;
	}

	/* This tells everyone we're updating. */
	if (!compare_and_swap(&q->head, h, h+1, __ATOMIC_ACQUIRE))
		goto again;

	store_ptr(&q->elems[(h/2) % QUEUE_ELEMS], elem, __ATOMIC_RELAXED);
	assert(read_once(&q->head, __ATOMIC_RELAXED) == h + 1);
	store_once(&q->head, h+2, __ATOMIC_RELEASE);

	if (read_once(&q->cons_waiting, __ATOMIC_SEQ_CST))
		wake_consumer(q);
	return;
}

void *queue_remove(struct queue *q)
{
	unsigned int h, t;
	void *elem;

	do {
		for (;;) {
			/* Read tail before head (reverse how they change) */
			t = read_once(&q->tail, __ATOMIC_SEQ_CST);
			h = read_once(&q->head, __ATOMIC_SEQ_CST);
			if ((h & ~1) != t)
				break;
			/* Empty... */
			atomic_inc(&q->cons_waiting, __ATOMIC_SEQ_CST);
			sleep_consumer(q);
			wait_for_change(&q->head, h);
			atomic_dec(&q->cons_waiting, __ATOMIC_RELAXED);
		}
		assert(t < h);
		elem = read_ptr(&q->elems[(t/2) % QUEUE_ELEMS],
				__ATOMIC_SEQ_CST);
	} while (!compare_and_swap(&q->tail, t, t+2, __ATOMIC_SEQ_CST));

	if (q->prod_waiting)
		wake_producer(q);

	return elem;
}
