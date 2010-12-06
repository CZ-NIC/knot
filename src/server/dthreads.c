#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "dthreads.h"
#include "common.h"
#include "log.h"

/* Lock thread state for R/W. */
static inline void lock_thread_rw(dthread_t *thread)
{
	pthread_mutex_lock(&thread->_mx);
}
/* Unlock thread state for R/W. */
static inline void unlock_thread_rw(dthread_t *thread)
{
	pthread_mutex_unlock(&thread->_mx);
}

/* Signalize thread state change. */
static inline void unit_signalize_change(dt_unit_t *unit)
{
	pthread_mutex_lock(&unit->_report_mx);
	pthread_cond_signal(&unit->_report);
	pthread_mutex_unlock(&unit->_report_mx);
}

/* Update thread state. */
static inline int dt_update_thread(dthread_t *thread, int state)
{
	// Check
	if (thread == 0) {
		return -1;
	}

	// Cancel with lone thread
	dt_unit_t *unit = thread->unit;
	if (unit == 0) {
		return 0;
	}

	// Cancel current runnable if running
	pthread_mutex_lock(&unit->_notify_mx);
	lock_thread_rw(thread);
	if (thread->state & (ThreadIdle | ThreadActive)) {

		// Update state
		thread->state = state;
		unlock_thread_rw(thread);

		// Notify thread
		dt_signalize(thread, SIGALRM);
		pthread_cond_broadcast(&unit->_notify);
		pthread_mutex_unlock(&unit->_notify_mx);
	} else {
		unlock_thread_rw(thread);
		pthread_mutex_lock(&unit->_notify_mx);
		return -1;
	}

	return 0;
}

/*
 * Thread entrypoint interrupt handler.
 */
static void thread_ep_intr(int s)
{
}

/*
 * Thread entrypoint function.
 * This is an Idle state of each thread.
 * Depending on thread state, runnable is run or
 * thread blocks until it is requested.
 */
static void *thread_ep(void *data)
{
	// Check data
	dthread_t *thread = (dthread_t *)data;
	if (thread == 0) {
		return 0;
	}

	// Check if is a member of unit
	dt_unit_t *unit = thread->unit;
	if (unit == 0) {
		return 0;
	}

	// Register service and signal handler
	struct sigaction sa;
	sa.sa_handler = thread_ep_intr;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGALRM, &sa, 0);

	debug_dt("dthreads: [%p] entered ep\n", thread);

	// Run loop
	for (;;) {

		// Check thread state
		lock_thread_rw(thread);
		if (thread->state == ThreadDead) {
			debug_dt("dthreads: [%p] marked as dead\n", thread);
			unlock_thread_rw(thread);
			break;
		}

		// Update data
		thread->data = thread->_adata;
		runnable_t _run = thread->run;

		// Start runnable if thread is marked Active
		if ((thread->state == ThreadActive) && (thread->run != 0)) {
			unlock_thread_rw(thread);
			debug_dt("dthreads: [%p] entering runnable\n", thread);
			_run(thread);
			debug_dt("dthreads: [%p] exited runnable\n", thread);
		} else {
			unlock_thread_rw(thread);
		}

		// If the runnable was cancelled, start new iteration
		lock_thread_rw(thread);
		if (thread->state & ThreadCancelled) {
			debug_dt("dthreads: [%p] cancelled\n", thread);
			thread->state &= ~ThreadCancelled;
			unlock_thread_rw(thread);
			continue;
		}
		unlock_thread_rw(thread);

		// Runnable finished without interruption, mark as Idle
		pthread_mutex_lock(&unit->_notify_mx);
		lock_thread_rw(thread);
		if (thread->state & ThreadActive) {
			thread->state &= ~ThreadActive;
			thread->state |= ThreadIdle;
		}

		// Go to sleep if idle
		if (thread->state & ThreadIdle) {
			unlock_thread_rw(thread);

			// Signalize state change
			unit_signalize_change(unit);

			// Wait for notification from unit
			debug_dt("dthreads: [%p] going idle\n", thread);
			pthread_cond_wait(&unit->_notify, &unit->_notify_mx);
			pthread_mutex_unlock(&unit->_notify_mx);
			debug_dt("dthreads: [%p] resumed from idle\n", thread);
		} else {
			unlock_thread_rw(thread);
			pthread_mutex_unlock(&unit->_notify_mx);
		}
	}

	// Report thread state change
	debug_dt("dthreads: [%p] thread finished\n", thread);
	unit_signalize_change(unit);
	debug_dt("dthreads: [%p] thread exited ep\n", thread);
	lock_thread_rw(thread);
	thread->state |= ThreadJoinable;
	unlock_thread_rw(thread);

	// Return
	return 0;
}

/*!
 * \brief Create single thread.
 * \return New thread instance or 0.
 * \private
 */
static dthread_t *dt_create_thread(dt_unit_t *unit)
{
	// Alloc thread
	dthread_t *thread = malloc(sizeof(dthread_t));
	if (thread == 0) {
		return 0;
	}

	memset(thread, 0, sizeof(dthread_t));

	// Blank thread state
	thread->state = ThreadJoined;
	pthread_mutex_init(&thread->_mx, 0);

	// Set membership in unit
	thread->unit = unit;

	// Initialize attribute
	pthread_attr_t *attr = &thread->_attr;
	pthread_attr_init(attr);
	pthread_attr_setinheritsched(attr, PTHREAD_INHERIT_SCHED);
	pthread_attr_setschedpolicy(attr, SCHED_OTHER);
	return thread;
}

/*!
 * \brief Delete single thread.
 * \private
 */
static void dt_delete_thread(dthread_t **thread)
{
	// Check
	if (thread == 0) {
		return;
	}
	if (*thread == 0) {
		return;
	}

	// Delete attribute
	pthread_attr_destroy(&(*thread)->_attr);

	// Delete mutex
	pthread_mutex_destroy(&(*thread)->_mx);

	// Free memory
	free(*thread);
	*thread = 0;
}

dt_unit_t *dt_create(int count)
{
	// Check count
	if (count <= 0) {
		return 0;
	}

	dt_unit_t *unit = malloc(sizeof(dt_unit_t));
	if (unit == 0) {
		return 0;
	}

	// Initialize conditions
	if (pthread_cond_init(&unit->_notify, 0) != 0) {
		free(unit);
		return 0;
	}
	if (pthread_cond_init(&unit->_report, 0) != 0) {
		pthread_cond_destroy(&unit->_notify);
		free(unit);
		return 0;
	}

	// Initialize mutexes
	if (pthread_mutex_init(&unit->_notify_mx, 0) != 0) {
		pthread_cond_destroy(&unit->_notify);
		pthread_cond_destroy(&unit->_report);
		free(unit);
		return 0;
	}
	if (pthread_mutex_init(&unit->_report_mx, 0) != 0) {
		pthread_cond_destroy(&unit->_notify);
		pthread_cond_destroy(&unit->_report);
		pthread_mutex_destroy(&unit->_notify_mx);
		free(unit);
		return 0;
	}
	if (pthread_mutex_init(&unit->_mx, 0) != 0) {
		pthread_cond_destroy(&unit->_notify);
		pthread_cond_destroy(&unit->_report);
		pthread_mutex_destroy(&unit->_notify_mx);
		pthread_mutex_destroy(&unit->_report_mx);
		free(unit);
		return 0;
	}

	// Save unit size
	unit->size = count;

	// Alloc threads
	unit->threads = malloc(count * sizeof(dthread_t *));
	if (unit->threads == 0) {
		pthread_cond_destroy(&unit->_notify);
		pthread_cond_destroy(&unit->_report);
		pthread_mutex_destroy(&unit->_notify_mx);
		pthread_mutex_destroy(&unit->_report_mx);
		pthread_mutex_destroy(&unit->_mx);
		free(unit);
		return 0;
	}

	// Initialize threads
	int init_success = 1;
	for (int i = 0; i < count; ++i) {
		unit->threads[i] = dt_create_thread(unit);
		if (unit->threads[i] == 0) {
			init_success = 0;
			break;
		}
	}

	// Check thread initialization
	if (!init_success) {

		// Delete created threads
		for (int i = 0; i < count; ++i) {
			dt_delete_thread(&unit->threads[i]);
		}

		// Free rest of the unit
		pthread_cond_destroy(&unit->_notify);
		pthread_cond_destroy(&unit->_report);
		pthread_mutex_destroy(&unit->_notify_mx);
		pthread_mutex_destroy(&unit->_report_mx);
		pthread_mutex_destroy(&unit->_mx);
		free(unit->threads);
		free(unit);
		return 0;
	}

	return unit;
}

dt_unit_t *dt_create_coherent(int count, runnable_t runnable, void *data)
{
	// Check count
	if (count <= 0) {
		return 0;
	}

	// Create unit
	dt_unit_t *unit = dt_create(count);
	if (unit == 0) {
		return 0;
	}

	// Set threads common purpose
	pthread_mutex_lock(&unit->_notify_mx);
	dt_unit_lock(unit);

	for (int i = 0; i < count; ++i) {
		dthread_t *thread = unit->threads[i];
		lock_thread_rw(thread);
		thread->run = runnable;
		thread->_adata = data;
		unlock_thread_rw(thread);
	}

	dt_unit_unlock(unit);
	pthread_mutex_unlock(&unit->_notify_mx);

	return unit;
}

void dt_delete(dt_unit_t **unit)
{
	/*
	 *  All threads must be stopped or idle at this point,
	 *  or else the behavior is undefined.
	 *  Sorry.
	 */

	// Check
	if (unit == 0) {
		return;
	}
	if (*unit == 0) {
		return;
	}

	// Compact and reclaim idle threads
	dt_unit_t *d_unit = *unit;
	dt_compact(d_unit);

	// Delete threads
	for (int i = 0; i < d_unit->size; ++i) {
		dt_delete_thread(&d_unit->threads[i]);
	}

	// Deinit mutexes
	pthread_mutex_destroy(&d_unit->_notify_mx);
	pthread_mutex_destroy(&d_unit->_report_mx);

	// Deinit conditions
	pthread_cond_destroy(&d_unit->_notify);
	pthread_cond_destroy(&d_unit->_report);

	// Free memory
	free(d_unit->threads);
	free(d_unit);
	*unit = 0;
}

int dt_resize(dt_unit_t *unit, int size)
{
	// Check input
	if (unit == 0 || size <= 0) {
		return -1;
	}

	// Evaluate delta
	int delta = unit->size - size;

	// Same size
	if (delta == 0) {
		return 0;
	}

	// Unit expansion
	if (delta < 0) {

		// Lock unit
		pthread_mutex_lock(&unit->_notify_mx);
		dt_unit_lock(unit);

		// Realloc threads
		debug_dt("dt_resize: growing from %d to %d threads\n",
		         unit->size, size);

		dthread_t **threads = realloc(unit->threads,
		                              size * sizeof(dthread_t *));
		if (threads == 0) {
			return -1;
		}

		// Reassign
		unit->threads = threads;

		// Create new threads
		for (int i = unit->size; i < size; ++i) {
			threads[i] = dt_create_thread(unit);
		}

		// Update unit
		unit->size = size;
		dt_unit_unlock(unit);
		pthread_mutex_unlock(&unit->_notify_mx);
		return 0;
	}


	// Unit shrinking
	int remaining = size;
	debug_dt("dt_resize: shrinking from %d to %d threads\n",
		 unit->size, size);

	// New threads vector
	dthread_t **threads = malloc(size * sizeof(dthread_t *));
	if (threads == 0) {
		return -1;
	}

	// Lock unit
	pthread_mutex_lock(&unit->_notify_mx);
	dt_unit_lock(unit);

	// Iterate while there is space in new unit
	memset(threads, 0, size * sizeof(dthread_t *));
	int threshold = ThreadActive;
	for (;;) {

		// Find threads matching given criterias
		int inspected = 0;
		for (int i = 0; i < unit->size; ++i) {

			// Get thread
			dthread_t *thread = unit->threads[i];
			if (thread == 0) {
				continue;
			}

			// Count thread as inspected
			++inspected;

			lock_thread_rw(thread);

			// Populate with matching threads
			if ((remaining > 0) &&
			    (!threshold || (thread->state & threshold))) {

				// Append to new vector
				threads[size - remaining] = thread;
				--remaining;

				// Invalidate in old vector
				unit->threads[i] = 0;
				debug_dt("dthreads: [%p] dt_resize: elected\n",
				         thread);

			} else if (remaining <= 0) {

				// Not enough space, delete thread
				if (thread->state & ThreadDead) {
					unlock_thread_rw(thread);
					--inspected;
					continue;
				}

				// Signalize thread to stop
				thread->state = ThreadDead | ThreadCancelled;
				dt_signalize(thread, SIGALRM);
				debug_dt("dthreads: [%p] dt_resize: "
				         "is discarded\n", thread);
			}

			// Unlock thread and continue
			unlock_thread_rw(thread);
		}

		// Finished inspecting running threads
		if (inspected == 0) {
			break;
		}

		// Lower threshold
		switch (threshold) {
		case ThreadActive:
			threshold = ThreadIdle;
			break;
		case ThreadIdle:
			threshold = ThreadDead;
			break;
		default:
			threshold = ThreadJoined;
			break;
		}
	}

	// Notify idle threads to wake up
	pthread_cond_broadcast(&unit->_notify);
	pthread_mutex_unlock(&unit->_notify_mx);

	// Join discarded threads
	for (int i = 0; i < unit->size; ++i) {

		// Get thread
		dthread_t *thread = unit->threads[i];
		if (thread == 0) {
			continue;
		}

		pthread_join(thread->_thr, 0);
		thread->state = ThreadJoined;

		// Delete thread
		dt_delete_thread(&thread);
		unit->threads[i] = 0;
	}

	// Reassign unit threads vector
	unit->size = size;
	free(unit->threads);
	unit->threads = threads;

	// Unlock unit
	dt_unit_unlock(unit);

	return 0;
}

int dt_start(dt_unit_t *unit)
{
	// Check input
	if (unit == 0) {
		return -1;
	}

	// Lock unit
	pthread_mutex_lock(&unit->_notify_mx);
	dt_unit_lock(unit);
	for (int i = 0; i < unit->size; ++i) {

		dthread_t *thread = unit->threads[i];
		int res = dt_start_id(thread);
		if (res != 0) {
			log_error("dthreads: %s: failed to create thread %d",
			          __func__, i);
			dt_unit_unlock(unit);
			return res;
		}

		debug_dt("dthreads: [%p] %s: thread started\n",
		         thread, __func__);
	}

	// Unlock unit
	dt_unit_unlock(unit);
	pthread_cond_broadcast(&unit->_notify);
	pthread_mutex_unlock(&unit->_notify_mx);
	return 0;
}

int dt_start_id(dthread_t *thread)
{
	// Check input
	if (thread == 0) {
		return -1;
	}

	lock_thread_rw(thread);

	// Update state
	int prev_state = thread->state;
	thread->state |= ThreadActive;
	thread->state &= ~ThreadIdle;
	thread->state &= ~ThreadDead;
	thread->state &= ~ThreadJoined;
	thread->state &= ~ThreadJoinable;

	// Do not re-create running threads
	if (prev_state != ThreadJoined) {
		debug_dt("dthreads: [%p] %s: refused to recreate thread\n",
		         thread, __func__);
		unlock_thread_rw(thread);
		return 0;
	}

	// Start thread
	int res = pthread_create(&thread->_thr,  /* pthread_t */
	                         &thread->_attr, /* pthread_attr_t */
	                         thread_ep,      /* routine: thread_ep */
	                         thread);        /* passed object: dthread_t */

	// Unlock thread
	unlock_thread_rw(thread);
	return res;
}

int dt_signalize(dthread_t *thread, int signum)
{
	// Check input
	if (thread == 0) {
		return -1;
	}

	return pthread_kill(thread->_thr, signum);
}

int dt_join(dt_unit_t *unit)
{
	// Check input
	if (unit == 0) {
		return -1;
	}

	for (;;) {

		// Lock unit
		pthread_mutex_lock(&unit->_report_mx);
		dt_unit_lock(unit);

		// Browse threads
		int active_threads = 0;
		for (int i = 0; i < unit->size; ++i) {

			// Count active threads
			dthread_t *thread = unit->threads[i];
			lock_thread_rw(thread);
			if (thread->state & ThreadActive) {
				++active_threads;
			}

			// Reclaim dead threads, but only fast
			if (thread->state & ThreadJoinable) {
				unlock_thread_rw(thread);
				debug_dt("dthreads: [%p] %s: reclaiming\n",
				         thread, __func__);
				pthread_join(thread->_thr, 0);
				debug_dt("dthreads: [%p] %s: reclaimed\n",
				         thread, __func__);
				thread->state = ThreadJoined;
			} else {
				unlock_thread_rw(thread);
			}
		}

		// Unlock unit
		dt_unit_unlock(unit);

		// Check result
		if (active_threads == 0) {
			pthread_mutex_unlock(&unit->_report_mx);
			break;
		}

		// Wait for a thread to finish
		pthread_cond_wait(&unit->_report, &unit->_report_mx);
		pthread_mutex_unlock(&unit->_report_mx);
	}

	return 0;
}

int dt_stop_id(dthread_t *thread)
{
	// Check input
	if (thread == 0) {
		return -1;
	}

	// Signalize active thread to stop
	lock_thread_rw(thread);
	if (thread->state & (ThreadIdle | ThreadActive)) {
		thread->state = ThreadDead | ThreadCancelled;
		dt_signalize(thread, SIGALRM);
	}
	unlock_thread_rw(thread);

	// Broadcast notification
	dt_unit_t *unit = thread->unit;
	if (unit != 0) {
		pthread_mutex_lock(&unit->_notify_mx);
		pthread_cond_broadcast(&unit->_notify);
		pthread_mutex_unlock(&unit->_notify_mx);
	}

	return 0;
}

int dt_stop(dt_unit_t *unit)
{
	// Check unit
	if (unit == 0) {
		return -1;
	}

	// Lock unit
	pthread_mutex_lock(&unit->_notify_mx);
	dt_unit_lock(unit);

	// Signalize all threads to stop
	for (int i = 0; i < unit->size; ++i) {

		// Lock thread
		dthread_t *thread = unit->threads[i];
		lock_thread_rw(thread);
		if (thread->state & (ThreadIdle | ThreadActive)) {
			thread->state = ThreadDead | ThreadCancelled;
			debug_dt("dthreads: [%p] %s: stopping thread\n",
			         thread, __func__);
			dt_signalize(thread, SIGALRM);
		}
		unlock_thread_rw(thread);
	}

	// Unlock unit
	dt_unit_unlock(unit);

	// Broadcast notification
	pthread_cond_broadcast(&unit->_notify);
	pthread_mutex_unlock(&unit->_notify_mx);

	return 0;
}

int dt_setprio(dthread_t *thread, int prio)
{
	// Check input
	if (thread == 0) {
		return -1;
	}

	// Clamp priority
	int policy = SCHED_FIFO;
	prio = MIN(MAX(sched_get_priority_min(policy), prio),
		   sched_get_priority_max(policy));

	// Update scheduler policy
	int ret = pthread_attr_setschedpolicy(&thread->_attr, policy);

	// Update priority
	if (ret >= 0) {
		struct sched_param sp;
		sp.sched_priority = prio;
		ret = pthread_attr_setschedparam(&thread->_attr, &sp);
	}

	// Report
	if (ret < 0) {
		debug_dt("dthreads: [%p] %s(%d): failed: %s",
		         thread, __func__, prio, strerror(errno));
	}

	return ret;
}

int dt_repurpose(dthread_t *thread, runnable_t runnable, void *data)
{
	// Check
	if (thread == 0) {
		return -1;
	}

	// Stop here if thread isn't a member of a unit
	dt_unit_t *unit = thread->unit;
	if (unit == 0) {
		lock_thread_rw(thread);
		thread->state = ThreadActive | ThreadCancelled;
		unlock_thread_rw(thread);
		return 0;
	}

	// Lock thread state changes
	pthread_mutex_lock(&unit->_notify_mx);
	lock_thread_rw(thread);

	// Repurpose it's object and runnable
	thread->run = runnable;
	thread->_adata = data;

	// Cancel current runnable if running
	if (thread->state & (ThreadIdle | ThreadActive)) {

		// Update state
		thread->state = ThreadActive | ThreadCancelled;
		unlock_thread_rw(thread);

		// Notify thread
		pthread_cond_broadcast(&unit->_notify);
		pthread_mutex_unlock(&unit->_notify_mx);
	} else {
		unlock_thread_rw(thread);
		pthread_mutex_unlock(&unit->_notify_mx);
	}

	return 0;
}

int dt_activate(dthread_t *thread)
{
	return dt_update_thread(thread, ThreadActive);
}

int dt_cancel(dthread_t *thread)
{
	return dt_update_thread(thread, ThreadIdle | ThreadCancelled);
}

int dt_compact(dt_unit_t *unit)
{
	// Check input
	if (unit == 0) {
		return -1;
	}

	// Lock unit
	pthread_mutex_lock(&unit->_notify_mx);
	dt_unit_lock(unit);

	// Reclaim all Idle threads
	for (int i = 0; i < unit->size; ++i) {

		// Locked state update
		dthread_t *thread = unit->threads[i];
		lock_thread_rw(thread);
		if (thread->state & (ThreadIdle)) {
			thread->state = ThreadDead | ThreadCancelled;
			dt_signalize(thread, SIGALRM);
		}
		unlock_thread_rw(thread);
	}

	// Notify all threads
	pthread_cond_broadcast(&unit->_notify);
	pthread_mutex_unlock(&unit->_notify_mx);

	// Join all threads
	for (int i = 0; i < unit->size; ++i) {

		// Reclaim all dead threads
		dthread_t *thread = unit->threads[i];
		lock_thread_rw(thread);
		if (thread->state & (ThreadDead)) {
			debug_dt("dthreads: [%p] %s: reclaiming thread\n",
			         __func__, thread);
			unlock_thread_rw(thread);
			pthread_join(thread->_thr, 0);
			debug_dt("dthreads: [%p] %s: thread reclaimed\n",
			         __func__, thread);
			thread->state = ThreadJoined;
		} else {
			unlock_thread_rw(thread);
		}
	}

	debug_dt("dthreads: compact: joined all threads\n");

	// Unlock unit
	dt_unit_unlock(unit);

	return 0;
}

int dt_optimal_size()
{
#ifdef _SC_NPROCESSORS_ONLN
	int ret = (int) sysconf(_SC_NPROCESSORS_ONLN);
	if (ret >= 1) {
		return ret + 1;
	}
#endif
	log_info("server: failed to estimate the number of online CPUs");
	return DEFAULT_THR_COUNT;
}

int dt_is_cancelled(dthread_t *thread)
{
	// Check input
	if (thread == 0) {
		return 0;
	}

	lock_thread_rw(thread);
	int ret = thread->state & ThreadCancelled;
	unlock_thread_rw(thread);
	return ret;
}

int dt_unit_lock(dt_unit_t *unit)
{
	// Check input
	if (unit == 0) {
		return -1;
	}

	return pthread_mutex_lock(&unit->_mx);
}

int dt_unit_unlock(dt_unit_t *unit)
{
	// Check input
	if (unit == 0) {
		return -1;
	}

	return pthread_mutex_unlock(&unit->_mx);
}
