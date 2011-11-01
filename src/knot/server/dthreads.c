/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "knot/common.h"
#include "knot/server/dthreads.h"
#include "knot/other/log.h"
#include "knot/other/error.h"

/*! \brief Lock thread state for R/W. */
static inline void lock_thread_rw(dthread_t *thread)
{
	pthread_mutex_lock(&thread->_mx);
}
/*! \brief Unlock thread state for R/W. */
static inline void unlock_thread_rw(dthread_t *thread)
{
	pthread_mutex_unlock(&thread->_mx);
}

/*! \brief Signalize thread state change. */
static inline void unit_signalize_change(dt_unit_t *unit)
{
	pthread_mutex_lock(&unit->_report_mx);
	pthread_cond_signal(&unit->_report);
	pthread_mutex_unlock(&unit->_report_mx);
}

/*!
 * \brief Update thread state with notification.
 * \param thread Given thread.
 * \param state New state for thread.
 * \retval 0 on success.
 * \retval <0 on error (EINVAL, ENOTSUP).
 */
static inline int dt_update_thread(dthread_t *thread, int state)
{
	// Check
	if (thread == 0) {
		return KNOTD_EINVAL;
	}

	// Cancel with lone thread
	dt_unit_t *unit = thread->unit;
	if (unit == 0) {
		return KNOTD_ENOTSUP;
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
		/* Unable to update thread, it is already dead. */
		unlock_thread_rw(thread);
		pthread_mutex_unlock(&unit->_notify_mx);
		return KNOTD_EINVAL;
	}

	return KNOTD_EOK;
}

/*!
 * \brief Thread entrypoint function.
 *
 * When a thread is created and started, it immediately enters this function.
 * Depending on thread state, it either enters runnable or
 * blocks until it is awakened.
 *
 * This function also handles "ThreadIdle" state to quickly suspend and resume
 * threads and mitigate thread creation costs. Also, thread runnable may
 * be changed to alter the thread behavior on runtime
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

	// Ignore specific signals (except SIGALRM)
	sigset_t ignset;
	sigemptyset(&ignset);
	sigaddset(&ignset, SIGINT);
	sigaddset(&ignset, SIGTERM);
	sigaddset(&ignset, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &ignset, 0); /*! \todo Review under BSD. */

	dbg_dt("dthreads: [%p] entered ep\n", thread);

	// Run loop
	for (;;) {

		// Check thread state
		lock_thread_rw(thread);
		if (thread->state == ThreadDead) {
			dbg_dt("dthreads: [%p] marked as dead\n", thread);
			unlock_thread_rw(thread);
			break;
		}

		// Update data
		thread->data = thread->_adata;
		runnable_t _run = thread->run;

		// Start runnable if thread is marked Active
		if ((thread->state == ThreadActive) && (thread->run != 0)) {
			unlock_thread_rw(thread);
			dbg_dt("dthreads: [%p] entering runnable\n", thread);
			_run(thread);
			dbg_dt("dthreads: [%p] exited runnable\n", thread);
		} else {
			unlock_thread_rw(thread);
		}

		// If the runnable was cancelled, start new iteration
		lock_thread_rw(thread);
		if (thread->state & ThreadCancelled) {
			dbg_dt("dthreads: [%p] cancelled\n", thread);
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
			dbg_dt("dthreads: [%p] going idle\n", thread);
			/*! \todo Check return value. */
			pthread_cond_wait(&unit->_notify, &unit->_notify_mx);
			pthread_mutex_unlock(&unit->_notify_mx);
			dbg_dt("dthreads: [%p] resumed from idle\n", thread);
		} else {
			unlock_thread_rw(thread);
			pthread_mutex_unlock(&unit->_notify_mx);
		}
	}

	// Report thread state change
	dbg_dt("dthreads: [%p] thread finished\n", thread);
	unit_signalize_change(unit);
	dbg_dt("dthreads: [%p] thread exited ep\n", thread);
	lock_thread_rw(thread);
	thread->state |= ThreadJoinable;
	unlock_thread_rw(thread);

	// Return
	return 0;
}

/*!
 * \brief Create single thread.
 * \retval New thread instance on success.
 * \retval NULL on error.
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

/*! \brief Delete single thread. */
static void dt_delete_thread(dthread_t **thread)
{
	// Check
	if (thread == 0) {
		return;
	}
	if (*thread == 0) {
		return;
	}

	dthread_t* thr = *thread;
	thr->unit = 0;
	*thread = 0;

	// Delete attribute
	pthread_attr_destroy(&(thr)->_attr);

	// Delete mutex
	pthread_mutex_destroy(&(thr)->_mx);

	// Free memory
	free(thr);
}

/*
 * Public APIs.
 */

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
		return KNOTD_EINVAL;
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
		dbg_dt("dthreads: growing from %d to %d threads\n",
		       unit->size, size);

		dthread_t **threads = realloc(unit->threads,
		                              size * sizeof(dthread_t *));
		if (threads == NULL) {
			dt_unit_unlock(unit);
			pthread_mutex_unlock(&unit->_notify_mx);
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
	dbg_dt("dthreads: shrinking from %d to %d threads\n",
	       unit->size, size);

	// New threads vector
	dthread_t **threads = malloc(size * sizeof(dthread_t *));
	if (threads == 0) {
		return KNOTD_ENOMEM;
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
				dbg_dt_verb("dthreads: [%p] dt_resize: elected\n",
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
				dbg_dt_verb("dthreads: [%p] dt_resize: "
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
		return KNOTD_EINVAL;
	}

	// Lock unit
	pthread_mutex_lock(&unit->_notify_mx);
	dt_unit_lock(unit);
	for (int i = 0; i < unit->size; ++i) {

		dthread_t *thread = unit->threads[i];
		int res = dt_start_id(thread);
		if (res != 0) {
			dbg_dt("dthreads: failed to create thread '%d'.", i);
			dt_unit_unlock(unit);
			pthread_mutex_unlock(&unit->_notify_mx);
			return res;
		}

		dbg_dt("dthreads: [%p] %s: thread started\n",
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
		return KNOTD_EINVAL;
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
		dbg_dt("dthreads: [%p] %s: refused to recreate thread\n",
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
		return KNOTD_EINVAL;
	}

	int ret = pthread_kill(thread->_thr, signum);

	/* Not thread id found or invalid signum. */
	if (ret == EINVAL || ret == ESRCH) {
		return KNOTD_EINVAL;
	}

	/* Generic error. */
	if (ret < 0) {
		return KNOTD_ERROR;
	}

	return KNOTD_EOK;
}

int dt_join(dt_unit_t *unit)
{
	// Check input
	if (unit == 0) {
		return KNOTD_EINVAL;
	}

	for (;;) {

		// Lock unit
		pthread_mutex_lock(&unit->_report_mx);
		dt_unit_lock(unit);

		// Browse threads
		int active_threads = 0;
		for (int i = 0; i < unit->size; ++i) {

			// Count active or cancelled but pending threads
			dthread_t *thread = unit->threads[i];
			lock_thread_rw(thread);
			if (thread->state & (ThreadActive|ThreadCancelled)) {
				++active_threads;
			}

			// Reclaim dead threads, but only fast
			if (thread->state & ThreadJoinable) {
				unlock_thread_rw(thread);
				dbg_dt_verb("dthreads: [%p] %s: reclaiming\n",
				         thread, __func__);
				pthread_join(thread->_thr, 0);
				dbg_dt("dthreads: [%p] %s: reclaimed\n",
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

	return KNOTD_EOK;
}

int dt_stop_id(dthread_t *thread)
{
	// Check input
	if (thread == 0) {
		return KNOTD_EINVAL;
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

	return KNOTD_EOK;
}

int dt_stop(dt_unit_t *unit)
{
	// Check unit
	if (unit == 0) {
		return KNOTD_EINVAL;
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
			dbg_dt("dthreads: [%p] %s: stopping thread\n",
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

	return KNOTD_EOK;
}

int dt_setprio(dthread_t *thread, int prio)
{
	// Check input
	if (thread == 0) {
		return KNOTD_EINVAL;
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

	/* Map error codes. */
	if (ret < 0) {
		dbg_dt("dthreads: [%p] %s(%d): failed",
		       thread, __func__, prio);

		/* Map "not supported". */
		if (ret == ENOTSUP) {
			return KNOTD_ENOTSUP;
		}

		return KNOTD_EINVAL;
	}

	return KNOTD_EOK;
}

int dt_repurpose(dthread_t *thread, runnable_t runnable, void *data)
{
	// Check
	if (thread == 0) {
		return KNOTD_EINVAL;
	}

	// Stop here if thread isn't a member of a unit
	dt_unit_t *unit = thread->unit;
	if (unit == 0) {
		lock_thread_rw(thread);
		thread->state = ThreadActive | ThreadCancelled;
		unlock_thread_rw(thread);
		return KNOTD_ENOTSUP;
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

	return KNOTD_EOK;
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
		return KNOTD_EINVAL;
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
			dbg_dt_verb("dthreads: [%p] %s: reclaiming thread\n",
			            thread, __func__);
			unlock_thread_rw(thread);
			pthread_join(thread->_thr, 0);
			dbg_dt("dthreads: [%p] %s: thread reclaimed\n",
			       thread, __func__);
			thread->state = ThreadJoined;
		} else {
			unlock_thread_rw(thread);
		}
	}

	dbg_dt_verb("dthreads: compact: joined all threads\n");

	// Unlock unit
	dt_unit_unlock(unit);

	return KNOTD_EOK;
}

int dt_optimal_size()
{
#ifdef _SC_NPROCESSORS_ONLN
	int ret = (int) sysconf(_SC_NPROCESSORS_ONLN);
	if (ret >= 1) {
		return ret + CPU_ESTIMATE_MAGIC;
	}
#endif
	dbg_dt("dthreads: failed to fetch the number of online CPUs.");
	return DEFAULT_THR_COUNT;
}

/*!
 * \todo Use memory barriers or asynchronous read-only access, locking
 *       poses a thread performance decrease by 1.31%.
 */

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
		return KNOTD_EINVAL;
	}

	int ret = pthread_mutex_lock(&unit->_mx);

	/* Map errors. */
	if (ret < 0) {
		return knot_map_errno(EINVAL, EAGAIN);
	}

	return KNOTD_EOK;
}

int dt_unit_unlock(dt_unit_t *unit)
{
	// Check input
	if (unit == 0) {
		return KNOTD_EINVAL;
	}

	int ret = pthread_mutex_unlock(&unit->_mx);

	/* Map errors. */
	if (ret < 0) {
		return knot_map_errno(EINVAL, EAGAIN);
	}

	return KNOTD_EOK;
}
