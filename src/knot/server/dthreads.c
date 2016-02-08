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

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <urcu.h>

#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif /* HAVE_PTHREAD_NP_H */

#include "knot/server/dthreads.h"
#include "libknot/libknot.h"

/* BSD cpu set compatibility. */
#if defined(HAVE_CPUSET_BSD)
typedef cpuset_t cpu_set_t;
#endif

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
		return KNOT_EINVAL;
	}

	// Cancel with lone thread
	dt_unit_t *unit = thread->unit;
	if (unit == 0) {
		return KNOT_ENOTSUP;
	}

	// Cancel current runnable if running
	pthread_mutex_lock(&unit->_notify_mx);
	lock_thread_rw(thread);
	if (thread->state & (ThreadIdle | ThreadActive)) {

		// Update state
		thread->state = state;
		unlock_thread_rw(thread);

		// Notify thread
		pthread_cond_broadcast(&unit->_notify);
		pthread_mutex_unlock(&unit->_notify_mx);
	} else {
		/* Unable to update thread, it is already dead. */
		unlock_thread_rw(thread);
		pthread_mutex_unlock(&unit->_notify_mx);
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
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

	// Unblock SIGALRM for synchronization
	sigset_t mask;
	(void)sigemptyset(&mask);
	sigaddset(&mask, SIGALRM);
	pthread_sigmask(SIG_UNBLOCK, &mask, NULL);

	rcu_register_thread();

	/* Drop capabilities except FS access. */
#ifdef HAVE_CAP_NG_H
	if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
		capng_type_t tp = CAPNG_EFFECTIVE|CAPNG_PERMITTED;
		capng_clear(CAPNG_SELECT_BOTH);
		capng_update(CAPNG_ADD, tp, CAP_DAC_OVERRIDE);
		capng_apply(CAPNG_SELECT_BOTH);
	}
#endif /* HAVE_CAP_NG_H */

	// Run loop
	for (;;) {

		// Check thread state
		lock_thread_rw(thread);
		if (thread->state == ThreadDead) {
			unlock_thread_rw(thread);
			break;
		}

		// Update data
		thread->data = thread->_adata;
		runnable_t _run = thread->run;

		// Start runnable if thread is marked Active
		if ((thread->state == ThreadActive) && (thread->run != 0)) {
			unlock_thread_rw(thread);
			_run(thread);
		} else {
			unlock_thread_rw(thread);
		}

		// If the runnable was cancelled, start new iteration
		lock_thread_rw(thread);
		if (thread->state & ThreadCancelled) {
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
			pthread_cond_wait(&unit->_notify, &unit->_notify_mx);
			pthread_mutex_unlock(&unit->_notify_mx);
		} else {
			unlock_thread_rw(thread);
			pthread_mutex_unlock(&unit->_notify_mx);
		}
	}

	// Thread destructor
	if (thread->destruct) {
		thread->destruct(thread);
	}

	// Report thread state change
	unit_signalize_change(unit);
	lock_thread_rw(thread);
	thread->state |= ThreadJoinable;
	unlock_thread_rw(thread);
	rcu_unregister_thread();

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
	//pthread_attr_setinheritsched(attr, PTHREAD_INHERIT_SCHED);
	//pthread_attr_setschedpolicy(attr, SCHED_OTHER);
	pthread_attr_setstacksize(attr, 1024*1024);
	return thread;
}

/*! \brief Delete single thread. */
static void dt_delete_thread(dthread_t **thread)
{
	// Check
	if (!thread || !*thread) {
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

static dt_unit_t *dt_create_unit(int count)
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
	unit->threads = calloc(count, sizeof(dthread_t *));
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

dt_unit_t *dt_create(int count, runnable_t runnable, runnable_t destructor, void *data)
{
	// Check count
	if (count <= 0) {
		return 0;
	}

	// Create unit
	dt_unit_t *unit = dt_create_unit(count);
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
		thread->destruct = destructor;
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
	pthread_mutex_destroy(&d_unit->_mx);

	// Deinit conditions
	pthread_cond_destroy(&d_unit->_notify);
	pthread_cond_destroy(&d_unit->_report);

	// Free memory
	free(d_unit->threads);
	free(d_unit);
	*unit = 0;
}

static int dt_start_id(dthread_t *thread)
{
	// Check input
	if (thread == 0) {
		return KNOT_EINVAL;
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
		unlock_thread_rw(thread);
		return 0;
	}

	// Start thread
	sigset_t mask_all, mask_old;
	sigfillset(&mask_all);
	pthread_sigmask(SIG_SETMASK, &mask_all, &mask_old);
	int res = pthread_create(&thread->_thr,  /* pthread_t */
	                         &thread->_attr, /* pthread_attr_t */
	                         thread_ep,      /* routine: thread_ep */
	                         thread);        /* passed object: dthread_t */
	pthread_sigmask(SIG_SETMASK, &mask_old, NULL);

	// Unlock thread
	unlock_thread_rw(thread);
	return res;
}

int dt_start(dt_unit_t *unit)
{
	// Check input
	if (unit == 0) {
		return KNOT_EINVAL;
	}

	// Lock unit
	pthread_mutex_lock(&unit->_notify_mx);
	dt_unit_lock(unit);
	for (int i = 0; i < unit->size; ++i) {

		dthread_t *thread = unit->threads[i];
		int res = dt_start_id(thread);
		if (res != 0) {
			dt_unit_unlock(unit);
			pthread_mutex_unlock(&unit->_notify_mx);
			return res;
		}
	}

	// Unlock unit
	dt_unit_unlock(unit);
	pthread_cond_broadcast(&unit->_notify);
	pthread_mutex_unlock(&unit->_notify_mx);
	return KNOT_EOK;
}

int dt_signalize(dthread_t *thread, int signum)
{
	// Check input
	if (thread == 0) {
		return KNOT_EINVAL;
	}

	int ret = pthread_kill(thread->_thr, signum);

	/* Not thread id found or invalid signum. */
	if (ret == EINVAL || ret == ESRCH) {
		return KNOT_EINVAL;
	}

	/* Generic error. */
	if (ret < 0) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int dt_join(dt_unit_t *unit)
{
	// Check input
	if (unit == 0) {
		return KNOT_EINVAL;
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
				pthread_join(thread->_thr, 0);
				lock_thread_rw(thread);
				thread->state = ThreadJoined;
				unlock_thread_rw(thread);
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

	return KNOT_EOK;
}

int dt_stop(dt_unit_t *unit)
{
	// Check unit
	if (unit == 0) {
		return KNOT_EINVAL;
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
			dt_signalize(thread, SIGALRM);
		}
		unlock_thread_rw(thread);
	}

	// Unlock unit
	dt_unit_unlock(unit);

	// Broadcast notification
	pthread_cond_broadcast(&unit->_notify);
	pthread_mutex_unlock(&unit->_notify_mx);

	return KNOT_EOK;
}

int dt_setaffinity(dthread_t *thread, unsigned* cpu_id, size_t cpu_count)
{
	if (thread == NULL) {
		return KNOT_EINVAL;
	}

#ifdef HAVE_PTHREAD_SETAFFINITY_NP
	int ret = -1;

/* Linux, FreeBSD interface. */
#if defined(HAVE_CPUSET_LINUX) || defined(HAVE_CPUSET_BSD)
	cpu_set_t set;
	CPU_ZERO(&set);
	for (unsigned i = 0; i < cpu_count; ++i) {
		CPU_SET(cpu_id[i], &set);
	}
	ret = pthread_setaffinity_np(thread->_thr, sizeof(cpu_set_t), &set);
/* NetBSD interface. */
#elif defined(HAVE_CPUSET_NETBSD)
	cpuset_t *set = cpuset_create();
	if (set == NULL) {
		return KNOT_ENOMEM;
	}
	cpuset_zero(set);
	for (unsigned i = 0; i < cpu_count; ++i) {
		cpuset_set(cpu_id[i], set);
	}
	ret = pthread_setaffinity_np(thread->_thr, cpuset_size(set), set);
	cpuset_destroy(set);
#endif /* interface */

	if (ret < 0) {
		return KNOT_ERROR;
	}

#else /* HAVE_PTHREAD_SETAFFINITY_NP */
	return KNOT_ENOTSUP;
#endif

	return KNOT_EOK;
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
		return KNOT_EINVAL;
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
			unlock_thread_rw(thread);
			pthread_join(thread->_thr, 0);
			lock_thread_rw(thread);
			thread->state = ThreadJoined;
			unlock_thread_rw(thread);
		} else {
			unlock_thread_rw(thread);
		}
	}

	// Unlock unit
	dt_unit_unlock(unit);

	return KNOT_EOK;
}

int dt_online_cpus(void)
{
	int ret = -1;
/* Linux, Solaris, OS X 10.4+ */
#ifdef _SC_NPROCESSORS_ONLN
	ret = (int) sysconf(_SC_NPROCESSORS_ONLN);
#else
/* FreeBSD, NetBSD, OpenBSD, OS X < 10.4 */
#if HAVE_SYSCTLBYNAME
	size_t rlen = sizeof(int);
	if (sysctlbyname("hw.ncpu", &ret, &rlen, NULL, 0) < 0) {
		ret = -1;
	}
#endif
#endif
	return ret;
}

int dt_optimal_size(void)
{
	int ret = dt_online_cpus();
	if (ret > 1) {
		return ret;
	}

	return DEFAULT_THR_COUNT;
}

int dt_is_cancelled(dthread_t *thread)
{
	// Check input
	if (thread == 0) {
		return 0;
	}

	return thread->state & ThreadCancelled; /* No need to be locked. */
}

unsigned dt_get_id(dthread_t *thread)
{
	if (thread == NULL || thread->unit == NULL) {
		return 0;
	}

	dt_unit_t *unit = thread->unit;
	for(int tid = 0; tid < unit->size; ++tid) {
		if (thread == unit->threads[tid]) {
			return tid;
		}
	}

	return 0;
}

int dt_unit_lock(dt_unit_t *unit)
{
	// Check input
	if (unit == 0) {
		return KNOT_EINVAL;
	}

	int ret = pthread_mutex_lock(&unit->_mx);

	/* Map errors. */
	if (ret < 0) {
		return knot_map_errno();
	}

	return KNOT_EOK;
}

int dt_unit_unlock(dt_unit_t *unit)
{
	// Check input
	if (unit == 0) {
		return KNOT_EINVAL;
	}

	int ret = pthread_mutex_unlock(&unit->_mx);

	/* Map errors. */
	if (ret < 0) {
		return knot_map_errno();
	}

	return KNOT_EOK;
}
