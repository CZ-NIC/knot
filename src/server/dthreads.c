#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
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
    dt_unit_t* unit = thread->unit;
    if (unit == 0) {
        return 0;
    }

    // Register service and signal handler
    struct sigaction sa;
    sa.sa_handler = thread_ep_intr;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, 0);

    // Run loop
    for (;;) {

        // Check thread state
        lock_thread_rw(thread);
        if (thread->state & ThreadDead) {
            unlock_thread_rw(thread);
            break;
        }
        unlock_thread_rw(thread);

        // Update data
        lock_thread_rw(thread);
        thread->data = thread->_adata;

        // Start runnable if thread is marked Active
        if ((thread->state == ThreadActive) && (thread->run != 0)) {
            unlock_thread_rw(thread);
            thread->run(thread);
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
        lock_thread_rw(thread);
        if(thread->state & ThreadActive) {
            thread->state &= ~ThreadActive;
            thread->state |= ThreadIdle;
        }
        unlock_thread_rw(thread);

        // Report thread state change
        unit_signalize_change(unit);

        // Go to sleep if idle
        lock_thread_rw(thread);
        if (thread->state & ThreadIdle) {
            unlock_thread_rw(thread);

            // Wait for notification from unit
            pthread_mutex_lock(&unit->_notify_mx);
            pthread_cond_wait(&unit->_notify, &unit->_notify_mx);
            pthread_mutex_unlock(&unit->_notify_mx);
        } else {
            unlock_thread_rw(thread);
        }
    }

    // Report thread state change
    unit_signalize_change(unit);

    // Return
    return 0;
}

dt_unit_t *dt_create (int count)
{
    dt_unit_t *unit = malloc(sizeof(dt_unit_t));
    if (unit == 0)
        return 0;

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

    // Save unit size
    unit->size = count;

    // Alloc threads
    unit->threads = malloc(count * sizeof(dthread_t));
    if (unit->threads == 0) {
        pthread_cond_destroy(&unit->_notify);
        pthread_cond_destroy(&unit->_report);
        pthread_mutex_destroy(&unit->_notify_mx);
        pthread_mutex_destroy(&unit->_report_mx);
        free(unit);
        return 0;
    }

    // Blank threads memory region
    memset(unit->threads, 0, count * sizeof(dthread_t));

    // Initialize threads
    for (int i = 0; i < count; ++i) {

        // Blank thread state
        unit->threads[i].state = ThreadJoined;
        pthread_mutex_init(&unit->threads[i]._mx, 0);

        // Set membership in unit
        unit->threads[i].unit = unit;

        // Initialize attribute
        pthread_attr_t *attr = &unit->threads[i]._attr;
        pthread_attr_init(attr);
        pthread_attr_setinheritsched(attr, PTHREAD_INHERIT_SCHED);
        pthread_attr_setschedpolicy(attr, SCHED_OTHER);
    }

    return unit;
}

dt_unit_t *dt_create_coherent (int count, runnable_t runnable, void *data)
{
    // Create unit
    dt_unit_t *unit = dt_create(count);
    if (unit == 0)
        return 0;

    // Set threads common purpose
    for (int i = 0; i < count; ++i) {
        unit->threads[i].run = runnable;
        unit->threads[i]._adata = data;
    }

    return unit;
}

void dt_delete (dt_unit_t **unit)
{
    /*
     *  All threads must be stopped or idle at this point,
     *  or else the behavior is undefined.
     *  Sorry.
     */

    // Check
    if (unit == 0)
        return;
    if (*unit == 0)
        return;

    // Compact and reclaim idle threads
    dt_compact(*unit);

    // Free thread attributes
    dt_unit_t *d_unit = *unit;
    for (int i = 0; i < d_unit->size; ++i) {
       pthread_attr_destroy(&d_unit->threads[i]._attr);
       pthread_mutex_destroy(&d_unit->threads[i]._mx);
    }

    // Deinit mutexes
    pthread_mutex_destroy(&d_unit->_notify_mx);
    pthread_mutex_destroy(&d_unit->_report_mx);

    // Deinit conditions
    pthread_cond_destroy(&d_unit->_notify);
    pthread_cond_destroy(&d_unit->_report);

    // Free threads
    free(d_unit->threads);
    free(d_unit);
    *unit = 0;
}

int dt_start (dt_unit_t *unit)
{
    for (int i = 0; i < unit->size; ++i)
    {
        dthread_t* thr = &unit->threads[i];
        lock_thread_rw(thr);

        // Update state
        int prev_state = thr->state;
        thr->state |= ThreadActive;
        thr->state &= ~ThreadIdle;
        thr->state &= ~ThreadDead;
        thr->state &= ~ThreadJoined;

        // Do not re-create running threads
        if (prev_state != ThreadJoined) {
            unlock_thread_rw(thr);
            continue;
        }

        // Start thread
        int res = pthread_create(&thr->_thr,  /* pthread_t */
                                 &thr->_attr, /* pthread_attr_t */
                                 thread_ep,   /* routine: thread_ep */
                                 thr);        /* passed object: dthread_t */

        // Unlock thread
        unlock_thread_rw(thr);
        if (res != 0) {
            log_error("%s: failed to create thread %d", __func__, i);
            return res;
        }
    }

    return 0;
}

int dt_signalize (dthread_t *thread, int signum)
{
   return pthread_kill(thread->_thr, signum);
}

int dt_join (dt_unit_t *unit)
{
    for(;;) {

        // Lock threads state
        pthread_mutex_lock(&unit->_report_mx);

        // Browse threads
        int active_threads = 0;
        for (int i = 0; i < unit->size; ++i) {

            // Count active threads
            dthread_t *thread = &unit->threads[i];
            lock_thread_rw(thread);
            if(thread->state & ThreadActive)
                ++active_threads;

            // Reclaim dead threads
            if(thread->state & ThreadDead) {
                pthread_join(thread->_thr, 0);
                thread->state = ThreadJoined;
            }
            unlock_thread_rw(thread);
        }

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

int dt_stop (dt_unit_t *unit)
{
    // Stop all live threads
    int count = 0;
    for (int i = 0; i < unit->size; ++i) {

        lock_thread_rw(unit->threads + i);
        if(unit->threads[i].state > ThreadDead) {
            unit->threads[i].state = ThreadDead | ThreadCancelled;
            dt_signalize(unit->threads + i, SIGALRM);
            ++count;
        }
        unlock_thread_rw(unit->threads + i);
    }

    // Broadcast all idle threads signal to wake up
    pthread_mutex_lock(&unit->_notify_mx);
    pthread_cond_broadcast(&unit->_notify);
    pthread_mutex_unlock(&unit->_notify_mx);
    return count;
}

int dt_setprio (dthread_t* thread, int prio)
{
    // Clamp priority
    int policy = SCHED_FIFO;
    prio = MIN(MAX(sched_get_priority_min(policy), prio),
               sched_get_priority_max(policy));

    // Update scheduler policy
    int ret = pthread_attr_setschedpolicy(&thread->_attr, policy);
    if (ret < 0) {
        debug_server("%s(%p, %d) failed: %s",
                     __func__, thread, prio, strerror(errno));
    }

    // Update priority
    struct sched_param sp;
    sp.sched_priority = prio;
    ret = pthread_attr_setschedparam(&thread->_attr, &sp);
    if (ret < 0) {
        debug_server("%s(%p, %d) failed: %s",
                     __func__, thread, prio, strerror(errno));
    }

    return ret;
}

int dt_repurpose (dthread_t* thread, runnable_t runnable, void *data)
{
    // Check
    if (thread == 0)
        return -1;

    // Lock thread state changes
    lock_thread_rw(thread);

    // Repurpose it's object and runnable
    thread->run = runnable;
    thread->_adata = data;

    // Stop here if thread isn't a member of a unit
    dt_unit_t *unit = thread->unit;
    if (unit == 0) {
        thread->state = ThreadActive | ThreadCancelled;
        unlock_thread_rw(thread);
        return 0;
    }

    // Cancel current runnable if running
    if (thread->state > ThreadDead) {

        // Update state
        thread->state = ThreadActive | ThreadCancelled;
        unlock_thread_rw(thread);

        // Notify thread
        pthread_mutex_lock(&unit->_notify_mx);
        pthread_cond_broadcast(&unit->_notify);
        pthread_mutex_unlock(&unit->_notify_mx);
    } else {
        unlock_thread_rw(thread);
    }

    return 0;
}

int dt_cancel (dthread_t *thread)
{
    // Check
    if (thread == 0)
        return -1;

    // Cancel with lone thread
    dt_unit_t* unit = thread->unit;
    if (unit == 0)
        return 0;

    // Cancel current runnable if running
    lock_thread_rw(thread);
    if (thread->state > ThreadDead) {

        // Update state
        thread->state = ThreadIdle | ThreadCancelled;
        unlock_thread_rw(thread);

        // Notify thread
        pthread_mutex_lock(&unit->_notify_mx);
        dt_signalize(thread, SIGALRM);
        pthread_cond_broadcast(&unit->_notify);
        pthread_mutex_unlock(&unit->_notify_mx);
    } else {
        unlock_thread_rw(thread);
    }

    return 0;
}

int dt_compact (dt_unit_t *unit)
{
    // Reclaim all Idle threads
    for (int i = 0; i < unit->size; ++i) {

        // Locked state update
        lock_thread_rw(unit->threads + i);
        if(unit->threads[i].state > ThreadDead &&
           unit->threads[i].state < ThreadActive)
        {
            unit->threads[i].state = ThreadDead;
        }
        unlock_thread_rw(unit->threads + i);
    }

    // Notify all threads
    pthread_mutex_lock(&unit->_notify_mx);
    pthread_cond_broadcast(&unit->_notify);
    pthread_mutex_unlock(&unit->_notify_mx);

    // Join all threads
    for (int i = 0; i < unit->size; ++i) {

        // Reclaim all dead threads
        dthread_t *thread = &unit->threads[i];
        if(thread->state & ThreadDead) {
            pthread_join(thread->_thr, 0);
            thread->state = ThreadJoined;
        }
    }

    return 0;
}

int dt_optimal_size()
{
#ifdef _SC_NPROCESSORS_ONLN
   int ret = (int) sysconf(_SC_NPROCESSORS_ONLN);
   if(ret >= 1)
      return ret + 1;
#endif
   log_info("server: failed to estimate the number of online CPUs");
   return DEFAULT_THR_COUNT;
}

