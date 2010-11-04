#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include "dthreads.h"
#include "common.h"
#include "log.h"

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

    // Run loop
    while (thread->state != ThreadDead) {

        // Update data
        thread->_adata = thread->data;

        // Start runnable if thread is marked Active
        if ((thread->state & ThreadActive) && (thread->run != 0)) {
            thread->run(thread->_adata);
        }

        // If the runnable was cancelled, start new iteration
        if(thread->state & ThreadCancelled) {
            thread->state &= ~ThreadCancelled;
            continue;
        }

        // Wait for events if Idle and Cancelled
        if (thread->state & ThreadIdle) {
            pthread_mutex_lock(&unit->_isidle_mx);
            pthread_cond_wait(&unit->_isidle, &unit->_isidle_mx);
            pthread_mutex_unlock(&unit->_isidle_mx);
        }
    }

    // Let unit know thread is finished
    pthread_mutex_lock(&unit->_isdead_mx);
    pthread_cond_signal(&unit->_isdead);
    pthread_mutex_unlock(&unit->_isdead_mx);

    // Return
    return 0;
}

dt_unit_t *dt_create (int count)
{
    dt_unit_t *unit = malloc(sizeof(dt_unit_t));
    if (unit == 0)
        return 0;

    // Initialize conditions
    if (pthread_cond_init(&unit->_isidle, 0) != 0) {
        free(unit);
        return 0;
    }
    if (pthread_cond_init(&unit->_isdead, 0) != 0) {
        pthread_cond_destroy(&unit->_isidle);
        free(unit);
        return 0;
    }

    // Initialize mutexes
    if (pthread_mutex_init(&unit->_isidle_mx, 0) != 0) {
        pthread_cond_destroy(&unit->_isidle);
        pthread_cond_destroy(&unit->_isdead);
        free(unit);
        return 0;
    }
    if (pthread_mutex_init(&unit->_isdead_mx, 0) != 0) {
        pthread_cond_destroy(&unit->_isidle);
        pthread_cond_destroy(&unit->_isdead);
        pthread_mutex_destroy(&unit->_isidle_mx);
        free(unit);
        return 0;
    }

    // Save unit size
    unit->size = count;

    // Alloc threads
    unit->threads = malloc(count * sizeof(dthread_t));
    if (unit->threads == 0) {
        pthread_cond_destroy(&unit->_isidle);
        pthread_cond_destroy(&unit->_isdead);
        pthread_mutex_destroy(&unit->_isidle_mx);
        pthread_mutex_destroy(&unit->_isdead_mx);
        free(unit);
        return 0;
    }

    // Initialize threads
    memset(unit->threads, 0, count * sizeof(dthread_t));
    for (int i = 0; i < count; ++i) {

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
        unit->threads[i].data = data;
    }

    return unit;
}

void dt_delete (dt_unit_t **unit)
{
    /*
     *  All threads must be stopped at this point,
     *  or else the behavior is undefined.
     *  Sorry.
     */

    // Check
    if (unit == 0)
        return;
    if (*unit == 0)
        return;

    // Free thread attributes
    dt_unit_t *d_unit = *unit;
    for (int i = 0; i < d_unit->size; ++i) {
       pthread_attr_destroy(&d_unit->threads[i]._attr);
    }

    // Deinit mutexes
    pthread_mutex_destroy(&d_unit->_isidle_mx);
    pthread_mutex_destroy(&d_unit->_isdead_mx);

    // Deinit conditions
    pthread_cond_destroy(&d_unit->_isidle);
    pthread_cond_destroy(&d_unit->_isdead);

    // Free threads
    free(d_unit->threads);
    free(d_unit);
    *unit = NULL;
}

int dt_start (dt_unit_t *unit)
{
    for (int i = 0; i < unit->size; ++i)
    {
        // Update state
        dthread_t* thr = &unit->threads[i];
        thr->state = ThreadActive;

        // Start thread
        int res = pthread_create(&thr->_thr,  /* pthread_t */
                                 &thr->_attr, /* pthread_attr_t */
                                 thread_ep,   /* routine: thread_ep */
                                 thr);        /* passed object: dthread_t */
        if (res != 0) {
            log_error("%s: failed to create thread %d", __func__, i);
            return res;
        }
    }

    return 0;
}

int dt_signalize (dt_unit_t *unit, int signum)
{
   for (int i = 0; i < unit->size; ++i) {
      pthread_kill(unit->threads[i]._thr, signum);
   }

   return 0;
}

int dt_join (dt_unit_t *unit)
{
    for(;;) {

        // Lock threads state
        pthread_mutex_lock(&unit->_isdead_mx);

        // Browse threads
        int active_threads = 0;
        for (int i = 0; i < unit->size; ++i) {

            // Count active threads
            dthread_t *thread = &unit->threads[i];
            if(thread->state & ThreadActive)
                ++active_threads;

            // Reclaim dead threads
            if(thread->state == ThreadDead) {
                pthread_join(thread->_thr, NULL);
                thread->state = ThreadJoined;
            }
        }

        // Check result
        if (active_threads == 0) {
            pthread_mutex_unlock(&unit->_isdead_mx);
            break;
        }

        // Wait for a thread to finish
        pthread_cond_wait(&unit->_isdead, &unit->_isdead_mx);
        pthread_mutex_unlock(&unit->_isdead_mx);
    }

    // Reclaim all Idle threads
    pthread_mutex_lock(&unit->_isidle_mx);
    for (int i = 0; i < unit->size; ++i) {
        if(unit->threads[i].state > ThreadDead) {
            unit->threads[i].state = ThreadDead;
        }
    }

    // Broadcast all remaining threads signal to wake up
    pthread_cond_broadcast(&unit->_isidle);
    pthread_mutex_unlock(&unit->_isidle_mx);

    // Join all threads
    for (int i = 0; i < unit->size; ++i) {

        // Reclaim all dead threads
        dthread_t *thread = &unit->threads[i];
        if(thread->state == ThreadDead) {
            pthread_join(thread->_thr, NULL);
            thread->state = ThreadJoined;
        }
    }

    return 0;
}

int dt_stop (dt_unit_t *unit)
{
    // Stop all live threads
    int count = 0;
    pthread_mutex_lock(&unit->_isidle_mx);
    for (int i = 0; i < unit->size; ++i) {
        if(unit->threads[i].state > ThreadDead) {
            unit->threads[i].state = ThreadDead | ThreadCancelled;
            ++count;
        }
    }

    // Broadcast all idle threads signal to wake up
    pthread_cond_broadcast(&unit->_isidle);
    pthread_mutex_unlock(&unit->_isidle_mx);
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

    // Repurpose it's object and runnable
    thread->run = runnable;
    thread->data = data;

    // Cancel current runnable
    thread->state = ThreadActive | ThreadCancelled;
    return 0;
}

int dt_cancel (dthread_t *thread)
{
    // Check
    if (thread == 0)
        return -1;

    thread->state = ThreadIdle | ThreadCancelled;
    return 0;
}

int dt_compact (dt_unit_t *unit)
{
    /* This function is not yet implemented.
     * Idle threads won't be reclaimed,
     * but it shouldn't worry you in most cases.
     * Sorry.
     */
    return 0;
}

