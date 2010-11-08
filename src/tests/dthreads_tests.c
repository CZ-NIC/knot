#include "server/dthreads.h"
#include "tap_unit.h"
#include <sys/select.h>
#include <pthread.h>
#include <sched.h>

static int dt_tests_count(int argc, char * argv[]);
static int dt_tests_run(int argc, char * argv[]);

/*
 * Unit API.
 */
unit_api dthreads_tests_api = {
   "DThreads",
   &dt_tests_count,
   &dt_tests_run
};

/*
 *  Unit implementation.
 */
static const int DT_TEST_COUNT = 17;

/* Unit runnable data. */
static pthread_mutex_t _runnable_mx;
static volatile int _runnable_i = 0;
static const int _runnable_cycles = 10000;

/*! \brief Unit runnable. */
int runnable(struct dthread_t *thread)
{
    for (int i = 0; i < _runnable_cycles; ++i) {

        // Increase counter
        pthread_mutex_lock(&_runnable_mx);
        ++_runnable_i;
        pthread_mutex_unlock(&_runnable_mx);

        // Cancellation point
        if (thread->state & ThreadCancelled) {
            break;
        }

        // Yield
        sched_yield();
    }

    return 0;
}

/*! \brief Unit blocking runnable. */
int runnable_simio(struct dthread_t *thread)
{
    // Infinite blocking, must be interrupted
    select(0, 0, 0, 0, 0);
    return 0;
}

/*! \brief Create unit. */
static inline dt_unit_t *dt_test_create(int size)
{
    return dt_create(size);
}

/*! \brief Assign a task. */
static inline int dt_test_single(dt_unit_t *unit)
{
    return dt_repurpose(unit->threads[0], &runnable, NULL) == 0;
}

/*! \brief Assign task to all unit threads. */
static inline int dt_test_coherent(dt_unit_t *unit)
{
    int ret = 0;
    for (int i = 0; i < unit->size; ++i) {
        ret += dt_repurpose(unit->threads[i], &runnable, NULL);
    }

    return ret == 0;
}

/*! \brief Repurpose single thread. */
static inline int dt_test_repurpose(dt_unit_t *unit, int id)
{
    return dt_repurpose(unit->threads[id], &runnable_simio, NULL) == 0;
}

/*! \brief Cancel single thread. */
static inline int dt_test_cancel(dt_unit_t *unit, int id)
{
    return dt_cancel(unit->threads[id]) == 0;
}

/*! \brief Reanimate dead threads. */
static inline int dt_test_reanimate(dt_unit_t *unit)
{
    // Compact all threads
    int ret = 0;
    ret += dt_compact(unit);

    // Remove purpose from all
    for (int i = 0; i < unit->size; ++i) {
        ret += dt_repurpose(unit->threads[i], 0, 0);
    }

    // Set single thread to purpose
    ret += dt_repurpose(unit->threads[0], &runnable, 0);

    // Restart
    _runnable_i = 0;
    ret += dt_start(unit);

    // Wait for finish
    ret += dt_join(unit);

    // Verify
    int expected = 1 * _runnable_cycles;
    if(_runnable_i != expected) {
        return 0;
    }

    // Check return codes
    return ret == 0;
}

/*! \brief Resize unit. */
static inline int dt_test_resize(dt_unit_t *unit, int size)
{
    // Resize
    int ret = 0;
    ret = dt_resize(unit, size);
    if (ret < 0) {
        return 0;
    }

    // Check outcome
    if (unit->size != size) {
        return 0;
    }

    // Repurpose all
    for (int i = 0; i < size; ++i) {
        ret += dt_repurpose(unit->threads[i], &runnable, 0);
    }

    // Restart
    _runnable_i = 0;
    ret += dt_start(unit);

    // Wait for finish
    ret += dt_join(unit);

    // Verify
    int expected = size * _runnable_cycles;
    note("resize test: %d threads, %d ticks, %d expected",
         size, _runnable_i, expected);
    if(_runnable_i != expected) {
        return 0;
    }

    // Check return codes
    return ret == 0;
}

/*! \brief Resize unit while threads are active. */
static inline int dt_test_liveresize(dt_unit_t *unit)
{
    // Size
    int size = unit->size;
    int size_hi = size + 2;
    int size_lo = size - 1;

    // Expand
    int ret = 0;
    ret = dt_resize(unit, size_hi);
    if (ret < 0) {
        return 0;
    }

    // Repurpose all
    for (int i = 0; i < unit->size; ++i) {
        ret += dt_repurpose(unit->threads[i], &runnable, 0);
    }

    // Restart
    _runnable_i = 0;
    ret += dt_start(unit);

    // Shrink
    ret += dt_resize(unit, size_lo);

    // Wait for finish
    ret += dt_join(unit);

    // Verify
    int expected_hi = size_hi * _runnable_cycles;
    int expected_lo = size_lo * _runnable_cycles;
    note("resize test: %d->%d->%d threads, %d ticks, <%d,%d> expected",
         size, size_hi, size_lo, _runnable_i, expected_lo, expected_hi);

    if(_runnable_i > expected_hi || _runnable_i < expected_lo) {
        return 0;
    }

    // Check return codes
    return ret == 0;
}

/*! \brief Start unit. */
static inline int dt_test_start(dt_unit_t *unit)
{
    return dt_start(unit) == 0;
}

/*! \brief Stop unit. */
static inline int dt_test_stop(dt_unit_t *unit)
{
    int ret = 0;
    for (int i = 0; i < unit->size; ++i)
        ret += dt_stop(unit->threads[i]);

    return ret;
}

/*! \brief Join unit. */
static inline int dt_test_join(dt_unit_t *unit)
{
    return dt_join(unit) == 0;
}

/*! API: return number of tests. */
static int dt_tests_count(int argc, char * argv[])
{
   return DT_TEST_COUNT;
}

/*! API: run tests. */
static int dt_tests_run(int argc, char * argv[])
{
    /* Initialize */
    srand(time(NULL));
    struct timeval tv;
    pthread_mutex_init(&_runnable_mx, NULL);

    /* Test 1: Create unit */
    dt_unit_t *unit = dt_test_create(dt_optimal_size());
    ok(unit != 0, "dthreads: create unit (optimal size %d)", unit->size);
    skip(unit == 0, DT_TEST_COUNT - 1);

    /* Test 2: Assign a single task. */
    ok(dt_test_single(unit), "dthreads: assign single task");

    /* Test 3: Start tasks. */
    _runnable_i = 0;
    ok(dt_test_start(unit), "dthreads: start single task");

    /* Test 4: Wait for tasks. */
    ok(dt_test_join(unit), "dthreads: join threads");

    /* Test 5: Compare counter. */
    int expected = _runnable_cycles * 1;
    cmp_ok(_runnable_i, "==", expected, "dthreads: result ok");

    /* Test 6: Repurpose threads. */
    _runnable_i = 0;
    ok(dt_test_coherent(unit), "dthreads: repurpose to coherent");

    /* Test 7: Restart threads. */
    ok(dt_test_start(unit), "dthreads: start coherent unit");

    /* Test 8: Repurpose single thread. */
    tv.tv_sec = 0;
    tv.tv_usec = 4000 + rand() % 1000; // 4-5ms
    note("waiting for %dus to let thread do some work ...",
         tv.tv_usec);
    select(0, 0, 0, 0, &tv);
    ok(dt_test_repurpose(unit, 0), "dthreads: repurpose on-the-fly");

    /* Test 9: Cancel blocking thread. */
    tv.tv_sec = 0;
    tv.tv_usec = (250 + rand() % 500) * 1000; // 250-750ms
    note("waiting for %dms to let thread pretend blocking I/O ...",
         tv.tv_usec / 1000);
    select(0, 0, 0, 0, &tv);
    ok(dt_test_cancel(unit, 0), "dthreads: cancel blocking thread");

    /* Test 10: Wait for tasks. */
    ok(dt_test_join(unit), "dthreads: join threads");

    /* Test 11: Compare counter. */
    int expected_lo = _runnable_cycles * (unit->size - 1);
    cmp_ok(_runnable_i, ">=", expected_lo,
           "dthreads: result %d is => %d", _runnable_i, expected_lo);

    /* Test 12: Compare counter #2. */
    int expected_hi = _runnable_cycles * unit->size;
    cmp_ok(_runnable_i, "<=", expected_hi,
           "dthreads: result %d is <= %d", _runnable_i, expected_hi);

    /* Test 13: Reanimate dead threads. */
    ok(dt_test_reanimate(unit), "dthreads: reanimate dead threads");

    /* Test 14: Expand unit by 100%. */
    int size = unit->size * 2;
    ok(dt_test_resize(unit, size),
       "dthreads: expanding unit to size * 2 (%d threads)", size);

    /* Test 15: Shrink unit to half. */
    size = unit->size / 2;
    ok(dt_test_resize(unit, size),
       "dthreads: shrinking unit to size / 2 (%d threads)", size);

    /* Test 16: Resize while threads are active. */
    ok(dt_test_liveresize(unit), "dthreads: resizing unit while active");

    /* Test 17: Deinitialize */
    dt_delete(&unit);
    ok(unit == 0, "dthreads: delete unit");
    endskip;

    pthread_mutex_destroy(&_runnable_mx);
    return 0;
}
