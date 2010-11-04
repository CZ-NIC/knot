#include "server/dthreads.h"
#include "tap_unit.h"

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

static const int DT_TEST_COUNT = 0;

/*! API: return number of tests. */
static int dt_tests_count(int argc, char * argv[])
{
   return DT_TEST_COUNT;
}

/*! API: run tests. */
static int dt_tests_run(int argc, char * argv[])
{
   return 0;
}
