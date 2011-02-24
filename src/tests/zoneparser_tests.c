#include "tap_unit.h"

static int zoneparser_tests_count(int argc, char *argv[]);
static int zoneparser_tests_run(int argc, char *argv[]);

/*
 * Unit API.
 */
unit_api zoneparser_tests_api = {
        "Zoneparser",
        &zoneparser_tests_count,
        &zoneparser_tests_run
};

/*
 *  Unit implementation.
 */

static const int ZONEPARSER_TEST_COUNT = 0;

/*! API: return number of tests. */
static int zoneparser_tests_count(int argc, char *argv[])
{
        return ZONEPARSER_TEST_COUNT;
}

/*! API: run tests. */
static int zoneparser_tests_run(int argc, char *argv[])
{
        return 1;
}
