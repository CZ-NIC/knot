#include "tests/tap_unit.h"

/*
   This is unit test template.
   Implement two mandatory functions below,
   name them accordingly and export unit API
   via global variable of "unit_api".

   Add the exported variable into the list
   "unit_api* tests[]" in src/tests/main.c

   There is no header file, all modules *.c files
   are included directly into src/tests/main.c

   See https://github.com/zorgnax/libtap for libtap API reference.

 */

/*! \brief Report the number of scheduled tests for given parameters. */
static int TEMPLATE_tests_count(int argc, char *argv[])
{
	return 1;
}

/*! \brief  Run all scheduled tests for given parameters. */
static int TEMPLATE_tests_run(int argc, char *argv[])
{
	ok(1 == 1, "dummy test");
	return 0;
}

/*!
 * \brief Exported unit API for later incorporation.
 *
 * Name must be unique for each module.
 */
unit_api TEMPLATE_tests_api = {
	"TEMPLATE unit",        /*!< Unit name. */
	&TEMPLATE_tests_count,  /*!< Count scheduled tests. */
	&TEMPLATE_tests_run     /*!< Run scheduled tests. */
};
