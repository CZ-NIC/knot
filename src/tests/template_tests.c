#include "tap_unit.h"

/* Unit implementation */
int TEMPLATE_tests_count(int argc, char *argv[])
{
   return 1;
}

int TEMPLATE_tests_run(int argc, char *argv[])
{
   ok(1 == 1, "dummy test");
   return 0;
}

/* Exported unit API. */
unit_api TEMPLATE_tests_api = {
   "TEMPLATE unit",
   &TEMPLATE_tests_count,
   &TEMPLATE_tests_run
};
