#include "libtap/tap.h"
#include "common.h"

// Units to test
#include "server_tests.c"

// Run all loaded units
int main(int argc, char * argv[])
{
   // Plan number of tests
   int test_count = 0;
   test_count += server_tests_api.count(argc, argv);
   plan(test_count);

   // Run tests
   note("Testing unit: %s ...", server_tests_api.name);
   server_tests_api.run(argc, argv);

   // Evaluate
   return exit_status();
}
