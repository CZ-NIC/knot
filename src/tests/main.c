#include "libtap/tap.h"
#include "common.h"

// Units to test
#include "server_tests.c"
#include "skiplist_tests.c"
#include "da_tests.c"

// Run all loaded units
int main(int argc, char * argv[])
{
   // Build test set
   unit_api* tests[] = {
      &skiplist_tests_api, //! Skip list unit
      &da_tests_api,       //! Dynamic array unit
      &server_tests_api,   //! Server unit
      NULL
   };

   // Plan number of tests
   int id = 0;
   int test_count = 0;
   note("Units:");
   while(tests[id] != NULL) {
      note("- %s : %d tests", tests[id]->name, tests[id]->count(argc, argv));
      test_count += tests[id]->count(argc, argv);
      ++id;
   }

   plan(test_count);

   // Run tests
   id = 0;
   while(tests[id] != NULL) {
      diag("Testing unit: %s", tests[id]->name);
      tests[id]->run(argc, argv);
      ++id;
   }

   // Evaluate
   return exit_status();
}
