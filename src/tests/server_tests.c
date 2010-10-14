#include "server/server.h"
#include "tap_unit.h"

int server_tests_count(int argc, char * argv[]);
int server_tests_run(int argc, char * argv[]);

/*
 * Unit API.
 */
unit_api server_tests_api = {
   "Server",
   &server_tests_count,
   &server_tests_run
};

/*
 *  Unit implementation.
 */

static const int SERVER_TEST_COUNT = 3;

/*! Test: create server. */
cute_server* test_server_create()
{
   return cute_create();
}

/*! Test: start server. */
int test_server_start(cute_server* s, char **filenames, uint zones)
{
   return cute_start(s, filenames, zones) == 0;
}

/*! Test: stop server. */
int test_server_destroy(cute_server* s)
{
   cute_destroy(&s);
   return s == 0;
}

/*! API: return number of tests. */
int server_tests_count(int argc, char * argv[])
{
   return SERVER_TEST_COUNT * (argc - 1) + 1;
}

/*! API: run tests. */
int server_tests_run(int argc, char * argv[])
{
   int ret = 0;
   cute_server* server = 0;

   /* For each zone, try to run and teardown server. */
   for(int i = 1; i < argc; ++i) {

      //! Test server for correct initialization
      server = test_server_create();
      ok(server != 0, "server: initialized");

      //! Test server startup
      ret = 0;
      lives_ok({
         ret = test_server_start(server, argv + i, 1);
      }, "server: not crashing on runtime");

      //! Test server exit code
      ok(ret, "server: started ok");

      //! Test server for correct deinitialization
      ok(test_server_destroy(server), "server: deinit");
   }

   return 0;
}
