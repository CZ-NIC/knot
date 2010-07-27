#include <stdio.h>

#include "common.h"
#include "server.h"
#include "cuckoo-test.h"
#include "tests.h"

/*----------------------------------------------------------------------------*/

int main( int argc, char **argv )
{
    if (argc < 2) {
        print_msg(LOG_ERR, "Usage: %s <filename>.\n", argv[0]);
        return -1;
    }

    // Open log
    log_open(LOG_UPTO(LOG_ERR), LOG_MASK(LOG_ERR)|LOG_MASK(LOG_WARNING));

	//int res = ct_test_hash_table(argv[1]);
	int res = test_dynamic_array();

	/*
    // Start server
    cute_server *server = cute_create();

    int res;
    if ((res = cute_start(server, argv[1])) != 0) {
        log_error("Problem starting the server, exiting..\n");
    }

    // Stop server and close log
    cute_destroy(&server);
	*/
    log_close();
	return res;
}
