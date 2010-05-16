#include <stdio.h>
#include <signal.h>

#include "common.h"
#include "server.h"
#include "cuckoo-test.h"
#include "tests.h"

/*----------------------------------------------------------------------------*/

static cute_server* s_server = NULL;

// SIGINT signal handler
void interrupt_handle(int s)
{
   // Stop server
   if(s == SIGINT && s_server != NULL) {
      cute_stop(s_server);
   }
}

int main( int argc, char **argv )
{
    if (argc < 2) {
        print_msg(LOG_ERR, "Usage: %s <filename>.\n", argv[0]);
        return -1;
    }

    // Open log
    log_open(LOG_UPTO(LOG_ERR), LOG_MASK(LOG_ERR)|LOG_MASK(LOG_WARNING));

    int res = 0;
//	res = test_skip_list();

//	if (res != 0) {
//		printf("\n!!!! Skip list test unsuccessful !!!!\n");
//	}

    // Start server

    // Create server instance
    s_server = cute_create();

    // Register service and signal handler
    struct sigaction sa;
    sa.sa_handler = interrupt_handle;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    // Run server
    if ((res = cute_start(s_server, argv[1])) != 0) {
        fprintf (stderr, "Problem starting the server, exiting..\n");
    }

    // Stop server and close log
    cute_destroy(&s_server);
    log_close();

    return res;
}
