#include <stdio.h>
#include <signal.h>

#include "common.h"
#include "server.h"
#include "cuckoo-test.h"
#include "tests.h"

/*----------------------------------------------------------------------------*/

static cute_server* server_singleton = NULL;

// SIGINT signal handler
void interrupt_handle(int s)
{
   // Stop server
   if(s == SIGINT && server_singleton != NULL) {
      cute_stop(server_singleton);
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
    cute_server* server = cute_create();

    // Register service and signal handler
    server_singleton = server;
    struct sigaction sa;
    sa.sa_handler = interrupt_handle;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    // Run server
    if ((res = cute_start(server, argv[1])) != 0) {
        log_error("Problem starting the server, exiting..\n");
    }

    // Stop server and close log
    cute_destroy(&server);

    log_close();
    return res;
}
