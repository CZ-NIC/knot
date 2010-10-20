#include <stdio.h>

#include "common.h"
#include "server.h"

/*----------------------------------------------------------------------------*/

static volatile short s_stopping = 0;
static cute_server* s_server = NULL;

// SIGINT signal handler
void interrupt_handle(int s)
{
   // Omit other signals
   if(s != SIGINT || s_server == NULL) {
      return;
   }

   // Stop server
   if(s_stopping == 0) {
      s_stopping = 1;
      cute_stop(s_server);
   }
   else {
      log_error("\nOK! OK! Exiting immediately.\n");
      exit(1);
   }
}

int main( int argc, char **argv )
{
    if (argc < 2) {
		print_msg(LOG_ERR, "Usage: %s <filename1> [<filename2> ...] .\n",
				  argv[0]);
        return -1;
    }

    // Open log
    log_open(LOG_UPTO(LOG_ERR), LOG_MASK(LOG_ERR)|LOG_MASK(LOG_WARNING));

    int res = 0;

    // Create server instance
    s_server = cute_create();

    // Run server
    if ((res = cute_start(s_server, argv + 1, argc - 1)) == 0) {

       // Register service and signal handler
       struct sigaction sa;
       sa.sa_handler = interrupt_handle;
       sigemptyset(&sa.sa_mask);
       sa.sa_flags = 0;
       sigaction(SIGINT, &sa, NULL);
       sigaction(SIGCLOSE, &sa, NULL); // Interrupt

       if((res = cute_wait(s_server)) != 0) {
          log_error("There was an error while waiting for server to finish.");
       }
    }
    else {
       log_error("There was an error while starting the server, exiting...\n");
    }

    // Stop server and close log
    cute_destroy(&s_server);
    log_close();

    return res;
}
