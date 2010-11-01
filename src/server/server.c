#include "server.h"
#include "udp-handler.h"
#include "tcp-handler.h"
#include "zone-database.h"
#include "name-server.h"
#include "zone-parser.h"
#include <unistd.h>

cute_server *cute_create()
{
    debug_server("Creating Server structure..\n");
    cute_server *server = malloc(sizeof(cute_server));
    server->handlers = NULL;
    server->state = Idle;
    if (server == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }

    debug_server("Done\n\n");
    debug_server("Creating Zone Database structure..\n");

    server->zone_db = zdb_create();
    if (server->zone_db == NULL) {
        return NULL;
    }

    debug_server("Done\n\n");
    debug_server("Creating Name Server structure..\n");

    server->nameserver = ns_create(server->zone_db);
    if (server->nameserver == NULL) {
        zdb_destroy(&server->zone_db);
        free(server);
        return NULL;
    }

    debug_server("Done\n\n");
    debug_server("Creating workers..\n");

    // Estimate number of threads/manager
    int thr_count = cute_estimate_threads();
    debug_server("Estimated number of threads per handler: %d\n", thr_count);

    // Create socket handlers
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    socket_bind(sock, "0.0.0.0", DEFAULT_PORT);
    socket_listen(sock, TCP_BACKLOG_SIZE);
    cute_create_handler(server, sock, &tcp_master, 1);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    socket_bind(sock, "0.0.0.0", DEFAULT_PORT);
    cute_create_handler(server, sock, &udp_worker, thr_count);
    debug_server("Done\n\n");

    return server;
}

int cute_create_handler(cute_server *server, int fd, thr_routine routine, int threads)
{
   // Create new worker
   iohandler_t* handler = malloc(sizeof(iohandler_t));
   if(handler == NULL)
      return -1;

   // Initialize
   handler->fd = fd;
   handler->state = Idle;
   handler->next = server->handlers;
   handler->server = server;
   handler->threads = dpt_create(threads, routine, handler);
   if(handler->threads == NULL) {
      free(handler);
      return -2;
   }

   // Update list
   server->handlers = handler;

   // Run if server is online
   if(server->state & Running) {
      dpt_start(handler->threads);
   }

   return handler->fd;
}

int cute_remove_handler(cute_server *server, int fd)
{
   // Find worker
   iohandler_t *w = NULL, *p = NULL;
   for(w = server->handlers; w != NULL; p = w,w = w->next) {

      // Compare fd
      if(w->fd == fd) {

         // Disconnect
         if(p == NULL) {
            server->handlers = w->next;
         }
         else {
            p->next = w->next;
         }
         break;
      }
   }

   // Check
   if(w == NULL) {
      return -1;
   }

   // Wait for dispatcher to finish
   if(w->state & Running) {
      w->state = Idle;
      dpt_notify(w->threads, SIGALRM);
      dpt_wait(w->threads);
   }

   // Close socket
   socket_close(w->fd);

   // Destroy dispatcher and worker
   dpt_destroy(&w->threads);
   free(w);
   return 0;
}

int cute_start( cute_server *server, char **filenames, uint zones )
{
	debug_server("Starting server with %u zone files.\n", zones);

	for (uint i = 0; i < zones; ++i) {
		debug_server("Parsing zone file %s..\n", filenames[i]);
		if (zp_parse_zone(filenames[i], server->zone_db) != 0) {
			return -1;
		}
	}

   debug_server("\nDone\n\n");
   debug_server("Starting servers..\n");

   // Start dispatchers
   int ret = 0;
   server->state |= Running;
   for(iohandler_t* w = server->handlers; w != NULL; w = w->next) {
      w->state = Running;
      ret += dpt_start(w->threads);
   }

   return ret;
}

int cute_wait(cute_server *server)
{
   // Wait for dispatchers to finish
   int ret = 0;
   while(server->handlers != NULL) {
      ret += dpt_wait(server->handlers->threads);
      cute_remove_handler(server, server->handlers->fd);
   }

   return ret;
}

void cute_stop( cute_server *server )
{
    // Notify servers to stop
   server->state &= ~Running;
   for(iohandler_t* w = server->handlers; w != NULL; w = w->next) {
      w->state = Idle;
      dpt_notify(w->threads, SIGALRM);
   }
}

void cute_destroy( cute_server **server )
{
   // Free workers
   iohandler_t* w = (*server)->handlers;
   while(w != NULL) {
      iohandler_t* n = w->next;
      cute_remove_handler(*server, w->fd);
      w = n;
   }

   ns_destroy(&(*server)->nameserver);
   zdb_destroy(&(*server)->zone_db);
   free(*server);
   *server = NULL;
}

int cute_estimate_threads()
{
#ifdef _SC_NPROCESSORS_ONLN
   int ret = (int) sysconf(_SC_NPROCESSORS_ONLN);
   if(ret >= 1)
      return ret + 1;
#endif
   log_info("server: failed to estimate the number of online CPUs");
   return DEFAULT_THR_COUNT;
}

