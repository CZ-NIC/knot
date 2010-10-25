#include "server.h"
#include "udp-handler.h"
#include "tcp-handler.h"
#include "zone-database.h"
#include "name-server.h"
#include "zone-parser.h"
#include <unistd.h>

/*----------------------------------------------------------------------------*/

cute_server *cute_create()
{
    debug_server("Creating Server structure..\n");
    cute_server *server = malloc(sizeof(cute_server));
    server->workers = NULL;
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
    socket_t* sock = socket_create(DEFAULT_PORT, TCP);
    socket_listen(sock, "0.0.0.0");
    cute_add_handler(server, sock, &tcp_master);

    sock = socket_create(DEFAULT_PORT, UDP);
    socket_listen(sock, "0.0.0.0");
    cute_add_handlers(server, sock, &udp_worker, thr_count);
    debug_server("Done\n\n");

    return server;
}

int cute_add_handlers( cute_server *server, socket_t* socket, thr_routine routine, int threads)
{
   //! Not thread-safe.
   static volatile int _ctr = 0;

   // Create new worker
   worker_t* worker = malloc(sizeof(worker_t));
   if(worker == NULL)
      return -1;

   // Initialize
   worker->id = ++_ctr;
   worker->state = Idle;
   worker->next = server->workers;
   worker->server = server;
   worker->socket = socket;
   worker->dispatcher = dpt_create(threads, routine, worker);
   if(worker->dispatcher == NULL) {
      free(worker);
      return -2;
   }

   // Update list
   server->workers = worker;

   // Run if server is online
   if(server->state & Running) {
      dpt_start(worker->dispatcher);
   }

   return worker->id;
}

int cute_remove_handler( cute_server *server, int id)
{
   // Find worker
   worker_t *w = NULL, *p = NULL;
   for(w = server->workers; w != NULL; p = w,w = w->next) {
      if(w->id == id) {

         // Disconnect
         if(p == NULL) {
            server->workers = w->next;
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
      dpt_notify(w->dispatcher, SIGALRM);
      dpt_wait(w->dispatcher);
   }

   // Close socket
   socket_remove(w->socket);

   // Destroy dispatcher and worker
   dpt_destroy(&w->dispatcher);
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
   for(worker_t* w = server->workers; w != NULL; w = w->next) {
      w->state = Running;
      ret += dpt_start(w->dispatcher);
   }

   return ret;
}

int cute_wait(cute_server *server)
{
   // Wait for dispatchers to finish
   int ret = 0;
   while(server->workers != NULL) {
      ret += dpt_wait(server->workers->dispatcher);
      cute_remove_handler(server, server->workers->id);
   }

   return ret;
}

void cute_stop( cute_server *server )
{
    // Notify servers to stop
   server->state &= ~Running;
   for(worker_t* w = server->workers; w != NULL; w = w->next) {
      w->state = Idle;
      dpt_notify(w->dispatcher, SIGALRM);
   }
}

void cute_destroy( cute_server **server )
{
   // Free workers
   worker_t* w = (*server)->workers;
   while(w != NULL) {
      worker_t* n = w->next;
      cute_remove_handler(*server, w->id);
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

