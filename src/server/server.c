#include "server.h"
#include "udp-handler.h"
#include "tcp-handler.h"
#include "zone-database.h"
#include "name-server.h"
#include "zone-parser.h"
#include <unistd.h>
#include <stdio.h>
#include "stat.h"

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
    int thr_count = dt_optimal_size();
    debug_server("Estimated number of threads per handler: %d\n", thr_count);

    // Create socket handlers
    int sock = socket_create(PF_INET, SOCK_STREAM);
    socket_bind(sock, "0.0.0.0", DEFAULT_PORT);
    socket_listen(sock, TCP_BACKLOG_SIZE);

    // Create threading unit
    dt_unit_t *unit = dt_create(thr_count);
    dt_repurpose(unit->threads[0], &tcp_master, 0);
    cute_create_handler(server, sock, unit);

    // Create UDP socket
    sock = socket_create(PF_INET, SOCK_DGRAM);
    socket_bind(sock, "0.0.0.0", DEFAULT_PORT);

    // Create threading unit
    unit = dt_create_coherent(thr_count, &udp_master, 0);
    cute_create_handler(server, sock, unit);
    debug_server("Done\n\n");

    return server;
}

iohandler_t* cute_create_handler(cute_server *server, int fd, dt_unit_t* unit)
{
   // Create new worker
   iohandler_t* handler = malloc(sizeof(iohandler_t));
   if(handler == 0)
      return 0;

   // Initialize
   handler->fd = fd;
   handler->state = Idle;
   handler->next = server->handlers;
   handler->server = server;
   handler->unit = unit;

   // Update unit data object
   for(int i = 0; i < unit->size; ++i) {
       dthread_t *thread = unit->threads[i];
       dt_repurpose(thread, thread->run, handler);
   }

   // Update list
   server->handlers = handler;

   // Run if server is online
   if(server->state & Running) {
      dt_start(handler->unit);
   }

   return handler;
}

int cute_remove_handler(cute_server *server, iohandler_t *ref)
{
   // Find worker
   iohandler_t *w = 0, *p = 0;
   for(w = server->handlers; w != NULL; p = w,w = w->next) {

      // Compare fd
      if(w == ref) {

         // Disconnect
         if(p == 0) {
            server->handlers = w->next;
         }
         else {
            p->next = w->next;
         }
         break;
      }
   }

   // Check
   if(w == 0) {
      return -1;
   }

   // Wait for dispatcher to finish
   if(w->state & Running) {
      w->state = Idle;
      dt_stop(w->unit);
      dt_join(w->unit);
   }

   // Close socket
   socket_close(w->fd);

   // Destroy dispatcher and worker
   dt_delete(&w->unit);
   free(w);
   return 0;
}

int cute_start( cute_server *server, char **filenames, uint zones )
{
   debug_server("Starting server with %u zone files.\n", zones);
   //stat

   stat_start(server->nameserver->gatherer);
  
   //!stat
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
      ret += dt_start(w->unit);
   }

   return ret;
}

int cute_wait(cute_server *server)
{
   // Wait for dispatchers to finish
   int ret = 0;
   while(server->handlers != NULL) {
      debug_server("server: [%p] joining threading unit\n", server->handlers);
      ret += dt_join(server->handlers->unit);
      cute_remove_handler(server, server->handlers);
      debug_server("server: joined threading unit\n", p);
   }

   return ret;
}

void cute_stop( cute_server *server )
{
    // Notify servers to stop
   server->state &= ~Running;
   for(iohandler_t* w = server->handlers; w != NULL; w = w->next) {
      w->state = Idle;
      dt_stop(w->unit);
   }
}

void cute_destroy( cute_server **server )
{
   // Free workers
   iohandler_t* w = (*server)->handlers;
   while(w != NULL) {
      iohandler_t* n = w->next;
      cute_remove_handler(*server, w);
      w = n;
   }

   stat_gatherer_free(*(&(*server)->nameserver->gatherer));
   ns_destroy(&(*server)->nameserver);
   zdb_destroy(&(*server)->zone_db);
   free(*server);
   *server = NULL;
}

