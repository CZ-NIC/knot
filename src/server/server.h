/*!
 * @file server.h
 *
 * Contains the main high-level server structure (cute_server) and interface
 * to functions taking care of proper initialization of the server and clean-up
 * when terminated.
 *
 * As of now, the server supports only one zone file and only in a special
 * format.
 *
 * @see zone-parser.h
 */
#ifndef SERVER_H
#define SERVER_H

#include "dispatcher.h"
#include "zone-database.h"
#include "name-server.h"
#include "common.h"
#include "socket.h"

/*! Round-robin mechanism of switching.
  */
#define get_next_rr(current, count) \
   (((current) + 1) % (count))

/*! Server state flags.
 */
typedef enum {
   Idle    = 0x00,
   Running = 0x01
} server_state;

struct cute_server;

/** Worker descriptor.
  */
typedef struct worker_t {

    int id;
    unsigned state;
    struct worker_t* next;
    struct cute_server* server;
    socket_t* socket;
    dpt_dispatcher* dispatcher;

} worker_t;

/*!
 * @brief Main server structure. Keeps references to all important structures
 *        needed for operation.
 */
typedef struct cute_server {

   /*! @brief Server state tracking. */
   unsigned state;

	/*! @brief Reference to the name server structure. */
    ns_nameserver *nameserver;

   /*! @brief Reference to the zone database structure. */
    zdb_database *zone_db;

   /*! @brief Server worker list. */
    worker_t *workers;

} cute_server;

/*!
 * @brief Allocates and initializes the server structure. Creates all other
 *        main structures
 */
cute_server *cute_create();

/** Add 1..n workers to the server.
  * \param routine Worker routine.
  * \param socket Socket instance.
  * \param threads Number of threads to spawn.
  * \return ptr to worker or NULL
  */
worker_t*  cute_add_handlers( cute_server *server, socket_t* socket, thr_routine routine, int threads);

/** Add a worker to the server.
  * \param routine Worker routine.
  * \param socket Socket instance.
  * \return ptr to worker or NULL
  */
static inline worker_t* cute_add_handler( cute_server *server, socket_t* socket, thr_routine routine) {
   return cute_add_handlers(server, socket, routine, 1);
}

/** Remove worker from server.
  * \param id Set id.
  * \return >=0 If successful, negative integer on failure.
  */
int cute_remove_handler( cute_server *server, int id);

/*!
 * @brief Starts the server.
 *
 * @param server Server structure to be used for operation.
 * @param filename Zone file name to be used by the server.
 *
 * @retval 0 On success.
 * @retval -1 If an error occured.
 *
 * @todo When a module for configuration is added, the filename parameter will
 *       be removed.
 */
int cute_start( cute_server *server, char **filenames, uint zones );

/*!
 * @brief Waits for the server to finish.
 *
 * @param server Server structure to be used for operation.
 *
 * @retval 0 On success.
 * @retval -1 If an error occured.
 *
 */
int cute_wait(cute_server *server);

/*!
 * @brief Requests server to stop.
 */
void cute_stop( cute_server *server );

/*!
 * @brief Properly destroys the server structure.
 */
void cute_destroy( cute_server **server );

/** Return optimal number of threads for instance.
  * It is estimated as NUM_CPUs + 1.
  * Fallback is DEFAULT_THR_COUNT  (\see common.h).
  * \return number of threads
  */
int cute_estimate_threads();

#endif
