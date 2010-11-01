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

/**  I/O handler structure.
  */
typedef struct iohandler_t {

   int fd;                       /* I/O filedescripto r */
   unsigned state;               /* Handler state */
   struct iohandler_t* next;     /* Next handler */
   dpt_dispatcher* threads;      /* Handler threads */
   struct cute_server* server;   /* Reference to server */

} iohandler_t;

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

/*! Forwad declaration of opaque I/O handler. */
struct iohandler_t;

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

   /*! @brief I/O handlers list. */
   struct iohandler_t *handlers;

} cute_server;

/*!
 * @brief Allocates and initializes the server structure. Creates all other
 *        main structures
 */
cute_server *cute_create();

/** Create and bind handler to given filedescriptor.
  * \param fd I/O filedescriptor.
  * \param routine Handler routine.
  * \param threads Number of threads to spawn.
  * \return handler identifier or -1
  */
int cute_create_handler(cute_server *server, int fd, thr_routine routine, int threads);

/** Delete handler.
  * \param fd I/O handler filedescriptor.
  * \return >=0 If successful, negative integer on failure.
  */
int cute_remove_handler(cute_server *server, int fd);

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
