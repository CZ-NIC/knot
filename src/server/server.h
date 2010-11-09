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

#include "zone-database.h"
#include "name-server.h"
#include "common.h"
#include "socket.h"
#include "dthreads.h"

/**  I/O handler structure.
  */
typedef struct iohandler_t {

   int fd;                      /* I/O filedescripto r */
   unsigned state;              /* Handler state */
   struct iohandler_t* next;    /* Next handler */
   dt_unit_t* unit;             /* Threading unit */
   struct cute_server* server;  /* Reference to server */

} iohandler_t;

/*! Round-robin mechanism of switching.
  */
#define get_next_rr(current, count) \
   (((current) + 1) % (count))

/*! Server state flags.
 */
typedef enum {
   Idle    = 0 << 0,
   Running = 1 << 0
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
  * \param unit Threading unit to serve given filedescriptor.
  * \return handler identifier or -1
  */
int cute_create_handler(cute_server *server, int fd, dt_unit_t* unit);

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

#endif
