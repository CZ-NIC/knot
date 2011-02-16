/*!
 * \file server.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Core server functions.
 *
 * Contains the main high-level server structure (cute_server) and interface
 * to functions taking care of proper initialization of the server and clean-up
 * when terminated.
 *
 * As of now, the server supports only one zone file and only in a special
 * format.
 *
 * \see zone-parser.h
 * \addtogroup server
 * @{
 */
#ifndef _CUTEDNS_SERVER_H_
#define _CUTEDNS_SERVER_H_

#include "name-server.h"
#include "common.h"
#include "socket.h"
#include "dthreads.h"
#include "zonedb.h"

/*! \brief I/O handler structure.
  */
typedef struct iohandler_t {

	int                fd;      /*!< I/O filedescriptor */
	unsigned           state;   /*!< Handler state */
	struct iohandler_t *next;   /*!< Next handler */
	dt_unit_t          *unit;   /*!< Threading unit */
	struct cute_server *server; /*!< Reference to server */

} iohandler_t;

/*! \brief Round-robin mechanism of switching.
  */
#define get_next_rr(current, count) \
	(((current) + 1) % (count))

/*! \brief Server state flags.
 */
typedef enum {
	ServerIdle    = 0 << 0, /*!< Server is idle. */
	ServerRunning = 1 << 0  /*!< Server is running. */
} server_state;

/* Forwad declarations. */
struct cute_server;
struct iohandler_t;

/*!
 * \brief Main server structure.
 *
 * Keeps references to all important structures needed for operation.
 */
typedef struct cute_server {

	/*! \brief Server state tracking. */
	unsigned state;

	/*! \brief Reference to the name server structure. */
	ns_nameserver *nameserver;

	/*! \brief Reference to the zone database structure. */
	dnslib_zonedb_t *zone_db;

	/*! \brief I/O handlers list. */
	struct iohandler_t *handlers;

} cute_server;

/*!
 * \brief Allocates and initializes the server structure.
 *
 * Creates all other main structures.
 *
 * \retval New instance if successful.
 * \retval 0 If an error occured.
 */
cute_server *cute_create();

/*!
 * \brief Create and bind handler to given filedescriptor.
 *
 * Pointer to handler instance is used as native unique identifier.
 * This requests instance not to be reallocated.
 *
 * \param server Server structure to be used for operation.
 * \param fd I/O filedescriptor.
 * \param unit Threading unit to serve given filedescriptor.
 *
 * \retval Handler instance if successful.
 * \retval 0 If an error occured.
 */
iohandler_t *cute_create_handler(cute_server *server, int fd, dt_unit_t *unit);

/*!
 * \brief Delete handler.
 *
 * \param fd I/O handler filedescriptor.
 *
 * \param server Server structure to be used for operation.
 * \param ref I/O handler instance.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int cute_remove_handler(cute_server *server, iohandler_t *ref);

/*!
 * \brief Starts the server.
 *
 * \param server Server structure to be used for operation.
 * \param filename Zone file name to be used by the server.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 *
 * \todo When a module for configuration is added, the filename parameter will
 *       be removed.
 */
int cute_start(cute_server *server, const char **filenames, uint zones);

/*!
 * \brief Waits for the server to finish.
 *
 * \param server Server structure to be used for operation.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int cute_wait(cute_server *server);

/*!
 * \brief Requests server to stop.
 *
 * \param server Server structure to be used for operation.
 */
void cute_stop(cute_server *server);

/*!
 * \brief Properly destroys the server structure.
 *
 * \param server Server structure to be used for operation.
 */
void cute_destroy(cute_server **server);

#endif // _CUTEDNS_SERVER_H_

/*! @} */

