/*!
 * \file server.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Core server functions.
 *
 * Contains the main high-level server structure (server_t) and interface
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
#ifndef _KNOT_SERVER_H_
#define _KNOT_SERVER_H_

#include "common.h"
#include "server/name-server.h"
#include "server/socket.h"
#include "server/dthreads.h"
#include "dnslib/zonedb.h"
#include "lib/lists.h"

/* Forwad declarations. */
struct iface_t;
struct iohandler_t;
struct server_t;
struct conf_t;

/*! \brief I/O handler structure.
  */
typedef struct iohandler_t {
	struct node *next, *prev;
	int                fd;      /*!< I/O filedescriptor */
	int                type;    /*!< Descriptor type/family. */
	unsigned           state;   /*!< Handler state */
	dt_unit_t          *unit;   /*!< Threading unit */
	struct iface_t     *iface;  /*!< Reference to associated interface. */
	struct server_t    *server; /*!< Reference to server */

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

/*!
 * \brief Server interface structure.
 */
typedef struct iface_t {
	struct node *next, *prev;
	int fd[2];   /*!< \brief Socket filedescriptors (UDP, TCP). */
	int type[2]; /*!< \brief Socket type. */
	int port;    /*!< \brief Socket port. */
	char* addr;  /*!< \brief Socket address. */
	iohandler_t* handler[2]; /*!< \brief Associated I/O handlers. */
} iface_t;

/* Interface indexes. */
#define UDP_ID 0
#define TCP_ID 1

/*!
 * \brief Main server structure.
 *
 * Keeps references to all important structures needed for operation.
 */
typedef struct server_t {

	/*! \brief Server state tracking. */
	volatile unsigned state;

	/*! \brief Reference to the name server structure. */
	ns_nameserver *nameserver;

	/*! \brief Reference to the zone database structure. */
	dnslib_zonedb_t *zone_db;

	/*! \brief I/O handlers list. */
	list handlers;

	/*! \brief List of interfaces. */
	list* ifaces;

} server_t;

/*!
 * \brief Allocates and initializes the server structure.
 *
 * Creates all other main structures.
 *
 * \retval New instance if successful.
 * \retval 0 If an error occured.
 */
server_t *server_create();

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
iohandler_t *server_create_handler(server_t *server, int fd, dt_unit_t *unit);

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
int server_remove_handler(server_t *server, iohandler_t *ref);

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
int server_start(server_t *server, const char **filenames, uint zones);

/*!
 * \brief Waits for the server to finish.
 *
 * \param server Server structure to be used for operation.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int server_wait(server_t *server);

/*!
 * \brief Requests server to stop.
 *
 * \param server Server structure to be used for operation.
 */
void server_stop(server_t *server);

/*!
 * \brief Properly destroys the server structure.
 *
 * \param server Server structure to be used for operation.
 */
void server_destroy(server_t **server);

/*!
 * \brief Server config hook.
 *
 * Routine for dynamic server reconfiguration.
 */
int server_conf_hook(const struct conf_t *conf, void *data);

#endif // _KNOT_SERVER_H_

/*! @} */

