/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
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
 *
 * \addtogroup server
 * @{
 */

#ifndef _KNOTD_SERVER_H_
#define _KNOTD_SERVER_H_

#include "knot/common.h"
#include "libknot/nameserver/name-server.h"
#include "knot/server/xfr-handler.h"
#include "knot/server/socket.h"
#include "knot/server/dthreads.h"
#include "knot/server/rrl.h"
#include "libknot/zone/zonedb.h"
#include "common/evsched.h"
#include "common/lists.h"

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
	void               *data;   /*!< Persistent data for I/O handler. */
	void (*interrupt)(struct iohandler_t *h); /*!< Interrupt handler. */

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
	knot_nameserver_t *nameserver;

	/*! \brief XFR handler. */
	xfrhandler_t *xfr_h;

	/*! \brief Event scheduler. */
	evsched_t *sched;

	/*! \brief I/O handlers list. */
	list handlers;

	/*! \brief List of interfaces. */
	list* ifaces;
	
	/*! \brief Rate limiting. */
	rrl_table_t *rrl;

} server_t;

/*!
 * \brief Allocates and initializes the server structure.
 *
 * Creates all other main structures.
 *
 * \retval New instance if successful.
 * \retval NULL If an error occured.
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
 * \retval NULL If an error occured.
 */
iohandler_t *server_create_handler(server_t *server, int fd, dt_unit_t *unit);

/*!
 * \brief Delete handler.
 *
 * \param server Server structure to be used for operation.
 * \param ref I/O handler instance.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 */
int server_remove_handler(server_t *server, iohandler_t *ref);

/*!
 * \brief Starts the server.
 *
 * \param server Server structure to be used for operation.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 *
 */
int server_start(server_t *server);

/*!
 * \brief Waits for the server to finish.
 *
 * \param server Server structure to be used for operation.
 *
 * \retval  0 On success (EOK).
 * \retval <0 If an error occured (EINVAL).
 */
int server_wait(server_t *server);

/*!
 * \brief Refresh served zones.
 *
 * \param server Server structure to be used for operation.
 *
 * \retval  0 On success (EOK).
 * \retval <0 If an error occured (EINVAL).
 */
int server_refresh(server_t *server);

/*!
 * \brief Reload server configuration.
 *
 * \param server Server instance.
 * \param cf Config file path.
 * \return 
 */
int server_reload(server_t *server, const char *cf);

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
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ENOTRUNNING if the server is not running.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ERROR unspecified error.
 */
int server_conf_hook(const struct conf_t *conf, void *data);

#endif // _KNOTD_SERVER_H_

/*! @} */
