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
struct server_t;
struct conf_t;

typedef struct iostate {
	volatile unsigned s;
	struct iohandler* h;
} iostate_t;

/*! \brief I/O handler structure.
  */
typedef struct iohandler {
	struct node        n;
	dt_unit_t          *unit;   /*!< Threading unit */
	struct server_t    *server; /*!< Reference to server */
	void               *data;   /*!< Persistent data for I/O handler. */
	iostate_t          *state;
	void (*dtor)(void *data); /*!< Data destructor. */
} iohandler_t;

/*! \brief Round-robin mechanism of switching.
  */
#define get_next_rr(current, count) \
	(((current) + 1) % (count))

/*! \brief Server state flags.
 */
typedef enum {
	ServerIdle    = 0 << 0, /*!< Server is idle. */
	ServerRunning = 1 << 0, /*!< Server is running. */
	ServerReload  = 1 << 1  /*!< Server reload requested. */
} server_state;

/*!
 * \brief Server interface structure.
 */
typedef struct iface_t {
	struct node n;
	int fd[2];
	int type;
	int port;    /*!< \brief Socket port. */
	char* addr;  /*!< \brief Socket address. */
} iface_t;

/* Handler types. */
#define IO_COUNT 2
enum {
	IO_UDP    = 0,
	IO_TCP    = 1
};

typedef struct ifacelist {
	ref_t ref;
	list l;
	list u;
} ifacelist_t;

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

	/*! \brief I/O handlers. */
	unsigned tu_size;
	xfrhandler_t *xfr;
	iohandler_t h[IO_COUNT];

	/*! \brief Event scheduler. */
	dt_unit_t *iosched;
	evsched_t *sched;

	/*! \brief List of interfaces. */
	ifacelist_t* ifaces;

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
 * \brief Create I/O handler.
 *
 * \param h Initialized handler.
 * \param s Server structure to be used for operation.
 * \param u Threading unit to serve given filedescriptor.
 * \param d Handler data.
 *
 * \retval Handler instance if successful.
 * \retval NULL If an error occured.
 */
int server_init_handler(iohandler_t * h, server_t *s, dt_unit_t *u, void *d);

/*!
 * \brief Delete handler.
 *
  * \param ref I/O handler instance.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 */
int server_free_handler(iohandler_t *h);

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

/*!
 * \brief Update fdsets from current interfaces list.
 * \param s Server.
 * \param fds Filedescriptor set.
 * \param type I/O type (UDP/TCP).
 * \return new interface list
 */
ref_t *server_set_ifaces(server_t *s, fdset_t *fds, int type);

#endif // _KNOTD_SERVER_H_

/*! @} */
