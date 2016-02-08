/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file
 *
 * \brief Core server functions.
 *
 * Contains the main high-level server structure (server_t) and interface
 * to functions taking care of initialization of the server and clean-up.
 *
 * \addtogroup server
 * @{
 */

#pragma once

#include "sys/socket.h"

#include "knot/conf/conf.h"
#include "knot/common/evsched.h"
#include "knot/common/fdset.h"
#include "knot/server/dthreads.h"
#include "knot/common/ref.h"
#include "knot/server/rrl.h"
#include "knot/worker/pool.h"
#include "knot/zone/zonedb.h"
#include "contrib/ucw/lists.h"

/* Forwad declarations. */
struct server;

/*! \brief I/O handler structure.
  */
typedef struct iohandler {
	struct node        n;
	struct server      *server; /*!< Reference to server */
	dt_unit_t          *unit;   /*!< Threading unit */
	unsigned           *thread_state; /*!< Thread state */
	unsigned           *thread_id; /*!< Thread identifier. */
} iohandler_t;

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
typedef struct iface {
	struct node n;
	int *fd_udp;
	int fd_udp_count;
	int fd_tcp;
	struct sockaddr_storage addr;
} iface_t;

/* Handler indexes. */
enum {
	IO_UDP = 0,
	IO_TCP = 1
};

typedef struct ifacelist {
	ref_t ref;
	list_t l;
	list_t u;
} ifacelist_t;

/*!
 * \brief Main server structure.
 *
 * Keeps references to all important structures needed for operation.
 */
typedef struct server {

	/*! \brief Server state tracking. */
	volatile unsigned state;

	/*! \brief Zone database. */
	knot_zonedb_t *zone_db;
	knot_db_t *timers_db;

	/*! \brief I/O handlers. */
	struct {
		unsigned size;
		iohandler_t handler;
	} handlers[2];

	/*! \brief Background jobs. */
	worker_pool_t *workers;

	/*! \brief Event scheduler. */
	evsched_t sched;

	/*! \brief List of interfaces. */
	ifacelist_t* ifaces;

	/*! \brief Rate limiting. */
	rrl_table_t *rrl;

} server_t;

/*!
 * \brief Initializes the server structure.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 */
int server_init(server_t *server, int bg_workers);

/*!
 * \brief Properly destroys the server structure.
 *
 * \param server Server structure to be used for operation.
 */
void server_deinit(server_t *server);

/*!
 * \brief Starts the server.
 *
 * \param server Server structure to be used for operation.
 * \param async  Don't wait for zones to load if true.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 *
 */
int server_start(server_t *server, bool async);

/*!
 * \brief Waits for the server to finish.
 *
 * \param server Server structure to be used for operation.
 *
 */
void server_wait(server_t *server);

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
 * \brief Server reconfiguration routine.
 *
 * Routine for dynamic server reconfiguration.
 */
void server_reconfigure(conf_t *conf, server_t *data);

/*!
 * \brief Reconfigure zone database.
 *
 * Routine for dynamic server zones reconfiguration.
 */
void server_update_zones(conf_t *conf, server_t *server);

/*!
 * \brief Update fdsets from current interfaces list.
 *
 * \param server  Server.
 * \param fds     File descriptor set.
 * \param index   I/O index (UDP/TCP).
 *
 * \return new interface list
 */
ref_t *server_set_ifaces(server_t *server, fdset_t *fds, int index, int thread_id);

/*! @} */
