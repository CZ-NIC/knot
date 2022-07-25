/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "knot/conf/conf.h"
#include "knot/catalog/catalog_update.h"
#include "knot/common/evsched.h"
#include "knot/common/fdset.h"
#include "knot/journal/knot_lmdb.h"
#include "knot/server/dthreads.h"
#include "knot/worker/pool.h"
#include "knot/zone/backup.h"
#include "knot/zone/zonedb.h"

struct server;
struct knot_xdp_socket;
struct knot_quic_creds;

/*!
 * \brief I/O handler structure.
 */
typedef struct {
	struct server *server;  /*!< Reference to server. */
	dt_unit_t *unit;        /*!< Threading unit. */
	unsigned *thread_state; /*!< Thread states. */
	unsigned *thread_id;    /*!< Thread identifiers per all handlers. */
} iohandler_t;

/*!
 * \brief Server state flags.
 */
typedef enum {
	ServerIdle    = 0 << 0, /*!< Server is idle. */
	ServerRunning = 1 << 0, /*!< Server is running. */
} server_state_t;

/*!
 * \brief Server interface structure.
 */
typedef struct {
	int *fd_udp;
	unsigned fd_udp_count;
	int *fd_tcp;
	unsigned fd_tcp_count;
	int *fd_xdp;
	unsigned fd_xdp_count;
	unsigned xdp_first_thread_id;
	struct knot_xdp_socket **xdp_sockets;
	struct sockaddr_storage addr;
} iface_t;

/*!
 * \brief Handler indexes.
 */
enum {
	IO_UDP = 0,
	IO_TCP = 1,
	IO_XDP = 2,
};

/*!
 * \brief Main server structure.
 *
 * Keeps references to all important structures needed for operation.
 */
typedef struct server {
	/*! \brief Server state tracking. */
	volatile unsigned state;

	knot_zonedb_t *zone_db;
	knot_lmdb_db_t timerdb;
	knot_lmdb_db_t journaldb;
	knot_lmdb_db_t kaspdb;
	catalog_t catalog;

	/*! \brief I/O handlers. */
	struct {
		unsigned size;
		iohandler_t handler;
	} handlers[3];

	/*! \brief Background jobs. */
	worker_pool_t *workers;

	/*! \brief Event scheduler. */
	evsched_t sched;

	/*! \brief List of interfaces. */
	iface_t *ifaces;
	size_t n_ifaces;

	/*! \brief Pending changes to catalog member zones. */
	catalog_update_t catalog_upd;

	/*! \brief Context of pending zones' backup. */
	zone_backup_ctxs_t backup_ctxs;

	/*! \brief Crendentials context for QUIC. */
	struct knot_quic_creds *quic_creds;
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
 * \param server  Server instance.
 *
 * \return Error code, KNOT_EOK if success.
 */
int server_reload(server_t *server);

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
 *
 * \return Error code, KNOT_EOK if success.
 */
int server_reconfigure(conf_t *conf, server_t *server);

/*!
 * \brief Reconfigure zone database.
 *
 * Routine for dynamic server zones reconfiguration.
 */
void server_update_zones(conf_t *conf, server_t *server);
