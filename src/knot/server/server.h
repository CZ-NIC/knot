/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "contrib/atomic.h"
#include "knot/conf/conf.h"
#include "knot/catalog/catalog_update.h"
#include "knot/common/evsched.h"
#include "knot/common/fdset.h"
#include "knot/journal/knot_lmdb.h"
#include "knot/server/dthreads.h"
#include "knot/worker/pool.h"
#include "knot/zone/backup.h"
#include "knot/zone/zonedb.h"

#define DFLT_QUIC_KEY_FILE	"quic_key.pem"

struct server;
struct knot_xdp_socket;
struct knot_creds;

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
 * \brief Server reload kinds.
 */
typedef enum {
	RELOAD_NONE    = 0,
	RELOAD_FULL    = 1 << 0, /*!< Reload the server and all zones. */
	RELOAD_COMMIT  = 1 << 1, /*!< Process changes from dynamic configuration. */
	RELOAD_ZONES   = 1 << 2, /*!< Reload all zones. */
	RELOAD_CATALOG = 1 << 3, /*!< Process catalog zone changes. */
} reload_t;

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
	bool anyaddr;
	bool tls;
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

	struct {
		knot_atomic_uint64_t tcp_io_timeout;
		knot_atomic_uint64_t tcp_idle_timeout;

	} stats;

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
	dt_unit_t *rdb_events;

	/*! \brief Event scheduler. */
	evsched_t sched;

	/*! \brief List of interfaces. */
	iface_t *ifaces;
	size_t n_ifaces;
	bool quic_active;
	bool tls_active;

	/*! \brief Mutex protecting simultaneous access from concurrent CTL threads. */
	pthread_rwlock_t ctl_lock;

	/*! \brief Pending changes to catalog member zones, update indication. */
	catalog_update_t catalog_upd;
	knot_atomic_bool catalog_upd_signal;

	/*! \brief Context of pending zones' backup. */
	zone_backup_ctxs_t backup_ctxs;

	/*! \brief Crendentials context for QUIC. */
	struct knot_creds *quic_creds;
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
 * \param mode    Reload mode.
 *
 * \return Error code, KNOT_EOK if success.
 */
int server_reload(server_t *server, reload_t mode);

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
 * \param conf    Configuration.
 * \param server  Server instance.
 *
 * \return Error code, KNOT_EOK if success.
 */
int server_reconfigure(conf_t *conf, server_t *server);

/*!
 * \brief Reconfigure zone database.
 *
 * Routine for dynamic server zones reconfiguration.
 *
 * \param conf    Configuration.
 * \param server  Server instance.
 * \param mode    Reload mode.
 */
void server_update_zones(conf_t *conf, server_t *server, reload_t mode);

/*!
 * \brief Returns current server certificate public key PIN as base64 string.
 *
 * \param server    Server instance.
 * \param out       Output buffer.
 * \param out_size  Size of the output buffer.
 *
 * \return Length of the output PIN string.
 */
size_t server_cert_pin(server_t *server, uint8_t *out, size_t out_size);
