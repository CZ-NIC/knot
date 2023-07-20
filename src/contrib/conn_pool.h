/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <pthread.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "contrib/time.h"

typedef intptr_t conn_pool_fd_t;
extern const conn_pool_fd_t CONN_POOL_FD_INVALID;

typedef void (*conn_pool_close_cb_t)(conn_pool_fd_t fd);
typedef bool (*conn_pool_invalid_cb_t)(conn_pool_fd_t fd);

typedef struct {
	struct sockaddr_storage src;
	struct sockaddr_storage dst;
	conn_pool_fd_t fd;
	knot_time_t last_active;
} conn_pool_memb_t;

typedef struct {
	size_t capacity;
	size_t usage;
	knot_timediff_t timeout;
	pthread_mutex_t mutex;
	pthread_t closing_thread;
	conn_pool_close_cb_t close_cb;
	conn_pool_invalid_cb_t invalid_cb;
	conn_pool_memb_t conns[];
} conn_pool_t;

extern conn_pool_t *global_conn_pool;
extern conn_pool_t *global_sessticket_pool; // pool for outgoing QUIC connection session tickets

/*!
 * \brief Allocate connection pool.
 *
 * \param capacity     Connection pool capacity (must be positive number).
 * \param timeout      Connection timeout (must be positive number).
 * \param close_cb     Callback for closing fd.
 * \param invalid_cb   Callback detecting if given fd is already unusable.
 *
 * \return Connection pool or NULL if error.
 */
conn_pool_t *conn_pool_init(size_t capacity, knot_timediff_t timeout,
                            conn_pool_close_cb_t close_cb,
                            conn_pool_invalid_cb_t invalid_cb);

/*!
 * \brief Deallocate the pool, close all connections, terminate closing thread.
 *
 * \param pool  Connection pool.
 */
void conn_pool_deinit(conn_pool_t *pool);

/*!
 * \brief Get and/or set connection timeout.
 *
 * \param pool         Connection pool.
 * \param new_timeout  Optional: set new timeout (if positive number).
 *
 * \return Previous value of timeout.
 */
knot_timediff_t conn_pool_timeout(conn_pool_t *pool,
                                  knot_timediff_t new_timeout);

/*!
 * \brief Try to get an open connection if present, check if alive.
 *
 * \param pool   Pool to search in.
 * \param src    Connection source address.
 * \param dst    Connection destination address.
 *
 * \retval -1    If error (no such connection).
 * \return >= 0  File descriptor of the connection.
 */
conn_pool_fd_t conn_pool_get(conn_pool_t *pool,
                             const struct sockaddr_storage *src,
                             const struct sockaddr_storage *dst);

/*!
 * \brief Put an open connection to the pool, possibly displacing the oldest one there.
 *
 * \param pool   Pool to insert into.
 * \param src    Connestion source address.
 * \param dst    Connection destination adress.
 * \param fd     Connection file descriptor.
 *
 * \retval -1    If connection stored to free slot.
 * \retval fd    If not able to store connection.
 * \return >= 0  File descriptor of the displaced old connection.
 */
conn_pool_fd_t conn_pool_put(conn_pool_t *pool,
                             const struct sockaddr_storage *src,
                             const struct sockaddr_storage *dst,
                             conn_pool_fd_t fd);

/*!
 * \brief Default close callback calling close() on given fd.
 */
void conn_pool_close_cb_dflt(conn_pool_fd_t fd);

/*!
 * \brief Default invalidness callback detecting socket not ready to write.
 */
bool conn_pool_invalid_cb_dflt(conn_pool_fd_t fd);

/*!
 * \brief Default invalidness callback always reporting valid fd.
 */
bool conn_pool_invalid_cb_allvalid(conn_pool_fd_t fd);
