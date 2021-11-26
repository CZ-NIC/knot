/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

typedef struct {
	struct sockaddr_storage src;
	struct sockaddr_storage dst;
	int fd;
	knot_time_t last_active;
} conn_pool_memb_t;

typedef struct {
	size_t capacity;
	size_t usage;
	knot_timediff_t timeout;
	pthread_mutex_t mutex;
	pthread_t closing_thread;
	conn_pool_memb_t conns[];
} conn_pool_t;

extern conn_pool_t *global_conn_pool;

/*!
 * \brief Allocate connection pool.
 *
 * \param capacity  Connection pool capacity (must be positive number).
 * \param timeout   Connection timeout (must be positive number).
 *
 * \return Connection pool or NULL if error.
 */
conn_pool_t *conn_pool_init(size_t capacity, knot_timediff_t timeout);

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
int conn_pool_get(conn_pool_t *pool,
                  struct sockaddr_storage *src,
                  struct sockaddr_storage *dst);

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
int conn_pool_put(conn_pool_t *pool,
                  struct sockaddr_storage *src,
                  struct sockaddr_storage *dst,
                  int fd);
