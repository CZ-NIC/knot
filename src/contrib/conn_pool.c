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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "contrib/conn_pool.h"

#include "contrib/sockaddr.h"

conn_pool_t *global_conn_pool = NULL;

static int pool_pop(conn_pool_t *pool, size_t i);

/*!
 * \brief Try to get an open connection older than specified timestamp.
 *
 * \param pool           Pool to search in.
 * \param older_than     Timestamp that the connection must be older than.
 * \param next_oldest    Out: the timestamp of the oldest connection (other than the returned).
 *
 * \return -1 if error (no such connection), >= 0 connection file descriptor.
 *
 * \warning The returned connection is not necessarily the oldest one.
 */
static int get_old(conn_pool_t *pool,
                   knot_time_t older_than,
                   knot_time_t *next_oldest)
{
	assert(pool);

	*next_oldest = 0;

	int fd = -1;
	pthread_mutex_lock(&pool->mutex);

	for (size_t i = 0; i < pool->capacity; i++) {
		knot_time_t la = pool->conns[i].last_active;
		if (fd == -1 && knot_time_cmp(la, older_than) < 0) {
			fd = pool_pop(pool, i);
		} else if (knot_time_cmp(la, *next_oldest) < 0) {
			*next_oldest = la;
		}
	}

	pthread_mutex_unlock(&pool->mutex);
	return fd;
}

static void *closing_thread(void *_arg)
{
	conn_pool_t *pool = _arg;

	while (true) {
		knot_time_t now = knot_time(), next = 0;
		knot_timediff_t timeout = conn_pool_timeout(pool, 0);
		assert(timeout != 0);

		while (true) {
			int old_fd = get_old(pool, now - timeout + 1, &next);
			if (old_fd >= 0) {
				close(old_fd);
			} else {
				break;
			}
		}

		if (next == 0) {
			sleep(timeout);
		} else {
			sleep(next + timeout - now);
		}
	}

	return NULL; // we never get here since the thread will be cancelled instead
}

conn_pool_t *conn_pool_init(size_t capacity, knot_timediff_t timeout)
{
	if (capacity == 0 || timeout == 0) {
		return NULL;
	}

	conn_pool_t *pool = calloc(1, sizeof(*pool) + capacity * sizeof(pool->conns[0]));
	if (pool != NULL) {
		pool->capacity = capacity;
		pool->timeout = timeout;
		if (pthread_mutex_init(&pool->mutex, 0) != 0) {
			free(pool);
			return NULL;
		}
		if (pthread_create(&pool->closing_thread, NULL, closing_thread, pool) != 0) {
			pthread_mutex_destroy(&pool->mutex);
			free(pool);
			return NULL;
		}
	}
	return pool;
}

void conn_pool_deinit(conn_pool_t *pool)
{
	if (pool != NULL) {
		pthread_cancel(pool->closing_thread);
		pthread_join(pool->closing_thread, NULL);

		int fd;
		knot_time_t unused;
		while ((fd = get_old(pool, 0, &unused)) >= 0) {
			close(fd);
		}

		pthread_mutex_destroy(&pool->mutex);
		free(pool);
	}
}

knot_timediff_t conn_pool_timeout(conn_pool_t *pool,
                                  knot_timediff_t new_timeout)
{
	if (pool == NULL) {
		return 0;
	}

	pthread_mutex_lock(&pool->mutex);

	knot_timediff_t prev = pool->timeout;
	if (new_timeout != 0) {
		pool->timeout = new_timeout;
	}

	pthread_mutex_unlock(&pool->mutex);
	return prev;
}

static int pool_pop(conn_pool_t *pool, size_t i)
{
	conn_pool_memb_t *conn = &pool->conns[i];
	assert(conn->last_active != 0);
	assert(pool->usage > 0);
	int fd = conn->fd;
	memset(conn, 0, sizeof(*conn));
	pool->usage--;
	return fd;
}

int conn_pool_get(conn_pool_t *pool,
                  struct sockaddr_storage *src,
                  struct sockaddr_storage *dst)
{
	if (pool == NULL) {
		return -1;
	}

	int fd = -1;
	pthread_mutex_lock(&pool->mutex);

	for (size_t i = 0; i < pool->capacity; i++) {
		if (pool->conns[i].last_active != 0 &&
		    sockaddr_cmp(&pool->conns[i].dst, dst, false) == 0 &&
		    sockaddr_cmp(&pool->conns[i].src, src, true) == 0) {
			fd = pool_pop(pool, i);
			break;
		}
	}

	pthread_mutex_unlock(&pool->mutex);

	if (fd >= 0) {
		uint8_t unused;
		int peek = recv(fd, &unused, 1, MSG_PEEK | MSG_DONTWAIT);
		if (peek >= 0) { // closed or pending data
			close(fd);
			fd = -1;
		}
	}

	return fd;
}

static void pool_push(conn_pool_t *pool, size_t i,
                      struct sockaddr_storage *src,
                      struct sockaddr_storage *dst,
                      int fd)
{
	conn_pool_memb_t *conn = &pool->conns[i];
	assert(conn->last_active == 0);
	assert(pool->usage < pool->capacity);
	conn->last_active = knot_time();
	conn->fd = fd;
	memcpy(&conn->src, src, sizeof(conn->src));
	memcpy(&conn->dst, dst, sizeof(conn->dst));
	pool->usage++;
}

int conn_pool_put(conn_pool_t *pool,
                  struct sockaddr_storage *src,
                  struct sockaddr_storage *dst,
                  int fd)
{
	if (pool == NULL || pool->capacity == 0) {
		return fd;
	}

	knot_time_t oldest_time = 0;
	size_t oldest_i = pool->capacity;

	pthread_mutex_lock(&pool->mutex);

	for (size_t i = 0; i < pool->capacity; i++) {
		knot_time_t la = pool->conns[i].last_active;
		if (la == 0) {
			pool_push(pool, i, src, dst, fd);
			pthread_mutex_unlock(&pool->mutex);
			return -1;
		} else if (knot_time_cmp(la, oldest_time) < 0) {
			oldest_time = la;
			oldest_i = i;
		}
	}

	assert(oldest_i < pool->capacity);
	int oldest_fd = pool_pop(pool, oldest_i);
	pool_push(pool, oldest_i, src, dst, fd);
	pthread_mutex_unlock(&pool->mutex);
	return oldest_fd;
}
