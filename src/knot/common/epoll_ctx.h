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

/*!
 * \brief I/O multiplexing with context and timeouts for each fd.
 */

#pragma once

#ifdef HAVE_EPOLL

#include <stddef.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/epoll.h>

#define EPOLL_INIT_SIZE 256 /* Resize step. */

/*! \brief Set of filedescriptors with associated context and timeouts. */
typedef struct epoll_ctx {
	int efd;                      /*!< File descriptor of epoll. */
	unsigned n;                   /*!< Active fds. */
	unsigned size;                /*!< Array size (allocated). */
	unsigned recv_size;           /*!< Size of array for received events. */
	struct epoll_event *ev;       /*!< Epoll event storage for each fd */
	void* *usrctx;                /*!< Context for each fd. */
	time_t *timeout;              /*!< Timeout for each fd (seconds precision). */
	struct epoll_event *recv_ev;  /*!< Array for received events. */
} epoll_ctx_t;

typedef struct epoll_it {
	epoll_ctx_t *ctx;         /*!< Iterator related context. */
	struct epoll_event *ptr;  /*!< Pointer on processed event. */
	int offset;               /*!< Event index offset. */
	int unprocessed;          /*!< Unprocessed events left. */
} epoll_it_t;

/*! \brief Mark-and-sweep state. */
typedef enum epoll_ctx_sweep_state {
	EPOLL_CTX_KEEP,
	EPOLL_CTX_SWEEP
} epoll_ctx_sweep_state_t;

/*! \brief Sweep callback (set, index, data) */
typedef enum epoll_ctx_sweep_state (*epoll_ctx_sweep_cb_t)(epoll_ctx_t*, int, void*);

/*!
 * \brief Initialize epoll_ctx to given size.
 *
 * \param ctx Target ctx.
 * \param size Initial ctx size.
 *
 * \retval ret == 0 if successful.
 * \retval ret < 0 on error.
 */
int epoll_ctx_init(epoll_ctx_t *ctx, const unsigned size);

/*!
 * \brief Clear whole context of epoll_ctx.
 *
 * \param ctx Target ctx.
 *
 * \retval ret == 0 if successful.
 * \retval ret < 0 on error.
 */
int epoll_ctx_clear(epoll_ctx_t* ctx);

/*!
 * \brief Close epoll related file descriptor.
 *
 * \param ctx Target ctx.
 */
void epoll_ctx_close(const epoll_ctx_t* ctx);

/*!
 * \brief Add file descriptor to watched ctx.
 *
 * \param ctx Target ctx.
 * \param fd Added file descriptor.
 * \param events Mask of watched events.
 * \param usrctx Context (optional).
 *
 * \retval ret >= 0 is index of the added fd.
 * \retval ret < 0 on errors.
 */
int epoll_ctx_add(epoll_ctx_t *ctx, const int fd, const unsigned events, void *usrctx);

/*!
 * \brief Wait for receive events.
 *
 * \param ctx Target ctx.
 * \param it Event iterator storage.
 * \param offset Index of first event.
 * \param timeout Timeout of operation (negative number for unlimited).
 *
 * \retval ret >= 0 represents number of events received.
 * \retval ret < 0 on error.
 */
int epoll_ctx_wait(epoll_ctx_t *ctx, epoll_it_t *it, const unsigned offset, const int timeout);

/*!
 * \brief Set file descriptor watchdog interval.
 *
 * Set time (interval from now) after which the associated file descriptor
 * should be sweeped (see epoll_ctx_sweep). Good example is setting a grace period
 * of N seconds between socket activity. If socket is not active within
 * <now, now + interval>, it is sweeped and potentially closed.
 *
 * \param ctx Target ctx.
 * \param i Index for the file descriptor.
 * \param interval Allowed interval without activity (seconds).
 *                 -1 disables watchdog timer
 *
 * \retval ret == 0 on success.
 * \retval ret < 0 on errors.
 */
int epoll_ctx_set_watchdog(epoll_ctx_t *ctx, const unsigned idx, const int interval);

/*!
 * \brief Returns file descriptor based on index.
 *
 * \param ctx Target ctx.
 * \param idx Index of the file descriptor.
 *
 * \retval ret >= 0 for file descriptor.
 * \retval ret < 0 on errors.
 */
int epoll_ctx_get_fd(const epoll_ctx_t *ctx, const unsigned idx);

/*!
 * \brief Returns number of file descriptors stored in ctx.
 *
 * \param ctx Target ctx.
 *
 * \retval Number of descriptors stored
 */
unsigned epoll_ctx_get_length(const epoll_ctx_t *ctx);

/*!
 * \brief Sweep file descriptors with exceeding inactivity period.
 *
 * \param ctx Target ctx.
 * \param cb Callback for sweeped descriptors.
 * \param data Pointer to extra data.
 *
 * \retval number of sweeped descriptors.
 * \retval -1 on errors.
 */
int epoll_ctx_sweep(epoll_ctx_t* ctx, const epoll_ctx_sweep_cb_t cb, void *data);

/*!
 * \brief Move iterator on next received event.
 *
 * \param it Target iterator.
 */
void epoll_it_next(epoll_it_t *it);

/*!
 * \brief Decide if there is more received events.
 *
 * \param it Target iterator.
 *
 * \retval Logical flag represents 'done' state.
 */
int epoll_it_done(const epoll_it_t *it);

/*!
 * \brief Remove file descriptor from watched ctx.
 *
 * \param it Target iterator.
 *
 * \retval 0 if successful.
 * \retval ret < 0 on error.
 */
int epoll_it_remove(epoll_it_t *it);

/*!
 * \brief Get file descriptor of event referenced by iterator.
 *
 * \param it Target iterator.
 *
 * \retval ret >= 0 for file descriptor.
 * \retval ret < 0 on errors.
 */
int epoll_it_get_fd(const epoll_it_t *it);

/*!
 * \brief Get index of event in set referenced by iterator.
 *
 * \param it Target iterator.
 *
 * \retval Index of event.
 */
unsigned epoll_it_get_idx(const epoll_it_t *it);

/*!
 * \brief Decide if event referenced by iterator is POLLIN event.
 *
 * \param it Target iterator.
 *
 * \retval Logical flag represents 'POLLIN' event received.
 */
int epoll_it_ev_is_pollin(const epoll_it_t *it);

/*!
 * \brief Decide if event referenced by iterator is error event.
 *
 * \param it Target iterator.
 *
 * \retval Logical flag represents error event received.
 */
int epoll_it_ev_is_err(const epoll_it_t *it);

#endif
