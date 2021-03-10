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

#ifdef USE_EPOLL

#include <stddef.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/epoll.h>

#define FDSET_INIT_SIZE 256 /* Resize step. */

/*! \brief Set of filedescriptors with associated context and timeouts. */
typedef struct epoll_ctx {
	int efd;
	unsigned n;               /*!< Active fds. */
	unsigned size;            /*!< Array size (allocated). */
	struct epoll_event *ev;   /*!< Epoll event storage for each fd */
	void* *usrctx;            /*!< Context for each fd. */
	time_t *timeout;          /*!< Timeout for each fd (seconds precision). */
    unsigned recv_size;
    struct epoll_event *recv_ev;
} epoll_ctx_t;

typedef struct epoll_it {
    epoll_ctx_t *ctx;
    struct epoll_event *ptr;
    int offset;
    int left;
} epoll_it_t;

/*! \brief Mark-and-sweep state. */
typedef enum epoll_ctx_sweep_state {
	EPOLL_CTX_KEEP,
	EPOLL_CTX_SWEEP
} epoll_ctx_sweep_state_t;

/*! \brief Sweep callback (set, index, data) */
typedef enum epoll_ctx_sweep_state (*epoll_ctx_sweep_cb_t)(epoll_ctx_t*, int, void*);

/*!
 * \brief Initialize fdset to given size.
 */
int epoll_ctx_init(epoll_ctx_t *set, unsigned size);

/*!
 * \brief Destroy FDSET.
 *
 * \retval 0 if successful.
 * \retval -1 on error.
 */
int epoll_ctx_clear(epoll_ctx_t* set);

void epoll_ctx_close(epoll_ctx_t* set);

/*!
 * \brief Add file descriptor to watched set.
 *
 * \param set Target set.
 * \param fd Added file descriptor.
 * \param events Mask of watched events.
 * \param ctx Context (optional).
 *
 * \retval index of the added fd if successful.
 * \retval -1 on errors.
 */
int epoll_ctx_add(epoll_ctx_t *set, int fd, unsigned events, void *ctx);

/*!
 * \brief Remove file descriptor from watched set.
 *
 * \param set Target set.
 * \param i Index of the removed fd.
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int epoll_ctx_remove_it(epoll_ctx_t *set, epoll_it_t *it);

int epoll_ctx_wait(epoll_ctx_t *ctx, epoll_it_t *it, unsigned offset, unsigned ev_size, int timeout);

/*!
 * \brief Set file descriptor watchdog interval.
 *
 * Set time (interval from now) after which the associated file descriptor
 * should be sweeped (see fdset_sweep). Good example is setting a grace period
 * of N seconds between socket activity. If socket is not active within
 * <now, now + interval>, it is sweeped and potentially closed.
 *
 * \param set Target set.
 * \param i Index for the file descriptor.
 * \param interval Allowed interval without activity (seconds).
 *                 -1 disables watchdog timer
 *
 * \retval 0 if successful.
 * \retval -1 on errors.
 */
int epoll_ctx_set_watchdog(epoll_ctx_t *set, unsigned i, int interval);

unsigned epoll_ctx_get_length(epoll_ctx_t *ctx);


int epoll_ctx_get_fd(epoll_ctx_t *set, unsigned i);

/*!
 * \brief Sweep file descriptors with exceeding inactivity period.
 *
 * \param set Target set.
 * \param cb Callback for sweeped descriptors.
 * \param data Pointer to extra data.
 *
 * \retval number of sweeped descriptors.
 * \retval -1 on errors.
 */
int epoll_ctx_sweep(epoll_ctx_t* set, epoll_ctx_sweep_cb_t cb, void *data);


void epoll_it_next(epoll_it_t *it);

int epoll_it_done(epoll_it_t *it);

int epoll_it_get_fd(epoll_it_t *it);

unsigned epoll_it_get_idx(epoll_it_t *it);

int epoll_it_ev_is_poll(epoll_it_t *it);

int epoll_it_ev_is_err(epoll_it_t *it);

#endif