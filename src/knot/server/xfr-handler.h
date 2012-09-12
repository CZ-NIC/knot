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
 * \file xfr-handler.h
 *
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief XFR requests handler.
 *
 * \addtogroup server
 * @{
 */

#ifndef _KNOTD_XFRHANDLER_H_
#define _KNOTD_XFRHANDLER_H_

#include "knot/server/dthreads.h"
#include "libknot/nameserver/name-server.h"
#include "common/evqueue.h"
#include "common/fdset.h"
#include "common/skip-list.h"

struct xfrhandler_t;

/*!
 * \brief XFR worker structure.
 */
typedef struct xfrworker_t
{
	knot_nameserver_t *ns;  /*!< \brief Pointer to nameserver.*/
	evqueue_t          *q;  /*!< \brief Shared XFR requests queue.*/
	fdset_t        *fdset; /*!< \brief File descriptor set. */
	struct xfrhandler_t *master; /*! \brief Worker master. */
} xfrworker_t;

/*!
 * \brief XFR handler structure.
 */
typedef struct xfrhandler_t
{
	dt_unit_t       *unit;  /*!< \brief Threading unit. */
	xfrworker_t **workers;  /*!< \brief Workers. */
	skip_list_t *tasks; /*!< \brief Pending tasks. */
	pthread_mutex_t tasks_mx; /*!< \brief Tasks synchronisation. */
	void (*interrupt)(struct xfrhandler_t *h); /*!< Interrupt handler. */
	unsigned rr; /*!< \brief Round-Robin counter. */
	pthread_mutex_t rr_mx; /*!< \brief RR mutex. */
} xfrhandler_t;

/*!
 * \brief Create XFR threading unit.
 *
 * Unit can be controlled by standard DThreads API.
 * Unit is created in Idle mode.
 *
 * \param thrcount Requested number of threads.
 * \param ns Pointer to nameserver.
 *
 * \retval New handler on success.
 * \retval NULL on error.
 */
xfrhandler_t *xfr_create(size_t thrcount, knot_nameserver_t *ns);

/*!
 * \brief Delete XFR handler.
 *
 * \warning Threading unit must be stopped and joined.
 *
 * \param handler XFR handler.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on NULL handler.
 * \retval KNOT_ERROR on error.
 */
int xfr_free(xfrhandler_t *handler);

/*!
 * \brief Start XFR handler.
 *
 * \param handler XFR handler.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERROR on error.
 */
static inline int xfr_start(xfrhandler_t *handler) {
	return dt_start(handler->unit);
}

/*!
 * \brief Stop XFR handler.
 *
 * \param handler XFR handler.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERROR on error.
 */
int xfr_stop(xfrhandler_t *handler);

/*!
 * \brief Wait for XFR handler to finish.
 *
 * \param handler XFR handler.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERROR on error.
 */
int xfr_join(xfrhandler_t *handler);

/*!
 * \brief Prepare XFR request.
 *
 * \param r XFR request.
 * \param type Request type.
 * \param flags Request flags.
 * \param pkt Query packet or NULL.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 * \retval KNOT_EINVAL
 */
int xfr_request_init(knot_ns_xfr_t *r, int type, int flags, knot_packet_t *pkt);

/*!
 * \brief Enqueue XFR request.
 *
 * \param handler XFR handler instance.
 * \param req XFR request.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on NULL handler or request.
 * \retval KNOT_ERROR on error.
 */
int xfr_request(xfrhandler_t *handler, knot_ns_xfr_t *req);

/*!
 * \brief Answer XFR query.
 *
 * \param ns Nameserver instance.
 * \param req XFR request.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on NULL handler or request.
 * \retval KNOT_ERROR on error.
 */
int xfr_answer(knot_nameserver_t *ns, knot_ns_xfr_t *req);

/*!
 * \brief XFR master runnable.
 *
 * Processes incoming AXFR/IXFR requests asynchonously.
 * When no thread is available at the moment, request is enqueued.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters.
 */
int xfr_worker(dthread_t *thread);

/*!
 * \brief Prepare TSIG for XFR.
 * \param xfr XFR request.
 * \param key Used TSIG key.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on NULL parameters.
 * \retval KNOT_ENOMEM when out of memory.
 */
int xfr_prepare_tsig(knot_ns_xfr_t *xfr, knot_key_t *key);

/*!
 * \brief Return formatted string of the remote as 'ip@port key $key'.
 *
 * \param addr Remote address.
 * \param keytag Used TSIG key name (or NULL).
 *
 * \return formatted string or NULL.
 */
char *xfr_remote_str(const sockaddr_t *addr, const char *keytag);

#endif // _KNOTD_XFRHANDLER_H_

/*! @} */
