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
#include "common/hattrie/ahtable.h"

struct xfrhandler_t;

/*! \brief Transfer state. */
enum xfrstate_t {
	XFR_IDLE = 0,
	XFR_SCHED,
	XFR_PENDING,
};

/*!
 * \brief XFR worker structure.
 */
typedef struct xfrworker_t
{
	struct {
		ahtable_t *t;
		fdset_t   *fds;
	} pool;
	unsigned pending;
	struct xfrhandler_t *master; /*! \brief Worker master. */
} xfrworker_t;

/*!
 * \brief XFR handler structure.
 */
typedef struct xfrhandler_t
{
	list queue;
	pthread_mutex_t mx; /*!< \brief Tasks synchronisation. */
	knot_nameserver_t *ns;
	dt_unit_t       *unit;  /*!< \brief Threading unit. */
	xfrworker_t workers[];  /*!< \brief Workers. */
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
 * \param xfr XFR handler.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on NULL handler.
 * \retval KNOT_ERROR on error.
 */
int xfr_free(xfrhandler_t *xfr);

/*!
 * \brief Start XFR handler.
 *
 * \param xfr XFR handler.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERROR on error.
 */
static inline int xfr_start(xfrhandler_t *xfr) {
	return dt_start(xfr->unit);
}

/*!
 * \brief Stop XFR handler.
 *
 * \param xfr XFR handler.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERROR on error.
 */
int xfr_stop(xfrhandler_t *xfr);

/*!
 * \brief Wait for XFR handler to finish.
 *
 * \param xfr XFR handler.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERROR on error.
 */
int xfr_join(xfrhandler_t *xfr);

/*!
 * \brief Enqueue XFR request.
 *
 * \param xfr XFR handler instance.
 * \param req XFR request.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on NULL handler or request.
 * \retval KNOT_ERROR on error.
 */
int xfr_enqueue(xfrhandler_t *xfr, knot_ns_xfr_t *rq);

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
int xfr_answer(knot_nameserver_t *ns, knot_ns_xfr_t *rq);

/*!
 * \brief Prepare XFR request.
 *
 * \param z Related zone.
 * \param type Request type.
 * \param flags Request flags.
 *
 * \return new request
 */
knot_ns_xfr_t *xfr_task_create(knot_zone_t *z, int type, int flags);

/*!
 * \brief Free XFR request.
 * \param rq Request.
 * \return KNOT_EOK or KNOT_EINVAL
 */
int xfr_task_free(knot_ns_xfr_t *rq);

/*!
 * \brief Set XFR request destination/source address.
 *
 * \param rq XFR request,
 * \param to Destination address.
 * \param from Source address.
 * \return
 */
int xfr_task_setaddr(knot_ns_xfr_t *rq, sockaddr_t *to, sockaddr_t *from);

/*!
 * \brief Return formatted string of the remote as 'ip\@port key $key'.
 *
 * \param addr Remote address.
 * \param keytag Used TSIG key name (or NULL).
 *
 * \return formatted string or NULL.
 */
char *xfr_remote_str(const sockaddr_t *addr, const char *keytag);

#endif // _KNOTD_XFRHANDLER_H_

/*! @} */
