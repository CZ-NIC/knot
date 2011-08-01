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

#ifndef _KNOT_XFRHANDLER_H_
#define _KNOT_XFRHANDLER_H_

#include <ev.h>

#include "knot/server/dthreads.h"
#include "knot/server/name-server.h"
#include "common/evqueue.h"

/*!
 * \brief XFR handler structure.
 */
typedef struct xfrhandler_t
{
	dt_unit_t     *unit;  /*!< \brief Threading unit. */
	dnslib_nameserver_t *ns;  /*!< \brief Pointer to nameserver.*/
	evqueue_t        *q;  /*!< \brief Shared XFR requests queue.*/
	evqueue_t       *cq;  /*!< \brief XFR client requests queue.*/
	struct ev_loop *loop; /*!< \brief Event loop. */
	void (*interrupt)(struct xfrhandler_t *h); /*!< Interrupt handler. */
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
xfrhandler_t *xfr_create(size_t thrcount, dnslib_nameserver_t *ns);

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
static inline int xfr_join(xfrhandler_t *handler) {
	return dt_join(handler->unit);
}

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
int xfr_request(xfrhandler_t *handler, dnslib_ns_xfr_t *req);

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
int xfr_master(dthread_t *thread);

/*!
  * \brief XFR client runnable.
  *
  * Processess AXFR/IXFR client sessions.
  *
  * \param thread Associated thread from DThreads unit.
  *
  * \retval KNOT_EOK on success.
  * \retval KNOT_EINVAL invalid parameters.
  */
int xfr_client(dthread_t *thread);

#endif // _KNOT_XFRHANDLER_H_

/*! @} */
