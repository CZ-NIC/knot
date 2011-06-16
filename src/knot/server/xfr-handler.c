#include <config.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "knot/common.h"
#include "knot/server/xfr-handler.h"
#include "knot/server/name-server.h"
#include "knot/other/error.h"

/*
 * Public APIs.
 */

xfrhandler_t *xfr_create(size_t thrcount, ns_nameserver_t *ns)
{
	/* Create XFR handler data. */
	xfrhandler_t *data = malloc(sizeof(xfrhandler_t));
	if (!data) {
		return 0;
	}
	data->ns = ns;

	/* Create event queue. */
	data->q = evqueue_new();
	if (!data->q) {
		free(data);
		return 0;
	}

	/* Create threading unit. */
	dt_unit_t *unit = 0;
	unit = dt_create_coherent(thrcount, &xfr_master, (void*)data);
	if (!unit) {
		evqueue_free(&data->q);
		free(data);
		return 0;
	}
	data->unit = unit;

	return data;
}

int xfr_free(xfrhandler_t *handler)
{
	if (!handler) {
		return KNOT_EINVAL;
	}

	/* Remove handler data. */
	evqueue_free(&handler->q);

	/* Delete unit. */
	dt_delete(&handler->unit);
	free(handler);

	return KNOT_EOK;
}

int xfr_request(xfrhandler_t *handler, ns_xfr_t *req)
{
	if (!handler || !req) {
		return KNOT_EINVAL;
	}

	int ret = evqueue_write(handler->q, req, sizeof(ns_xfr_t));
	if (ret < 0) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int xfr_master(dthread_t *thread)
{
	xfrhandler_t *data = (xfrhandler_t *)thread->data;

	/* Check data. */
	if (data < 0) {
		debug_net("xfr_master: no data recevied, finishing.\n");
		return KNOT_EINVAL;
	}

	/* Buffer for answering. */
	uint8_t buf[65535];

	/* Accept requests. */
	debug_net("xfr_master: thread started.\n");
	for (;;) {

		/* Poll new events. */
		int ret = evqueue_poll(data->q, 0);

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			debug_net("xfr_master: finished.\n");
			return KNOT_EOK;
		}

		/* Check poll count. */
		if (ret <= 0) {
			debug_net("xfr_master: queue poll returned %d.\n", ret);
			return KNOT_ERROR;
		}

		/* Read single request. */
		ns_xfr_t xfr;
		ret = evqueue_read(data->q, &xfr, sizeof(ns_xfr_t));
		debug_net("xfr_master: started AXFR request.\n", ret);
		if (ret != sizeof(ns_xfr_t)) {
			debug_net("xfr_master: queue read returned %d.\n", ret);
			return KNOT_ERROR;
		}

		/* Update request. */
		xfr.response_wire = buf;
		xfr.rsize = sizeof(buf);

		/* Handle request. */
		ret = ns_answer_axfr(data->ns, &xfr);
		debug_net("xfr_master: ns_answer_axfr() returned %d.\n", ret);
		if (ret != KNOT_EOK) {
			log_server_error("AXFR request failed: %s\n",
					 knot_strerror(ret));
		}
	}


	// Stop whole unit
	debug_net("xfr_master: finished.\n");
	return KNOT_EOK;
}
