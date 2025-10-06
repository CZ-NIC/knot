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

#define __APPLE_USE_RFC_3542
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#ifdef HAVE_SYS_UIO_H	// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif /* HAVE_SYS_UIO_H */
#include <unistd.h>
#include <urcu.h>
#include "knot/server/dns-handler.h"

#define DISPATCH_QUEUE_SIZE (8 * 1024)

/*!
 * \brief Process dns request for first time or resume processing if it was suspended due to async handling.
 *
 * \param dns_handler DNS Handler to process the request.
 * \param dns_req DNS request to process for first time or after it is resumed from async delay state.
 *
 * \retval KNOT_EOK if succeeded.
 */
static int handle_dns_request_continue(dns_request_handler_context_t *dns_handler, dns_handler_request_t *dns_req) {
	assert(dns_handler->layer.mm == dns_req->req_data.mm);
	int ret = KNOT_EOK;
	knot_pkt_t *ans = dns_req->handler_data.ans;
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	if (dns_req->handler_data.flag & DNS_HANDLER_REQUEST_FLAG_IS_CANCELLED) {
		/* force state to be in failed state and execute produce. This guarantees module cleanup are performed */
		knot_layer_set_async_state(&dns_handler->layer, ans, KNOT_STATE_FAIL);
	}
#endif

	/* Process answer. */
	while (knot_layer_active_state(dns_handler->layer.state)) {
		knot_layer_produce(&dns_handler->layer, ans);

#ifdef ENABLE_ASYNC_QUERY_HANDLING
		if (dns_req->handler_data.flag & DNS_HANDLER_REQUEST_FLAG_IS_CANCELLED) {
			ret = KNOT_EOF;
			break;
		} else if (dns_handler->layer.state != KNOT_LAYER_STATE_ASYNC)
#endif
		{
			/* Send, if response generation passed and wasn't ignored. */
			if (dns_handler->send_result && ans->size > 0 && knot_layer_send_state(dns_handler->layer.state)) {
				int sent = dns_handler->send_result(dns_handler, dns_req, ans->size);
				if (sent != ans->size) {
					ret = KNOT_EOF;
					break;
				}
			}
		}
	}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	if (dns_handler->layer.state != KNOT_LAYER_STATE_ASYNC) {
#endif
		/* Send response only if finished successfully. */
		if (dns_handler->layer.state == KNOT_STATE_DONE) {
			dns_req->req_data.tx->iov_len = ans->size;
		} else {
			dns_req->req_data.tx->iov_len = 0;
		}

		/* Reset after processing. */
		knot_layer_finish(&dns_handler->layer);

		/* Flush per-query memory (including query and answer packets). */
		mp_flush(dns_handler->layer.mm->ctx);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	} else {
		dns_req->handler_data.flag |= DNS_HANDLER_REQUEST_FLAG_IS_ASYNC;
		knot_layer_backup_to_dns_handler_request(dns_handler->layer, *dns_req);
	}
#endif

	return ret;
}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
/*!
 * \brief Resume the execution of request processing interrupted in produce call which is currently in async delayed state.
 *
 * \param dns_handler dns request handler context.
 * \param dns_req Request to be Resumed.
 *
 * \retval KNOT_EOK if succeeded.
 */
static int handle_dns_request_resume(dns_request_handler_context_t *dns_handler, dns_handler_request_t *dns_req)
{
	assert(dns_handler_request_is_async(*dns_req));
	knot_layer_backup_from_dns_handler_request(dns_handler->layer, *dns_req);
	dns_req->handler_data.flag &= ~DNS_HANDLER_REQUEST_FLAG_IS_ASYNC;
	dns_handler->layer.state = KNOT_STATE_PRODUCE; /* State is ignored by the produce itself. But helps handle_dns_request_continue to start the produce */

	int ret = handle_dns_request_continue(dns_handler, dns_req);
	if (!dns_handler_request_is_async(*dns_req)) {
		// The requeste is completed. Notify network layer, this is done.
		dns_handler->async_complete(dns_handler, dns_req);
	}
	return ret;
}

/*!
 * \brief Callback from knot_layer_t indicating the async request is complete.
 * NOTE: This WILL BE called on the thread different from that owns the dns_request_handler_context_t.
 * Any step that creates race condition with dns_request_handler_context_t thread has to be mutexed.
 *
 * \param params params for the knot_layer_t which completed async operation.
 */
static int dns_handler_notify_async_completed(knotd_qdata_params_t *params)
{
	dns_handler_request_t *dns_req = params->dns_req;
	uint64_t value = 1;

	// capture the handle. As soon as req is put in queue, ownership of the req moves to queue and req can be dispatched and cleaned up.
	int async_notify_handle = dns_req->handler_data.dns_handler_ctx->async_notify_handle;

	bool first = false;
	int rc = knotd_lockless_queue_enqueue(dns_req->handler_data.dns_handler_ctx->async_completed_reqs, dns_req, &first);
	assert(rc == 0);

	if (first && write(async_notify_handle, &value, sizeof(value)) == -1) {
		/* Request is queued, we just did not wake up async handler, next might be able to */
		return KNOT_ESYSTEM;
	}
	else {
		return KNOT_EOK;
	}
}

/*!
 * \brief Continune processing async completed requests.
 * Network layer is expected to call this function, when dns_request_handler_context_get_async_notify_handle is signaled.
 *
 * \param dns_handler dns request handler context.
 */
void handle_dns_request_async_completed_queries(dns_request_handler_context_t *dns_handler_ctx)
{
    /* cleanup read ctx */
    uint8_t buff[8];
    /* consume the data from the async notification handle */
    _unused_ int unused = read(dns_handler_ctx->async_notify_handle, buff, sizeof(buff));

	dns_handler_request_t *dns_req;
	while ((dns_req = knotd_lockless_queue_dequeue(dns_handler_ctx->async_completed_reqs))) {
        handle_dns_request_resume(dns_handler_ctx, dns_req);
	}
}
#endif

/*!
 * \brief Initialize dns request handler.
 *
 * \param dns_handler DNS handler to be initialized.
 * \param server Server to be used in this DNS request handler.
 * \param thread_id ID of the thread that will invoke this dns_handler.
 * \param flags DNS request flags to be used in this handler.
 * \param send_result Optional. Callback method to send results to network layer. If none provided, only final result will be available in tx of request.
 * \param async_complete Notification when async query is completed.
 *
 * \retval KNOT_EOK if success.
 */
int initialize_dns_handle(
	dns_request_handler_context_t *dns_handler,
	server_t *server,
	int thread_id,
	uint8_t flags,
	send_produced_result send_result
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	,async_query_completed_callback async_complete
#endif
) {
	assert(flags & KNOTD_QUERY_FLAG_LIMIT_SIZE || send_result);
	dns_handler->server = server;
	dns_handler->thread_id = thread_id;
	dns_handler->flags = flags;
	dns_handler->send_result = send_result;
	knot_layer_init(&dns_handler->layer, NULL, process_query_layer());

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	dns_handler->async_complete = async_complete;
	dns_handler->async_notify_handle = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (dns_handler->async_notify_handle == -1) {
		return KNOT_ESYSTEM;
	}

	int ret;
    if ((ret = knotd_lockless_queue_create(&dns_handler->async_completed_reqs, DISPATCH_QUEUE_SIZE))) {
		return ret;
	}
#endif

	return 0;
}

/*!
 * \brief Cleanup dns request handler.
 *
 * \param dns_handler DNS handler to be cleaned up.
 */
void cleanup_dns_handle(dns_request_handler_context_t *dns_handler) {
#ifdef ENABLE_ASYNC_QUERY_HANDLING
    if (dns_handler->async_notify_handle != -1) {
        close(dns_handler->async_notify_handle);
        dns_handler->async_notify_handle = -1;
    }

	knotd_lockless_queue_delete(dns_handler->async_completed_reqs);
#endif
}

/*!
 * \brief handles dns request.
 *
 * \param dns_handler DNS handler to be used.
 * \param dns_req DNS request to be processed.
 *
 * \retval KNOT_EOK if success.
 */
int handle_dns_request(dns_request_handler_context_t *dns_handler, dns_handler_request_t *dns_req)
{
	dns_handler_request_clear_handler_data(*dns_req);
	knot_layer_clear_req_data(dns_handler->layer);

	// Use the memory from req for this query processing
	dns_handler->layer.mm = dns_req->req_data.mm;
	dns_req->handler_data.dns_handler_ctx = dns_handler;

	// allocate params from request memory
	knotd_qdata_params_t *params = mm_alloc(dns_handler->layer.mm, sizeof(*params));
	if (!params) {
		// failed to allocated, just fail the call
		dns_req->req_data.tx->iov_len = 0;
		return KNOT_ESPACE;
	}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	dns_req->handler_data.flag &= ~(DNS_HANDLER_REQUEST_FLAG_IS_ASYNC | DNS_HANDLER_REQUEST_FLAG_IS_CANCELLED);
	params->async_completed_callback = dns_handler_notify_async_completed;
#endif

	/* Create query processing parameter. */
	params->remote = &dns_req->req_data.source_addr;
	params->local  = &dns_req->req_data.target_addr;
	params->flags = dns_handler->flags;
	params->socket = dns_req->req_data.fd;
	params->server = dns_handler->server;
	params->xdp_msg = dns_req->req_data.xdp_msg;
	params->thread_id = dns_handler->thread_id;
	params->dns_req = dns_req;
	dns_req->handler_data.params = params;

	/* Start query processing. */
	knot_layer_begin(&dns_handler->layer, params);

	/* Create packets. */
	knot_pkt_t *query = knot_pkt_new(dns_req->req_data.rx->iov_base, dns_req->req_data.rx->iov_len, dns_handler->layer.mm);
	dns_req->handler_data.ans = knot_pkt_new(dns_req->req_data.tx->iov_base, dns_req->req_data.tx->iov_len, dns_handler->layer.mm);

	/* Input packet. */
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK && query->parsed > 0) { // parsing failed (e.g. 2x OPT)
		query->parsed--; // artificially decreasing "parsed" leads to FORMERR
	}
	knot_layer_consume(&dns_handler->layer, query);

	return handle_dns_request_continue(dns_handler, dns_req);
}
