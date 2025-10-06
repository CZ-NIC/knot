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

#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"
#include "knot/common/fdset.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "knot/server/server.h"
#include "libknot/xdp/xdp.h"
#ifdef ENABLE_ASYNC_QUERY_HANDLING
#include "knot/include/lqueue.h"
#include <sys/eventfd.h>
#endif

/* Buffer identifiers. */
enum {
	RX = 0,
	TX = 1,
	NBUFS = 2
};

typedef struct dns_request_handler_context dns_request_handler_context_t;
typedef struct dns_handler_request dns_handler_request_t;
typedef int (*send_produced_result)(dns_request_handler_context_t *net, dns_handler_request_t *req, size_t size);

#ifdef ENABLE_ASYNC_QUERY_HANDLING
typedef void (*async_query_completed_callback)(dns_request_handler_context_t *net, dns_handler_request_t *req);

/*! \brief DNS request handler flags. */
typedef enum dns_handler_request_flag {
	DNS_HANDLER_REQUEST_FLAG_IS_ASYNC = (1 << 0),	  /*!< Is the request is currently handled asynchronously. */
	DNS_HANDLER_REQUEST_FLAG_IS_CANCELLED = (1 << 1),  /*!< Is the request cancelled. */
} dns_handler_request_flag_t;
#endif

/*! \brief DNS request handler context data. */
struct dns_request_handler_context {
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	knotd_lockless_queue_t *async_completed_reqs;	/*!< Requests which were asynchrnously completed by modules, but processing has not resumed for these requests. */
	async_query_completed_callback async_complete;	/*!< Callback to network layer to indicate that the query in async state is completed. */
	int async_notify_handle;						/*!< Handle used by dns request handling base layer to notify that there are requests pending async handling. */
#endif
	knot_layer_t layer;					/*!< Query processing layer. */
	server_t *server;					/*!< Name server structure. */
	send_produced_result send_result;	/*!< Sends the results produced.
										If this is null, the sender handles the response after completion of dns request handling
										and sends only single result. */
	unsigned thread_id;					/*!< Thread identifier. */
	uint8_t flags;						/*!< Flags for dns request handler for how to handle request. */
};

/*! \brief Network request data from network layer. */
typedef struct dns_handler_network_layer_request {
	struct sockaddr_storage source_addr;	/*!< Source address. */
	struct sockaddr_storage target_addr;	/*!< Target address. */
	struct iovec *rx;						/*!< Received iovec. */
	struct iovec *tx;						/*!< Send iovec. */
	struct knot_xdp_msg *xdp_msg;			/*!< XDP message. */
	knot_mm_t *mm;							/*!< Processing memory context. */
	int fd;									/*!< handle for the network request. */
} dns_handler_network_layer_request_t;

/*! \brief Network handler data to process the request. */
typedef struct dns_handler_request_data {
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	dns_handler_request_flag_t flag;					/*!< Flags for the req. */
#endif
	knot_pkt_t *ans;									/*!< Answer for the req. */
	dns_request_handler_context_t *dns_handler_ctx;		/*!< dns request handler context for the req. */
	knotd_qdata_params_t *params;						/*!< params for this req. */
	struct {
		knot_layer_state_t state;			//!< Processing state.
		void *data;							//!< Module specific.
		tsig_ctx_t *tsig;					//!< TODO: remove
		unsigned flags;						//!< Custom flags.
	} layer_data_backup_on_async_stop;		//!< Layer data backup when req was offline. Valid only when req is offline.
} dns_handler_request_data_t;

/*! \brief Dns handler request data. */
struct dns_handler_request {
	dns_handler_network_layer_request_t req_data;	/*!< Data from network layer. Only data here can be exchanged between network layer and dns handler. */
	dns_handler_request_data_t handler_data;		/*!< Data from dns request handler. This data should be treated private for dns handler and network handler should not use it. */
};

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
);

/*!
 * \brief Cleanup dns request handler.
 *
 * \param dns_handler DNS handler to be cleaned up.
 */
void cleanup_dns_handle(dns_request_handler_context_t *dns_handler);

/*!
 * \brief handles dns request.
 *
 * \param dns_handler DNS handler to be used.
 * \param dns_req DNS request to be processed.
 *
 * \retval KNOT_EOK if success.
 */
int handle_dns_request(dns_request_handler_context_t *dns_handler, dns_handler_request_t *dns_req);

/*!
 * \brief Clear the request with any previously processed query state information.
 *
 * \param dns_req DNS request that needs to be reset.
 */
#define dns_handler_request_clear_handler_data(dns_req) memset(&((dns_req).handler_data), 0, sizeof(dns_handler_request_data_t))

#ifdef ENABLE_ASYNC_QUERY_HANDLING
/*!
 * \brief Get the async handle that needs to be used for monitoring pending async completed requests.
 *
 * \param dns_handler dns request handler context.
 *
 * \retval Poll handle for monitoring existence of queries in async queue ready to execute.
 */
#define dns_request_handler_context_get_async_notify_handle(dns_handler) ((dns_handler)->async_notify_handle)

/*!
 * \brief Gets if a DNS request is in async state.
 *
 * \param dns_req DNS request whose async state needs to be checked.
 *
 * \retval true if the request is in async state.
 */
#define dns_handler_request_is_async(dns_req) ((dns_req).handler_data.flag & DNS_HANDLER_REQUEST_FLAG_IS_ASYNC)

/*!
 * \brief Gets if a DNS request is in cancelled state.
 *
 * \param dns_req DNS request whose async state needs to be checked.
 *
 * \retval true if the request is in cancelled state.
 */
#define dns_handler_request_is_cancelled(dns_req) ((dns_req).handler_data.flag & DNS_HANDLER_REQUEST_FLAG_IS_CANCELLED)

/*!
 * \brief Cancels the request from being processed.
 *
 * \param dns_req DNS request whose async state needs to be changed.
 */
#define dns_handler_cancel_request(dns_req) ((dns_req).handler_data.flag |= DNS_HANDLER_REQUEST_FLAG_IS_CANCELLED)

/*!
 * \brief Handle DNS async completed queries in this dns handler.
 *
 * \param dns_handler dns request handler context.
 */
void handle_dns_request_async_completed_queries(dns_request_handler_context_t *dns_handler);

#endif

/*!
 * \brief Backup the layer state into request itself,
 * \brief to allow layer to process other requests while current request is delayed by async processing.
 *
 * \param layer Layer whose states need to be preserved.
 * \param dns_req DNS request that needs to be used to preserve layer state.
 */
#define knot_layer_backup_to_dns_handler_request(layer, dns_req) {						\
	assert((layer).mm == (dns_req).req_data.mm);										\
	(dns_req).handler_data.layer_data_backup_on_async_stop.state = (layer).state;		\
	(dns_req).handler_data.layer_data_backup_on_async_stop.data = (layer).data;			\
	(dns_req).handler_data.layer_data_backup_on_async_stop.tsig = (layer).tsig;			\
	(dns_req).handler_data.layer_data_backup_on_async_stop.flags = (layer).flags;		\
}

/*!
 * \brief Restore the layer state from request,
 * \brief to resume processing request that was previously delayed due to async
 *
 * \param layer Layer whose states need to be restored.
 * \param dns_req DNS request that needs to be used to restore layer state.
 */
#define knot_layer_backup_from_dns_handler_request(layer, dns_req) {					\
	(layer).mm = (dns_req).req_data.mm;													\
	(layer).state = (dns_req).handler_data.layer_data_backup_on_async_stop.state;		\
	(layer).data = (dns_req).handler_data.layer_data_backup_on_async_stop.data;			\
	(layer).tsig = (dns_req).handler_data.layer_data_backup_on_async_stop.tsig;			\
	(layer).flags = (dns_req).handler_data.layer_data_backup_on_async_stop.flags;		\
}


