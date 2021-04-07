#pragma once
#include "knot/query/layer.h"
#include "knot/server/server.h"
#include "contrib/sockaddr.h"
#ifdef ENABLE_ASYNC_QUERY_HANDLING
#include "knot/include/lstack.h"
#include <sys/eventfd.h>
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
 ((type *)                              \
   (  ((char *)(ptr))                   \
    - ((char *)(&((type*)0)->member)) ))

#endif

/* Buffer identifiers. */
enum {
	RX = 0,
	TX = 1,
	NBUFS = 2
};

typedef enum response_handler_type {
    response_handler_type_intermediate, /*!< Handles responses (including partial response) as soon as produced. */
    response_handler_type_final         /*!< Handles responses only after entire response is produced. */
} response_handler_type_t;

struct network_request;
typedef struct network_context {
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	lockless_stack_t async_completed_reqs;    /*!< Requests which were asynchrnously completed by modules, but processing has not resumed for these requests. */
    int async_notify_handle;                  /*!< Handle used by network handling base layer to notify that there are requests pending async handling. */
#endif
	unsigned thread_id;                       /*!< Thread identifier. */
	server_t *server;                         /*!< Name server structure. */
	const knot_layer_api_t *layer_api;        /*!< Layer API. */
    knotd_query_flag_t query_flags;           /*!< Query flags used in this network context for handling requests. */
    int (*send_response)(struct network_context *ctx, struct network_request *req);
                                              /*!< Send response to the network layer implementation. */
    int (*async_complete)(struct network_context *ctx, struct network_request *req);
                                              /*!< Notification to indicate the request has been completed asynchronously. */
    response_handler_type_t response_handler_type;
} network_context_t;

#ifdef ENABLE_ASYNC_QUERY_HANDLING
/*!
 * \brief Get the async handle that needs to be used for monitoring pending async completed requests.
 *
 * \param network network context.
 */
#define network_context_get_async_notify_handle(network_ctx) ((network_ctx)->async_notify_handle)
#endif

/*! \brief Control message to fit IP_PKTINFO or IPv6_RECVPKTINFO. */
typedef union {
	struct cmsghdr cmsg;                                     /*!< Control message header. */
	uint8_t buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];     /*!< Bufer for control message. */
} cmsg_pktinfo_t;

typedef enum network_request_flag {
#ifdef ENABLE_ASYNC_QUERY_HANDLING
    network_request_flag_is_async = (1 << 0),      /*!< Is the request is currently handled asynchronously. */
    network_request_flag_is_cancelled = (1 << 1),  /*!< Is the request cancelled. */
#endif
    network_request_flag_udp_buff = (1 << 2),     /*!< Request is using small buffer. */
    network_request_flag_tcp_buff = (1 << 3),     /*!< Request is using large buffer. */
    network_request_flag_xdp_buff = (1 << 4),     /*!< Request does not have dedicated buffer. */
} network_request_flag_t;

typedef struct network_request {
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	lockless_stack_node_t stack_node;        /*!< Node used to insert this object into different stacks. */
	network_context_t *network_ctx;          /*!< Network context this request belongs to. */
#endif
    knot_mm_t mm;                            /*!< Memory context for the request. */
	knotd_qdata_params_t params;             /*!< Query params for this request. */
	knot_layer_t layer;                      /*!< Layer used to process this query. */
	knot_pkt_t *ans;                         /*!< Answer packet produced by the layer for this query request. */
	int fd;                                  /*!< Requests received socked fd. */
    network_request_flag_t flag;             /*!< Request flags. */
} network_request_t;

typedef struct network_request_udp {
    network_request_t req;                   /*!< Common network requests objects. */
    struct sockaddr_storage addr;            /*!< Remote endpoints address. */
    struct iovec iov[NBUFS];                 /*!< iovec to receive request and send response. */
    struct msghdr msg[NBUFS];                /*!< msghdr to receive request and send response. */
    cmsg_pktinfo_t pktinfo;                  /*!< Packet info. */
} network_request_udp_t;

typedef struct network_request_tcp {
    network_request_t req;                   /*!< Common network requests objects. */
    struct iovec iov[NBUFS];                 /*!< iovec to receive request and send response. */
    struct sockaddr_storage addr;            /*!< Remote endpoints address. */
} network_request_tcp_t;

#ifdef ENABLE_XDP
typedef struct network_request_xdp {
    network_request_t req;                   /*!< Common network requests objects. */
    knot_xdp_msg_t msg[NBUFS];               /*!< XDP receive/send buffer. */
} network_request_xdp_t;
#endif

/*!
 * \brief Gets the pointer to iovec from request.
 *
 * \param req Request from which iovec to be picked.
 * \param rxtx Either RX or TX indicating receive or send iovec is requested.
 */
struct iovec * request_get_iovec(network_request_t *req, int rxtx);

#define udp_req_from_req(r) container_of(r, network_request_udp_t, req)
#define tcp_req_from_req(r) container_of(r, network_request_tcp_t, req)
#define xdp_req_from_req(r) container_of(r, network_request_xdp_t, req)

#ifdef ENABLE_ASYNC_QUERY_HANDLING
/*!
 * \brief Initializes the asynchronous request handling for the entire server. This needs to be called only one time per server.
 *
 * \param udp_async_reqs Maximum number of async requests that needs to be supported.
 * \param tcp_async_reqs Maximum number of async requests that needs to be supported.
 * \param xdp_async_reqs Maximum number of async requests that needs to be supported.
 */
int network_initialize_async_handling(size_t udp_async_reqs, size_t tcp_async_reqs, size_t xdp_async_reqs);

/*!
 * \brief Callback from network implementation when async_notify_handle is ready with events. This MUST BE called in the network_ctx thread.
 *
 * \param network network context.
 */
void network_handle_async_completed_queries(network_context_t *network_ctx);
#endif

/*!
 * \brief Initializes the query processing context for threads handling network calls.
 *
 * \param network network context.
 * \param server server for this network.
 * \param thread_id ID of the thread.
 * \param query_flags Flags used for handling queries from this network context.
 * \param handler_type Underlying network implementation type.
 * \param send_response A callback into network implementation to send the response.
 * \param async_complete A callback into network implementation to indicate the completion of async calls.
 */
int network_context_initialize( network_context_t *network_ctx, server_t *server, int thread_id,
                                knotd_query_flag_t query_flags,
                                response_handler_type_t handler_type,
                                int (*send_response)(struct network_context *ctx,
                                                        struct network_request *req),
                                int (*asyc_complete)(struct network_context *ctx,
                                                     struct network_request *req));

/*!
 * \brief Cleans up the network context.
 *
 * \param network network context.
 */
void network_context_cleanup(network_context_t *network_ctx);

/*!
 * \brief Implements the handling of DNS query and generates response.
 *
 * \param network network context.
 * \param req request to be processed.
 * \param xdp_msg XDP message if present.
 *
 * \retval Error code of the operation.
 */
int network_handle(network_context_t *network, network_request_t *req,
					   struct knot_xdp_msg *xdp_msg);

/*!
 * \brief Allocates the network request from this network_context.
 *
 * \param network network context.
 * \param mm Memory allocation context if prefered.
 * \param type Type of request to allocate.
 *
 * \retval New network request structure.
 */
network_request_t *network_allocate_request(network_context_t *network, knot_mm_t *mm, network_request_flag_t type);

/*!
 * \brief Frees the network request from this network_context.
 *
 * \param network network context.
 * \param mm Memory allocation context if prefered.
 * \param req Previously allocated request structure from network_allocate_request.
 * \param type Type of request to allocate.
 */
void network_free_request(network_context_t *network, knot_mm_t *mm, network_request_t *req);
