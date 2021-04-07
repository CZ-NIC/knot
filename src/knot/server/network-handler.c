#define __APPLE_USE_RFC_3542

#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <assert.h>
#include <sys/param.h>
#ifdef HAVE_SYS_UIO_H	// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif /* HAVE_SYS_UIO_H */

#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "knot/server/server.h"
#include "knot/server/network-handler.h"

/*!
 * \brief Allocates the network request for udp.
 *
 * \param mm Memory allocation context if prefered.
 *
 * \retval New network request structure.
 */
static network_request_t *req_allocate_internal_udp(knot_mm_t *mm)
{
	network_request_udp_t *udp_req = mm_alloc(mm, sizeof(network_request_udp_t));
	if (udp_req == NULL) {
		return NULL;
	}
	network_request_t *req = &udp_req->req;

	for (unsigned i = 0; i < NBUFS; ++i) {
		udp_req->iov[i].iov_base = mm_alloc(mm, KNOT_WIRE_MAX_UDP_PKTSIZE);
		udp_req->iov[i].iov_len = KNOT_WIRE_MAX_UDP_PKTSIZE;
		if (udp_req->iov[i].iov_base == NULL) {
			for (unsigned j = 0; j < i; ++j) {
				mm_free(mm, udp_req->iov[j].iov_base);
			}
			mm_free(mm, udp_req);
			return NULL;
		}
		VALGRIND_MAKE_MEM_UNDEFINED(udp_req->iov[i].iov_base, KNOT_WIRE_MAX_UDP_PKTSIZE);

		udp_req->msg[i].msg_name = &udp_req->addr;
		udp_req->msg[i].msg_namelen = sizeof(udp_req->addr);
		udp_req->msg[i].msg_iov = &udp_req->iov[i];
		udp_req->msg[i].msg_iovlen = 1;
		udp_req->msg[i].msg_control = &udp_req->pktinfo.cmsg;
		udp_req->msg[i].msg_controllen = sizeof(udp_req->pktinfo);
	}

    /* Create big enough memory cushion. */
	mm_ctx_mempool(&req->mm, 16 * MM_DEFAULT_BLKSIZE);
    req->flag = network_request_flag_udp_buff;

	return req;
}

/*!
 * \brief Allocates the network request for tcp.
 *
 * \param mm Memory allocation context if prefered.
 *
 * \retval New network request structure.
 */
static network_request_t *req_allocate_internal_tcp(knot_mm_t *mm)
{
	network_request_tcp_t *tcp_req = mm_alloc(mm, sizeof(network_request_tcp_t));
	if (tcp_req == NULL) {
		return NULL;
	}
	network_request_t *req = &tcp_req->req;

	for (unsigned i = 0; i < NBUFS; ++i) {
		tcp_req->iov[i].iov_base = mm_alloc(mm, KNOT_WIRE_MAX_PKTSIZE);
		tcp_req->iov[i].iov_len = KNOT_WIRE_MAX_PKTSIZE;
		if (tcp_req->iov[i].iov_base == NULL) {
			for (unsigned j = 0; j < i; ++j) {
				mm_free(mm, tcp_req->iov[j].iov_base);
			}
			mm_free(mm, tcp_req);
			return NULL;
		}
		VALGRIND_MAKE_MEM_UNDEFINED(tcp_req->iov[i].iov_base, KNOT_WIRE_MAX_PKTSIZE);
	}

    /* Create big enough memory cushion. */
	mm_ctx_mempool(&req->mm, 16 * MM_DEFAULT_BLKSIZE);
    req->flag = network_request_flag_tcp_buff;

	return req;
}

#ifdef ENABLE_XDP
/*!
 * \brief Allocates the network request for xdp.
 *
 * \param mm Memory allocation context if prefered.
 *
 * \retval New network request structure.
 */
static network_request_t *req_allocate_internal_xdp(knot_mm_t *mm)
{
	network_request_xdp_t *xdp_req = mm_calloc(mm, 1, sizeof(network_request_xdp_t));
	if (xdp_req == NULL) {
		return NULL;
	}
	network_request_t *req = &xdp_req->req;

    /* Create big enough memory cushion. */
	mm_ctx_mempool(&req->mm, 16 * MM_DEFAULT_BLKSIZE);
    req->flag = network_request_flag_xdp_buff;

	return req;
}
#endif

/*!
 * \brief Frees the network request.
 *
 * \param mm Memory allocation context if prefered.
 * \param req Previously allocated request structure from network_request_t.
 */
void req_free_internal(knot_mm_t *mm, network_request_t *req)
{
	if (req) {
		void *req_container = NULL;
		if (req->flag & network_request_flag_udp_buff) {
			network_request_udp_t *udp_req = udp_req_from_req(req);
			req_container = udp_req;
			for (unsigned i = 0; i < NBUFS; ++i) {
                mm_free(mm, udp_req->iov[i].iov_base);
				VALGRIND_MAKE_MEM_NOACCESS(udp_req->iov[i].iov_base, KNOT_WIRE_MAX_UDP_PKTSIZE);
            }
		} else if (req->flag & network_request_flag_tcp_buff) {
			network_request_tcp_t *tcp_req = tcp_req_from_req(req);
			req_container = tcp_req;
			for (unsigned i = 0; i < NBUFS; ++i) {
                mm_free(mm, tcp_req->iov[i].iov_base);
				VALGRIND_MAKE_MEM_NOACCESS(tcp_req->iov[i].iov_base, KNOT_WIRE_MAX_PKTSIZE);
            }
		}
#ifdef ENABLE_XDP
		else if (req->flag & network_request_flag_xdp_buff) {
			req_container = xdp_req_from_req(req);
		}
#endif
		mm_free(mm, req_container);
	}
}


struct sockaddr_storage *request_get_address_from(network_request_t *req)
{
	if (req->flag & network_request_flag_udp_buff) {
		network_request_udp_t *udp_req = udp_req_from_req(req);
		return &udp_req->addr;
	} else 	if (req->flag & network_request_flag_tcp_buff) {
		network_request_tcp_t *tcp_req = tcp_req_from_req(req);
		return &tcp_req->addr;
	}
#ifdef ENABLE_XDP
	else if (req->flag & network_request_flag_xdp_buff) {
		network_request_xdp_t *xdp_req = xdp_req_from_req(req);
		return (struct sockaddr_storage *)&xdp_req->msg[RX].ip_from;
	}
#endif
	assert(0);
	return NULL;
}

struct iovec * request_get_iovec(network_request_t *req, int rxtx)
{
	if (req->flag & network_request_flag_udp_buff) {
		network_request_udp_t *udp_req = udp_req_from_req(req);
		return &udp_req->iov[rxtx];
	} else 	if (req->flag & network_request_flag_tcp_buff) {
		network_request_tcp_t *tcp_req = tcp_req_from_req(req);
		return &tcp_req->iov[rxtx];
	}
#ifdef ENABLE_XDP
	else if (req->flag & network_request_flag_xdp_buff) {
		network_request_xdp_t *xdp_req = xdp_req_from_req(req);
		return &xdp_req->msg[rxtx].payload;
	}
#endif
	assert(0);
	return NULL;
}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
typedef struct {
	lockless_stack_t free_reqs_udp;             /*!< free pool of requests with small IO buffer. */
	lockless_stack_t free_reqs_tcp;             /*!< free pool of requests with large IO buffer. */
#ifdef ENABLE_XDP
	lockless_stack_t free_reqs_xdp;              /*!< free pool of requests with no IO buffer. */
#endif
	knot_mm_t mm;
} req_pool_t;

req_pool_t global_pool;

static int req_pool_init(req_pool_t *pool)
{
	lockless_stack_init(&pool->free_reqs_udp);
	lockless_stack_init(&pool->free_reqs_tcp);
#ifdef ENABLE_XDP
	lockless_stack_init(&pool->free_reqs_xdp);
#endif
	mm_ctx_mempool(&pool->mm, sizeof(network_request_t));
	return KNOT_EOK;
}

static int req_pool_reserve(req_pool_t *pool, size_t udp_async_reqs, size_t tcp_async_reqs, size_t xdp_async_reqs)
{
	for (size_t i = 0; i < udp_async_reqs; i++) {
		network_request_t *req = req_allocate_internal_udp(&pool->mm);
		if (req == NULL) {
			return KNOT_ENOMEM;
		}
		lockless_stack_push(&pool->free_reqs_udp, &req->stack_node);
	}

	for (size_t i = 0; i < tcp_async_reqs; i++) {
		network_request_t *req = req_allocate_internal_tcp(&pool->mm);
		if (req == NULL) {
			return KNOT_ENOMEM;
		}
		lockless_stack_push(&pool->free_reqs_tcp, &req->stack_node);
	}

#ifdef ENABLE_XDP
	for (size_t i = 0; i < xdp_async_reqs; i++) {
		network_request_t *req = req_allocate_internal_xdp(&pool->mm);
		if (req == NULL) {
			return KNOT_ENOMEM;
		}
		lockless_stack_push(&pool->free_reqs_xdp, &req->stack_node);
	}
#endif

	return KNOT_EOK;
}

static int req_pool_alloc(req_pool_t *pool, network_request_t **req, network_request_flag_t type)
{
	*req = NULL;
    lockless_stack_node_t *node;
    switch (type) {
        case network_request_flag_udp_buff:
	        node = lockless_stack_pop(&pool->free_reqs_udp);
            break;
        case network_request_flag_tcp_buff:
	        node = lockless_stack_pop(&pool->free_reqs_tcp);
            break;
#ifdef ENABLE_XDP
        case network_request_flag_xdp_buff:
	        node = lockless_stack_pop(&pool->free_reqs_xdp);
            break;
#endif
        default:
            return KNOT_ENOTSUP;
    }

	if (node == NULL) {
		return KNOT_ELIMIT;
	}

	*req = container_of(node, network_request_t, stack_node);
	return KNOT_EOK;
}

static void req_pool_free(req_pool_t *pool, network_request_t *req)
{
	if (req) {
        if (req->flag & network_request_flag_udp_buff) {
            lockless_stack_push(&pool->free_reqs_udp, &req->stack_node);
        } else if (req->flag & network_request_flag_tcp_buff) {
            lockless_stack_push(&pool->free_reqs_tcp, &req->stack_node);
        }
#ifdef ENABLE_XDP
		else if (req->flag & network_request_flag_xdp_buff) {
            lockless_stack_push(&pool->free_reqs_xdp, &req->stack_node);
        }
#endif
	}
}

int network_initialize_async_handling(size_t udp_async_reqs, size_t tcp_async_reqs, size_t xdp_async_reqs)
{
	int ret = req_pool_init(&global_pool);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = req_pool_reserve(&global_pool, udp_async_reqs, tcp_async_reqs, xdp_async_reqs);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return ret;
}
#endif

/*!
 * \brief Executes the async/restartable part of the layer calls.
 *
 * \param network network context.
 * \param req Request to be processed.
 */
static int network_handle_continue(network_context_t *network, network_request_t *req) {
    int ret = KNOT_EOK;

#ifdef ENABLE_ASYNC_QUERY_HANDLING
    if (req->flag & network_request_flag_is_cancelled) {
        /* force state to be in failed state and execute produce. This guarantees module cleanup are performed */
        knot_layer_set_async_state(&req->layer, req->ans, KNOT_STATE_FAIL);
    }
#endif

    /* Process answer. */
    while (knot_layer_active_state(req->layer.state)) {
        knot_layer_produce(&req->layer, req->ans);

#ifdef ENABLE_ASYNC_QUERY_HANDLING
        if (req->flag & network_request_flag_is_cancelled) {
            ret = KNOT_EOF;
            break;
        } else if (req->layer.state != KNOT_STATE_ASYNC) {
#endif
            if (network->response_handler_type == response_handler_type_intermediate) {
                /* Send, if response generation passed and wasn't ignored. */
                if (req->ans->size > 0 && knot_layer_send_state(req->layer.state)) {
                    int sent = network->send_response(network, req);
                    if (sent != req->ans->size) {
                        ret = KNOT_EOF;
                        break;
                    }
                }
            }
#ifdef ENABLE_ASYNC_QUERY_HANDLING
        }
#endif
    }

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	if (req->layer.state != KNOT_STATE_ASYNC) {
#endif
		/* Send response only if finished successfully. */
		struct iovec *out = request_get_iovec(req, TX);
		if (req->layer.state == KNOT_STATE_DONE) {
			out->iov_len = req->ans->size;
		} else {
			out->iov_len = 0;
		}

		/* Reset after processing. */
		knot_layer_finish(&req->layer);

		/* Flush per-query memory (including query and answer packets). */
		mp_flush(req->mm.ctx);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
        req->flag &= ~network_request_flag_is_async;
    } else {
        req->flag |= network_request_flag_is_async;
	}
#endif

    return ret;
}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
/*!
 * \brief Resume the execution of request processing interrupted in produce call.
 *
 * \param network network context.
 * \param req Request to be processed.
 */
static int network_handle_resume(network_context_t *network, network_request_t *req)
{
    assert(req->layer.state == KNOT_STATE_ASYNC);
	req->layer.state = KNOT_STATE_PRODUCE; /* State is ignored by the produce itself. But helps network_handle_continue to start the produce */

	return network_handle_continue(network, req);
}

/*!
 * \brief Callback indicating the async request is complete. NOTE: This WILL BE called on the thread different from that owns the network_ctx.
 * Any step that creates race condition with network_ctx thread has to be mutexed.
 *
 * \param network network context.
 * \param req Request to be processed.
 */
static int network_notify_async_completed(knotd_qdata_params_t *params)
{
	network_request_t *req = params->req;
	uint64_t value = 1;

    /* Using stack inverts the handling of requests. Assuming not all requests go into async mode, this is still acceptable.
     * Consider bringing in DPDK ring buffer or other lockless queue at some point */
	lockless_stack_push(&req->network_ctx->async_completed_reqs, &req->stack_node);

	if (write(req->network_ctx->async_notify_handle, &value, sizeof(value)) == -1) {
		/* Request is queued, we just did not wake up async handler, next might be able to */
		return KNOT_ESYSTEM;
	}
	else {
		return KNOT_EOK;
	}
}

void network_handle_async_completed_queries(network_context_t *network_ctx)
{
    /* cleanup read ctx */
    uint8_t buff[8];
    /* consume the data from the async notification handle */
    int unused = read(network_ctx->async_notify_handle, buff, sizeof(buff));
    UNUSED(unused);

	lockless_stack_node_t *node;
	while ((node = lockless_stack_pop(&network_ctx->async_completed_reqs))) {
		network_request_t *req = container_of(node, network_request_t, stack_node);

        network_handle_resume(network_ctx, req);
		if (! (req->flag & network_request_flag_is_async) ) {
			/* the query is processed, send the result and free up */
            if (!(req->flag & network_request_flag_is_cancelled) && network_ctx->response_handler_type == response_handler_type_final) {
			    network_ctx->send_response(network_ctx, req);
            }

            network_ctx->async_complete(network_ctx, req);
		}
	}
}
#endif

int network_handle(network_context_t *network, network_request_t *req,
					   struct knot_xdp_msg *xdp_msg)
{
	//rq->fd, &rq->addr, &rq->iov[RX], &rq->iov[TX], &rq->params,
	/* Create query processing parameter. */
	knotd_qdata_params_t *params = &req->params;
	params->remote = request_get_address_from(req);
	params->flags = network->query_flags;
	params->socket = req->fd;
	params->server = network->server;
	params->xdp_msg = xdp_msg;
	params->thread_id = network->thread_id;
	params->req = req;
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	req->flag &= ~(network_request_flag_is_async | network_request_flag_is_cancelled);
	req->network_ctx = network;
	params->layer_async_operation_completed = network_notify_async_completed;
#endif
	/* Initialize this requests layer */
	knot_layer_init(&req->layer, &req->mm, network->layer_api);

	/* Start query processing. */
	knot_layer_begin(&req->layer, params);

	/* Create packets. */
	struct iovec *in = request_get_iovec(req, RX);
	struct iovec *out = request_get_iovec(req, TX);
	knot_pkt_t *query = knot_pkt_new(in->iov_base, in->iov_len, req->layer.mm);
	req->ans = knot_pkt_new(out->iov_base, out->iov_len, req->layer.mm);

	/* Input packet. */
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK && query->parsed > 0) { // parsing failed (e.g. 2x OPT)
		query->parsed--; // artificially decreasing "parsed" leads to FORMERR
	}
	knot_layer_consume(&req->layer, query);

    return network_handle_continue(network, req);;
}

int network_context_initialize( network_context_t *network_ctx, server_t *server, int thread_id,
                                knotd_query_flag_t query_flags,
                                response_handler_type_t handler_type,
                                int (*send_response)(struct network_context *ctx,
                                                     struct network_request *req),
                                int (*async_complete)(struct network_context *ctx,
                                                     struct network_request *req))
{
    network_ctx->server = server;
    network_ctx->thread_id = thread_id;
    network_ctx->layer_api = process_query_layer();
    network_ctx->query_flags = query_flags;
    network_ctx->send_response = send_response;
    network_ctx->async_complete = async_complete;
    network_ctx->response_handler_type = handler_type;

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	network_ctx->async_notify_handle = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (network_ctx->async_notify_handle == -1) {
		return KNOT_ESYSTEM;
	}

    lockless_stack_init(&network_ctx->async_completed_reqs);
#endif
    return KNOT_EOK;
}

void network_context_cleanup(network_context_t *network_ctx)
{
#ifdef ENABLE_ASYNC_QUERY_HANDLING
    if (network_ctx->async_notify_handle != -1) {
        close(network_ctx->async_notify_handle);
        network_ctx->async_notify_handle = -1;
    }
#endif
}

network_request_t *network_allocate_request(network_context_t *network, knot_mm_t *mm, network_request_flag_t type)
{
    network_request_t *req = NULL;
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	req_pool_alloc(&global_pool, &req, type);
#else
	if (type == network_request_flag_udp_buff) {
		req = req_allocate_internal_udp(mm);
	} else if (type == network_request_flag_tcp_buff) {
		req = req_allocate_internal_tcp(mm);
#ifdef ENABLE_XDP
	} else if (type == network_request_flag_xdp_buff) {
		req = req_allocate_internal_xdp(mm);
#endif
	} else {
		assert(0);
	}
#endif

    return req;
}

void network_free_request(network_context_t *network, knot_mm_t *mm, network_request_t *req)
{
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	req_pool_free(&global_pool, req);
#else
	req_free_internal(mm, req);
#endif
}