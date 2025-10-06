#pragma once
#include <urcu.h>
#include "knot/server/dns-handler.h"
#ifdef ENABLE_ASYNC_QUERY_HANDLING
#include "knot/include/lstack.h"
#endif
#ifdef KNOT_ENABLE_NUMA
#include <numa.h>
#define KNOT_MAX_NUMA 16
#else
#define KNOT_MAX_NUMA 1
#endif
#include "knot/common/log.h"

/*! \brief Control message to fit IP_PKTINFO or IPv6_RECVPKTINFO. */
typedef union {
	struct cmsghdr cmsg;
	uint8_t buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
} cmsg_pktinfo_t;

/*! \brief DNS request structure allocated for networking layer. */
typedef struct network_dns_request {
#ifdef ENABLE_ASYNC_QUERY_HANDLING
    knotd_lockless_stack_node_t free_list_node;//!< Lockless stack node.
#endif
	dns_handler_request_t dns_req;		//!< dns request part for the handler.
	struct iovec iov[NBUFS];			//!< IOV used in network API for this DNS request.
    size_t msg_namelen_received;        //!< Message name length received.
    size_t msg_controllen_received;     //!< Message control length received.
	cmsg_pktinfo_t pktinfo;				//!< Request's DNS cmsg info.
} network_dns_request_t;

/*! \brief Network request manager that handles allocation/deallocation/reset. */
typedef struct network_dns_request_manager {
	network_dns_request_t* (*allocate_network_request_func)(struct network_dns_request_manager *);        //!< allocate request call.
	void* (*allocate_mem_func)(struct network_dns_request_manager *, size_t);                     //!< allocate memory for request call.
 	void (*restore_network_request_func)(struct network_dns_request_manager *, network_dns_request_t *);  //!< Restore request state after a query is executed to prepare for next request.
	void (*free_network_request_func)(struct network_dns_request_manager *, network_dns_request_t *);     //!< Free previously allocated request.
	void (*free_mem_func)(struct network_dns_request_manager *, void *);                     //!< Free memory allocated in allocate_mem_func.
	void (*delete_req_manager)(struct network_dns_request_manager *);                             //!< Delete the dns request manager.
} network_dns_request_manager_t;

/*!
 * \brief Creates the network manager which allocates the DNS requests using malloc/free.
 * \brief This request manager uses a single knot_mm for all requests allocated. So can't be used for async.
 *
 * \param buffer_size Buffer size to be used for dns request/response.
 * \param memory_size Memory size to be used when handling the DNS request.
 *
 * \retval DNS request manager on success. NULL otherwise.
 */
network_dns_request_manager_t *network_dns_request_manager_basic_create(size_t buffer_size, size_t memory_size);

/*!
 * \brief Creates the network manager which allocates the DNS requests using knot_mm_t.
 * \brief This request manager uses a single knot_mm for all requests allocated. So can't be used for async.
 * \brief Since knot_mm_t does not support free, any request allocated using this manager will be freed when this manager is destroyed.
 *
 * \param buffer_size Buffer size to be used for dns request/response.
 * \param memory_size Memory size to be used when handling the DNS request.
 *
 * \retval DNS request manager on success. NULL otherwise.
 */
network_dns_request_manager_t *network_dns_request_manager_knot_mm_create(size_t buffer_size, size_t memory_size);

#ifdef ENABLE_ASYNC_QUERY_HANDLING
struct shared_dns_request_manager {
	KNOT_ALIGN(16)
    network_dns_request_manager_t *req_mgr;
    int ref_count;
};

typedef KNOT_ATOMIC struct shared_dns_request_manager atomic_shared_dns_request_manager_t;

#define init_shared_req_mgr(shared_req_mgr) { struct shared_dns_request_manager __t = {0}; KNOT_ATOMIC_INIT(shared_req_mgr, __t); }

/*!
 * \brief Creates the network manager which allocates the DNS requests and manages the pool.
 * \brief Any freed request will be added to free pool, and hence memory is not released.
 * \brief Deleting the request manager frees the memory.
 *
 * \param shared_req_mgr Shared request pool manager. Should be initialized with init_shared_req_mgr.
 * \param buffer_size Buffer size to be used for dns request/response.
 * \param memory_size Memory size to be used when handling the DNS request.
 * \param pool_size Number of requests to maintain in the pool initially.
 *
 * \retval DNS request manager on success. NULL otherwise.
 */
network_dns_request_manager_t *network_dns_request_pool_manager_create(atomic_shared_dns_request_manager_t *shared_req_mgr, size_t buffer_size, size_t memory_size, size_t pool_size);
#endif
