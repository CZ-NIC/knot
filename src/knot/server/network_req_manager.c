#include "knot/server/network_req_manager.h"
#include "contrib/memcheck.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Watomic-alignment"

/*! \brief Basic network request manager data. */
typedef struct network_dns_request_manager_basic {
	network_dns_request_manager_t base;         //!< Base network request manager function pointers.

	size_t buffer_size;                         //!< Buffer size used in rx/tx while allocating the DNS request.
	knot_mm_t query_processing_mm;              //!< Query processing mm for the requests allocated. There is only one per network manager and hence can't support async requests.
} network_dns_request_manager_basic_t;

/*!
 * \brief Free network request allocated using free.
 *
 * \param mgr Network request manager used for allocating req.
 * \param req Request to be freed.
 */
static void network_dns_request_manager_basic_free_req(network_dns_request_manager_t *mgr, network_dns_request_t *req) {
	if (req) {
		for (unsigned i = 0; i < NBUFS; ++i) {
			free(req->iov[i].iov_base);
		}
		free(req);
	}
}

/*!
 * \brief Allocate memory for data associated with request.
 *
 * \param mgr Network request manager to be used.
 * \param size size of memory to allocate.
 *
 * \retval Memory allocated. NULL if failed.
 */
static void* network_dns_request_manager_basic_allocate_mem(network_dns_request_manager_t *mgr, size_t size) {
	return malloc(size);
}

/*!
 * \brief Free memory for data associated with request previously allocated using allocate_mem_func.
 *
 * \param mgr Network request manager to be used.
 * \param mem Memory previously allocated using allocate_mem_func.
 */
void network_dns_request_manager_basic_free_mem(struct network_dns_request_manager *mgr, void *mem) {
	return free(mem);
}

/*!
 * \brief Allocate request.
 *
 * \param mgr Network request manager to be used.
 *
 * \retval Request allocaed, NULL if failed.
 */
static network_dns_request_t* network_dns_request_manager_basic_allocate_req(network_dns_request_manager_t *mgr) {
	network_dns_request_manager_basic_t *this = caa_container_of(mgr, network_dns_request_manager_basic_t, base);
	network_dns_request_t *req = NULL;
	req = calloc(1, sizeof(network_dns_request_t));
	if (req == NULL) {
		return NULL;
	}

	for (unsigned i = 0; i < NBUFS; ++i) {
		req->iov[i].iov_base = malloc(this->buffer_size);
		if (req->iov[i].iov_base == NULL) {
			network_dns_request_manager_basic_free_req(&this->base, req);
			return NULL;
		}
		req->iov[i].iov_len = this->buffer_size;
	}

	req->dns_req.req_data.rx = &req->iov[RX];
	req->dns_req.req_data.tx = &req->iov[TX];
	req->dns_req.req_data.mm = &this->query_processing_mm;
	req->dns_req.req_data.xdp_msg = NULL;

	return req;
}

/*!
 * \brief Reset request to handle new request.
 *
 * \param mgr Network request manager to be used.
 * \param req Request to be reset.
 */
static void network_dns_request_manager_basic_reset_request(network_dns_request_manager_t *mgr, network_dns_request_t *req) {
	network_dns_request_manager_basic_t *this = caa_container_of(mgr, network_dns_request_manager_basic_t, base);
	req->iov[RX].iov_len = this->buffer_size;
	req->iov[TX].iov_len = this->buffer_size;

	// Reusing buffer, make buffer not initialized to avoid previous request data considered valid for new request.
	VALGRIND_MAKE_MEM_UNDEFINED(req->iov[RX].iov_base, this->buffer_size);
	VALGRIND_MAKE_MEM_UNDEFINED(req->iov[TX].iov_base, this->buffer_size);

	dns_handler_request_clear_handler_data(req->dns_req);
}

/*!
 * \brief Delete the request manager.
 *
 * \param mgr Network request manager to be deleted.
 */
static void network_dns_request_manager_basic_delete(network_dns_request_manager_t *mgr) {
	network_dns_request_manager_basic_t *this = caa_container_of(mgr, network_dns_request_manager_basic_t, base);
	mp_delete(this->query_processing_mm.ctx);
	memset(this, 0, sizeof(*this));
	free(this);
}

/*! \brief Knot_mm based network request manager data. */
typedef struct network_dns_request_manager_knot_mm {
	network_dns_request_manager_t base;         //!< Base network request manager function pointers.

	size_t buffer_size;                         //!< Buffer size used in rx/tx while allocating the DNS request.
	knot_mm_t req_allocation_mm;                //!< mm used for request allocation only. All memory for request are freed when request manager is destroyed.
	knot_mm_t query_processing_mm;              //!< Query processing mm for the requests allocated. There is only one per network manager and hence can't support async requests.
} network_dns_request_manager_knot_mm_t;

/*!
 * \brief Free network request allocated using knot_mm.
 *
 * \param mgr Network request manager used for allocating req.
 * \param req Request to be freed.
 */
static void network_dns_request_manager_knot_mm_free_req(network_dns_request_manager_t *mgr, network_dns_request_t *req) {
	_unused_ network_dns_request_manager_knot_mm_t *this = caa_container_of(mgr, network_dns_request_manager_knot_mm_t, base);

	// individual request can't be freed, but mark as not accessible
	VALGRIND_MAKE_MEM_NOACCESS(req->iov[RX].iov_base, this->buffer_size);
	VALGRIND_MAKE_MEM_NOACCESS(req->iov[TX].iov_base, this->buffer_size);
	VALGRIND_MAKE_MEM_NOACCESS(req, sizeof(network_dns_request_t));
}

/*!
 * \brief Allocate request.
 *
 * \param mgr Network request manager to be used.
 *
 * \retval Request allocaed, NULL if failed.
 */
static network_dns_request_t* network_dns_request_manager_knot_mm_allocate_req(network_dns_request_manager_t *mgr) {
	network_dns_request_manager_knot_mm_t *this = caa_container_of(mgr, network_dns_request_manager_knot_mm_t, base);
	network_dns_request_t *req = NULL;
	req = mm_calloc(&this->req_allocation_mm, 1, sizeof(network_dns_request_t));
	if (req == NULL) {
		return NULL;
	}

	for (unsigned i = 0; i < NBUFS; ++i) {
		req->iov[i].iov_base = mm_alloc(&this->req_allocation_mm, this->buffer_size);
		if (req->iov[i].iov_base == NULL) {
			network_dns_request_manager_knot_mm_free_req(&this->base, req);
			return NULL;
		}
		req->iov[i].iov_len = this->buffer_size;
	}

	req->dns_req.req_data.rx = &req->iov[RX];
	req->dns_req.req_data.tx = &req->iov[TX];
	req->dns_req.req_data.mm = &this->query_processing_mm;
	req->dns_req.req_data.xdp_msg = NULL;

	return req;
}

/*!
 * \brief Allocate memory for data associated with request.
 *
 * \param mgr Network request manager to be used.
 * \param size size of memory to allocate.
 *
 * \retval Memory allocated. NULL if failed.
 */
static void* network_dns_request_manager_knot_mm_allocate_mem(network_dns_request_manager_t *mgr, size_t size) {
	network_dns_request_manager_knot_mm_t *this = caa_container_of(mgr, network_dns_request_manager_knot_mm_t, base);
	return mm_alloc(&this->req_allocation_mm, size);
}

/*!
 * \brief Free memory for data associated with request previously allocated using allocate_mem_func.
 *
 * \param mgr Network request manager to be used.
 * \param mem Memory previously allocated using allocate_mem_func.
 */
void network_dns_request_manager_knot_mm_free_mem(struct network_dns_request_manager *mgr, void *mem) {
	// Individual allocation cannot be freed when done from knot_mm.
}

/*!
 * \brief Reset request to handle new request.
 *
 * \param mgr Network request manager to be used.
 * \param req Request to be reset.
 */
static void network_dns_request_manager_knot_mm_reset_request(network_dns_request_manager_t *mgr, network_dns_request_t *req) {
	network_dns_request_manager_knot_mm_t *this = caa_container_of(mgr, network_dns_request_manager_knot_mm_t, base);
	req->iov[RX].iov_len = this->buffer_size;
	req->iov[TX].iov_len = this->buffer_size;

	// Reusing buffer, make buffer not initialized to avoid previous request data considered valid for new request.
	VALGRIND_MAKE_MEM_UNDEFINED(req->iov[RX].iov_base, this->buffer_size);
	VALGRIND_MAKE_MEM_UNDEFINED(req->iov[TX].iov_base, this->buffer_size);

	dns_handler_request_clear_handler_data(req->dns_req);
}

/*!
 * \brief Delete the request manager.
 *
 * \param mgr Network request manager to be deleted.
 */
static void network_dns_request_manager_knot_mm_delete(network_dns_request_manager_t *mgr) {
	network_dns_request_manager_knot_mm_t *this = caa_container_of(mgr, network_dns_request_manager_knot_mm_t, base);
	mp_delete(this->req_allocation_mm.ctx);
	mp_delete(this->query_processing_mm.ctx);
	memset(this, 0, sizeof(*this));
	free(this);
}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
#include "knot/include/lstack.h"

/*! \brief Pooled network request manager data. */
typedef struct network_dns_request_pool_manager {
	network_dns_request_manager_t base;         //!< Base network request manager function pointers.

	size_t buffer_size;                         //!< Buffer size used in rx/tx while allocating the DNS request.
	size_t memory_size;                         //!< memory size to use for processing DNS request.
	knot_mm_t req_allocation_mm;                //!< mm used for request allocation only. All memory for request are freed when request manager is destroyed.
	knotd_lockless_stack_t free_pool;           //!< Stack of freed request pool.
	atomic_shared_dns_request_manager_t *shared_req_mgr; //!< Shared resource manager.
} network_dns_request_pool_manager_t;

/*!
 * \brief Free network request allocated by adding to free queue
 *
 * \param mgr Network request manager used for allocating req.
 * \param req Request to be freed.
 */
static void network_dns_request_pool_manager_free_req(network_dns_request_manager_t *mgr, network_dns_request_t *req) {
	network_dns_request_pool_manager_t *this = caa_container_of(mgr, network_dns_request_pool_manager_t, base);
	assert(req->free_list_node.next == NULL);

	// Reset request for reuse and put it in the pool
	mgr->restore_network_request_func(mgr, req);

	// Make the request memory inaccessible
	VALGRIND_MAKE_MEM_NOACCESS(req->iov[RX].iov_base, this->buffer_size);
	VALGRIND_MAKE_MEM_NOACCESS(req->iov[TX].iov_base, this->buffer_size);
	VALGRIND_MAKE_MEM_NOACCESS(req, sizeof(network_dns_request_t));
	// except free_list_node which is needed for maintaining free list.
	VALGRIND_MAKE_MEM_UNDEFINED(&req->free_list_node, sizeof(req->free_list_node));

	// Put the request in free pool
	knotd_lockless_stack_push(&this->free_pool, &req->free_list_node);
}

/*!
 * \brief Allocate request from pool.
 *
 * \param mgr Network request manager to be used.
 *
 * \retval Request allocaed, NULL if failed.
 */
static network_dns_request_t* network_dns_request_pool_manager_allocate_req(network_dns_request_manager_t *mgr) {
	network_dns_request_pool_manager_t *this = caa_container_of(mgr, network_dns_request_pool_manager_t, base);
	knotd_lockless_stack_node_t *free_node = knotd_lockless_stack_pop(&this->free_pool);
	if (free_node == NULL) {
		return NULL;
	}

	network_dns_request_t* req = caa_container_of(free_node, network_dns_request_t, free_list_node);
	// Make everything in req available to read. Buffers available but not initialized.
	// Request was initialized as part of creation, but we intentionally made it inaccessible when it is in free list.
	VALGRIND_MAKE_MEM_DEFINED(req, sizeof(network_dns_request_t));
	VALGRIND_MAKE_MEM_UNDEFINED(req->iov[RX].iov_base, this->buffer_size);
	VALGRIND_MAKE_MEM_UNDEFINED(req->iov[TX].iov_base, this->buffer_size);
	return req;
}

/*!
 * \brief Allocate request.
 *
 * \param this Network request manager to be used.
 *
 * \retval Request allocaed, NULL if failed.
 */
static network_dns_request_t* network_dns_request_pool_manager_real_allocate(network_dns_request_pool_manager_t *this) {
	network_dns_request_t *req = NULL;
	req = mm_calloc(&this->req_allocation_mm, 1, sizeof(network_dns_request_t));
	if (req == NULL) {
		return NULL;
	}

	for (unsigned i = 0; i < NBUFS; ++i) {
		req->iov[i].iov_base = mm_alloc(&this->req_allocation_mm, this->buffer_size);
		if (req->iov[i].iov_base == NULL) {
			network_dns_request_pool_manager_free_req(&this->base, req);
			return NULL;
		}
		req->iov[i].iov_len = this->buffer_size;
	}

	req->dns_req.req_data.rx = &req->iov[RX];
	req->dns_req.req_data.tx = &req->iov[TX];
	req->dns_req.req_data.mm = mm_calloc(&this->req_allocation_mm, 1, sizeof(knot_mm_t));
	if (req->dns_req.req_data.mm == NULL) {
		return NULL;
	}
	mm_ctx_mempool(req->dns_req.req_data.mm, this->memory_size);
	req->dns_req.req_data.xdp_msg = NULL;

	return req;
}

/*!
 * \brief Allocate memory for data associated with request.
 *
 * \param mgr Network request manager to be used.
 * \param size size of memory to allocate.
 *
 * \retval Memory allocated. NULL if failed.
 */
static void* network_dns_request_pool_manager_allocate_mem(network_dns_request_manager_t *mgr, size_t size) {
	// Don't allocate from knot_mm. It will lead to race condition as pool manager is shared by threads.
	// Only DNS requests are preallocated to avoid race condition. Individual memory should be allocated using malloc,
	return malloc(size);
}

/*!
 * \brief Free memory for data associated with request previously allocated using allocate_mem_func.
 *
 * \param mgr Network request manager to be used.
 * \param mem Memory previously allocated using allocate_mem_func.
 */
void network_dns_request_pool_manager_free_mem(struct network_dns_request_manager *mgr, void *mem) {
	free(mem);
}

/*!
 * \brief Reset request to handle new request.
 *
 * \param mgr Network request manager to be used.
 * \param req Request to be reset.
 */
static void network_dns_request_pool_manager_reset_request(network_dns_request_manager_t *mgr, network_dns_request_t *req) {
	network_dns_request_pool_manager_t *this = caa_container_of(mgr, network_dns_request_pool_manager_t, base);
	req->iov[RX].iov_len = this->buffer_size;
	req->iov[TX].iov_len = this->buffer_size;

	// Reusing buffer, make buffer not initialized to avoid previous request data considered valid for new request.
	VALGRIND_MAKE_MEM_UNDEFINED(req->iov[RX].iov_base, this->buffer_size);
	VALGRIND_MAKE_MEM_UNDEFINED(req->iov[TX].iov_base, this->buffer_size);

	dns_handler_request_clear_handler_data(req->dns_req);
}

/*!
 * \brief Delete the request manager.
 *
 * \param mgr Network request manager to be deleted.
 */
static void network_dns_request_pool_manager_delete(network_dns_request_manager_t *mgr) {
	network_dns_request_pool_manager_t *this = caa_container_of(mgr, network_dns_request_pool_manager_t, base);
	struct shared_dns_request_manager expect, new_value = {0};
	do {
		KNOT_ATOMIC_GET(this->shared_req_mgr, expect);
		new_value.ref_count = expect.ref_count - 1;
		if (expect.ref_count == 1) {
			// last reference
			new_value.req_mgr = NULL;
		} else {
			new_value.req_mgr = expect.req_mgr;
		}
	} while (!KNOT_ATOMIC_COMPARE_EXCHANGE_WEAK(this->shared_req_mgr, expect, new_value));

	if ( new_value.ref_count == 0) {
		// free the request manager
		mp_delete(this->req_allocation_mm.ctx);
		knotd_lockless_stack_cleanup(&this->free_pool);
		memset(this, 0, sizeof(*this));
		free(this);
	}
}
#endif

/*!
 * \brief Creates the network manager which allocates the DNS requests using malloc/free.
 * \brief This request manager uses a single knot_mm for all requests allocated. So can't be used for async.
 *
 * \param buffer_size Buffer size to be used for dns request/response.
 * \param memory_size Memory size to be used when handling the DNS request.
 *
 * \retval DNS request manager on success. NULL otherwise.
 */
network_dns_request_manager_t *network_dns_request_manager_basic_create(size_t buffer_size, size_t memory_size) {
	network_dns_request_manager_basic_t *this = calloc(1, sizeof(*this));
	if (this == NULL) {
		return NULL;
	}

	this->base.allocate_network_request_func = network_dns_request_manager_basic_allocate_req;
	this->base.allocate_mem_func = network_dns_request_manager_basic_allocate_mem;
	this->base.restore_network_request_func = network_dns_request_manager_basic_reset_request;
	this->base.free_network_request_func = network_dns_request_manager_basic_free_req;
	this->base.free_mem_func = network_dns_request_manager_basic_free_mem;
	this->base.delete_req_manager = network_dns_request_manager_basic_delete;

	this->buffer_size = buffer_size;
	mm_ctx_mempool(&this->query_processing_mm, memory_size);

	return &this->base;
}

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
network_dns_request_manager_t *network_dns_request_manager_knot_mm_create(size_t buffer_size, size_t memory_size) {
	network_dns_request_manager_knot_mm_t *this = calloc(1, sizeof(*this));
	if (this == NULL) {
		return NULL;
	}

	this->base.allocate_network_request_func = network_dns_request_manager_knot_mm_allocate_req;
	this->base.allocate_mem_func = network_dns_request_manager_knot_mm_allocate_mem;
	this->base.restore_network_request_func = network_dns_request_manager_knot_mm_reset_request;
	this->base.free_network_request_func = network_dns_request_manager_knot_mm_free_req;
	this->base.free_mem_func = network_dns_request_manager_knot_mm_free_mem;
	this->base.delete_req_manager = network_dns_request_manager_knot_mm_delete;

	this->buffer_size = buffer_size;
	mm_ctx_mempool(&this->req_allocation_mm, buffer_size);
	mm_ctx_mempool(&this->query_processing_mm, memory_size);

	return &this->base;
}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
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
network_dns_request_manager_t* network_dns_request_pool_manager_create(atomic_shared_dns_request_manager_t *shared_req_mgr, size_t buffer_size, size_t memory_size, size_t pool_size) {
	struct shared_dns_request_manager expect, new_value = {0};
	void *is_being_initialized_value = (void*)shared_req_mgr;

	// atomically initialize the structure. On input created_pool points to NULL.
	// If shared_req_mgr points to NULL, make it point to itself and proceed to creation.
	// If shared_req_mgr points to itself, wait until it completes.
	do {
		KNOT_ATOMIC_GET(shared_req_mgr, expect);
		if (expect.req_mgr == NULL) {
			// not initialized. Try to take a lock.
			new_value.req_mgr = is_being_initialized_value;
			new_value.ref_count = 0;
			if (KNOT_ATOMIC_COMPARE_EXCHANGE_WEAK(shared_req_mgr, expect, new_value)) {
				// we got the lock to create it.
				break;
			}
		}
		else if (expect.req_mgr == is_being_initialized_value) {
			// still being initialized
			struct timespec ten_ms = { 0, 10000000};
			nanosleep(&ten_ms, &ten_ms);
		}
		else {
			new_value.req_mgr = expect.req_mgr;
			new_value.ref_count = expect.ref_count + 1;
			if (KNOT_ATOMIC_COMPARE_EXCHANGE_WEAK(shared_req_mgr, expect, new_value)) {
				// we got the reference to the mgr
				return expect.req_mgr;
			}
		}
	}
	while (true);

	new_value.req_mgr = NULL;
	new_value.ref_count = 0;
	network_dns_request_pool_manager_t *this = calloc(1, sizeof(*this));
	if (this == NULL) {
		KNOT_ATOMIC_INIT(*shared_req_mgr, new_value);
		return NULL;
	}

	this->base.allocate_network_request_func = network_dns_request_pool_manager_allocate_req;
	this->base.allocate_mem_func = network_dns_request_pool_manager_allocate_mem;
	this->base.restore_network_request_func = network_dns_request_pool_manager_reset_request;
	this->base.free_network_request_func = network_dns_request_pool_manager_free_req;
	this->base.free_mem_func = network_dns_request_pool_manager_free_mem;
	this->base.delete_req_manager = network_dns_request_pool_manager_delete;

	this->shared_req_mgr = shared_req_mgr;
	this->buffer_size = buffer_size;
	this->memory_size = memory_size;

	if (knotd_lockless_stack_init(&this->free_pool) != 0) {
		free(this);
		KNOT_ATOMIC_INIT(*shared_req_mgr, new_value);
		return NULL;
	}

	mm_ctx_mempool(&this->req_allocation_mm, buffer_size);

	for (size_t i = 0; i < pool_size; i++) {
		network_dns_request_t* req = network_dns_request_pool_manager_real_allocate(this);
		if (req == NULL) {
			mp_delete(this->req_allocation_mm.ctx);
			free(this);
			KNOT_ATOMIC_INIT(*shared_req_mgr, new_value);
			return NULL;
		}
		knotd_lockless_stack_push(&this->free_pool, &req->free_list_node);
	}

	new_value.req_mgr = &this->base;
	new_value.ref_count = 1;
	KNOT_ATOMIC_INIT(*shared_req_mgr, new_value);
	return new_value.req_mgr;
}
#endif
