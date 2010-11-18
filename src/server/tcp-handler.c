#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "name-server.h"
#include "tcp-handler.h"
#include "stat.h"

/*
 * TCP connection pool.
 */
typedef struct tcp_pool_t {
    int ep_fd;                     /* epoll socket */
    int ep_ecount;                 /* epoll events counter */
    int ep_esize;                  /* epoll events backing store size */
    struct epoll_event *ep_events; /* epoll events backing store */
    ns_nameserver *ns;             /* reference to name server */
    pthread_mutex_t mx;            /* pool synchronisation */
    iohandler_t*  handler;         /* master I/O handler */
    stat_t *stat;                  /* statistics gatherer */
} tcp_pool_t;

/* Forward decls. */
static int tcp_pool (dthread_t* thread);
static tcp_pool_t* tcp_pool_new (iohandler_t *handler);
static void tcp_pool_del (tcp_pool_t **pool);
static int tcp_pool_add (int epfd, int socket, uint32_t events);
static int tcp_pool_remove (int epfd, int socket);
static int tcp_pool_reserve (tcp_pool_t *pool, uint size);

/* Locking. */
static inline int tcp_pool_lock (tcp_pool_t *pool)
{
    return pthread_mutex_lock(&pool->mx);
}
static inline int tcp_pool_unlock (tcp_pool_t *pool)
{
    return pthread_mutex_unlock(&pool->mx);
}

int tcp_master (dthread_t* thread)
{
    dt_unit_t *unit = thread->unit;
    iohandler_t* handler = (iohandler_t *)thread->data;
    int master_sock = handler->fd;
    debug_dt("dthreads: [%p] is TCP master, state: %d\n", thread, thread->state);

    /*
     * Create N pools of TCP connections.
     * Each pool is responsible for its own
     * set of clients.
     *
     * \note Pool instance is deallocated by their assigned thread.
     */
    int pool_id = -1;

    // Accept clients
    debug_net("tcp: running 1 master with %d pools\n", unit->size - 1);
    for (;;) {

        // Cancellation point
        if (dt_is_cancelled(thread))
            return -1;

        // Accept on master socket
        int incoming = accept(master_sock, 0, 0);

        // Register to worker
        if (incoming < 0) {
            if(errno != EINTR) {
                log_error("tcp_master: cannot accept incoming "
                          "connection (errno %d): %s.\n",
                          errno, strerror(errno));
            }
        } else {

            // Select next pool (Round-Robin)
            dt_unit_lock(unit);
            int pool_count = unit->size - 1;
            pool_id = get_next_rr(pool_id, pool_count);
            dthread_t *t = unit->threads[pool_id + 1];

            // Allocate new pool if needed
            if (t->run != &tcp_pool) {
                dt_repurpose(t, &tcp_pool, tcp_pool_new(handler));
                debug_dt("dthreads: [%p] repurposed as TCP pool\n", t);
            }

            // Add incoming socket to selected pool
            tcp_pool_t* pool = (tcp_pool_t *)t->_adata;
            tcp_pool_lock(pool);
            debug_net("tcp_master: accept: assigned socket %d to pool #%d\n",
                      incoming, pool_id);

            if (tcp_pool_add(pool->ep_fd, incoming, EPOLLIN) == 0)
                ++pool->ep_ecount;

            // Activate pool
            dt_activate(t);
            tcp_pool_unlock(pool);
            dt_unit_unlock(unit);
        }
    }


   // Stop whole unit
   debug_net("tcp: stopping (%d master, %d pools)\n", 1, unit->size - 1);
   return 0;
}

static inline void tcp_answer (int fd,
                               uint8_t* src,
                               int inbuf_sz,
                               uint8_t* dest,
                               int outbuf_sz,
                               tcp_pool_t* pool)
{
    // Receive size
    unsigned short pktsize = 0;
    int n = socket_recv(fd, &pktsize, sizeof(unsigned short), 0);
    pktsize = ntohs(pktsize);
    debug_net("tcp: incoming packet size on %d: %u buffer size: %u\n", fd, (unsigned) pktsize, (unsigned) inbuf_sz);

    // Receive payload
    if (n > 0 && pktsize > 0) {
        if (pktsize <= inbuf_sz) {
            n = socket_recv(fd, src, pktsize, 0); /// \todo Check buffer overflow.
        } else {
            n = 0;
        }
    }

    //! \todo Real address;
    struct sockaddr_in faddr;
    faddr.sin_family = AF_INET;
    faddr.sin_port = htons(0);
    faddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    stat_get_first(pool->stat, &faddr); //faddr has to be read immediately.

    // Check read result
    if (n > 0) {

        // Send answer
        size_t answer_size = outbuf_sz;
        int res = ns_answer_request(pool->ns, src, n, dest + sizeof(short),
                                    &answer_size);
        debug_net("tcp: answer wire format (size %u, result %d).\n",
                  (unsigned) answer_size, res);

        if (res >= 0) {

            /*! Cork, \see http://vger.kernel.org/~acme/unbehaved.txt */
            int cork = 1;
            setsockopt(fd, SOL_TCP, TCP_CORK, &cork, sizeof(cork));

            // Copy header
            ((unsigned short*) dest)[0] = htons(answer_size);
            int sent = -1;
            while (sent < 0) {
                sent = socket_send(fd, dest, answer_size + sizeof(short), 0);
            }

            // Uncork
            cork = 0;
            setsockopt(fd, SOL_TCP, TCP_CORK, &cork, sizeof(cork));
            stat_get_second(pool->stat);
            debug_net("tcp: sent answer to %d\n", fd);
        }
    }
}

static int tcp_pool (dthread_t* thread)
{
    /*
     * \todo: Make sure stack size is big enough.
     *        Although this is much cheaper,
     *        16kB worth of buffers *may* pose a problem.
     */
    tcp_pool_t* pool = (tcp_pool_t *)thread->data;
    uint8_t buf[SOCKET_MTU_SZ];
    uint8_t answer[SOCKET_MTU_SZ];

    int nfds = 0;
    debug_net("tcp: entered pool #%d\n", pool->ep_fd);

    // Poll new data from clients
    while (pool->ep_ecount > 0) {

        // Poll sockets
        tcp_pool_reserve(pool, pool->ep_ecount * 2);
        nfds = epoll_wait(pool->ep_fd, pool->ep_events, pool->ep_esize, -1);

        // Cancellation point
        if(dt_is_cancelled(thread)) {
            debug_net("tcp: pool #%d thread is cancelled\n", pool->ep_fd);
            break;
        }

        // Evaluate
        debug_net("tcp: pool #%d, %d events (%d sockets).\n",
                  pool->ep_fd, nfds, pool->ep_ecount);

        int fd = 0;
        for(int i = 0; i < nfds; ++i) {

            // Get client fd
            fd = pool->ep_events[i].data.fd;

            debug_net("tcp: pool #%d processing fd=%d.\n",
                      pool->ep_fd, fd);
            tcp_answer(fd, buf, SOCKET_MTU_SZ,
                       answer,  SOCKET_MTU_SZ,
                       pool);
            debug_net("tcp: pool #%d finished fd=%d (remaining %d).\n",
                      pool->ep_fd, fd, pool->ep_ecount);

            // Disconnect
            debug_net("tcp: disconnected: %d\n", fd);
            tcp_pool_lock(pool);
            tcp_pool_remove(pool->ep_fd, fd);
            --pool->ep_ecount;
            socket_close(fd);
            tcp_pool_unlock(pool);
        }
    }

    // If exiting, cleanup
    if(pool->handler->state == Idle) {
        debug_net("tcp: pool #%d is finishing\n", pool->ep_fd);
        tcp_pool_del(&pool);
        return 0;
    }

    debug_net("tcp: pool #%d going to idle.\n", pool->ep_fd);
    return 0;
}

static tcp_pool_t* tcp_pool_new (iohandler_t *handler)
{
   // Alloc
   tcp_pool_t *pool = malloc(sizeof(tcp_pool_t));
   if (pool == 0)
      return 0;

   // Initialize
   memset(pool, 0, sizeof(tcp_pool_t));
   pool->handler = handler;
   pool->ns = handler->server->nameserver;
   pool->ep_ecount = 0;
   pool->ep_esize = 0;

   // Create epoll fd
   pool->ep_fd = epoll_create(1);
   if (pool->ep_fd == -1) {
      free(pool);
      return 0;
   }

   // Alloc backing-store
   if (tcp_pool_reserve(pool, 1) != 0) {
      close(pool->ep_fd);
      free(pool);
      return 0;
   }

   // Initialize synchronisation
   if (pthread_mutex_init(&pool->mx, 0) != 0) {
      close(pool->ep_fd);
      free(pool->ep_events);
      free(pool);
      return 0;
   }

   // Create stat gatherer
   STAT_INIT(pool->stat);
   stat_set_protocol(pool->stat, stat_TCP);

   return pool;
}

static void tcp_pool_del (tcp_pool_t **pool)
{
    // Check
    if(pool == 0)
        return;

    // Close epoll fd
    close((*pool)->ep_fd);

    // Free backing store
    if((*pool)->ep_events != 0)
        free((*pool)->ep_events);

    // Destroy synchronisation
    pthread_mutex_destroy(&(*pool)->mx);

    // Delete stat
    stat_free((*pool)->stat);

    // Free
    free((*pool));
    *pool = 0;
}

static int tcp_pool_add (int epfd, int socket, uint32_t events)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));

    // All polled events should use non-blocking mode.
    int old_flag = fcntl(socket, F_GETFL, 0);
    if (fcntl(socket, F_SETFL, old_flag | O_NONBLOCK) == -1) {
        log_error("error setting non-blocking mode on the socket.\n");
        return -1;
    }

    // Register to epoll
    ev.data.fd = socket;
    ev.events = events;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, socket, &ev) != 0) {
        log_error("failed to add socket to event set (errno %d): %s.\n", errno, strerror(errno));
        return -1;
    }

    return 0;
}

static int tcp_pool_remove (int epfd, int socket)
{
    // Compatibility with kernels < 2.6.9, require non-0 ptr.
    struct epoll_event ev;

    // find socket ptr
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, socket, &ev) != 0) {
        perror ("epoll_ctl");
        return -1;
    }

    return 0;
}

static int tcp_pool_reserve (tcp_pool_t *pool, uint size)
{
   if (pool->ep_esize >= size)
      return 0;

   // Alloc new events
   struct epoll_event *new_events = malloc(size * sizeof(struct epoll_event));
   if (new_events == 0)
      return -1;

   // Free and replace old events backing-store
   if (pool->ep_events != 0)
      free(pool->ep_events);

   pool->ep_esize = size;
   pool->ep_events = new_events;
   return 0;
}

