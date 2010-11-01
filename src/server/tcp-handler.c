#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include "tcp-handler.h"

/** Event descriptor.
  */
typedef struct tcp_worker_t {
    int epfd;
    int events_count;
    int events_size;
    struct epoll_event* events;
    cute_server* server;
    pthread_mutex_t mutex;
    pthread_cond_t wakeup;
} tcp_worker_t;

/*! \todo Make generic in socket.h interface. */
static int tcp_reserve_bs(tcp_worker_t* worker, uint size)
{
   if(worker->events_size >= size)
      return 0;

   struct epoll_event* new_events = malloc(size * sizeof(struct epoll_event));
   if(new_events == NULL)
      return -1;

   if(worker->events != NULL)
      free(worker->events);

   worker->events = new_events;
   return 0;
}

tcp_worker_t* tcp_worker_create(cute_server* server)
{
   // Alloc
   tcp_worker_t* worker = malloc(sizeof(tcp_worker_t));
   if(worker == NULL)
      return NULL;

   // Create epoll
   worker->epfd = socket_poll_create(1);
   if (worker->epfd == -1) {
      free(worker);
      return NULL;
   }

   // Alloc backing store
   worker->events = malloc(1 * sizeof(struct epoll_event));
   if (worker->events == NULL) {
      close(worker->epfd);
      free(worker);
      return NULL;
   }

   // Initialize synchronisation
   if (pthread_mutex_init(&worker->mutex, NULL) != 0) {
      close(worker->epfd);
      free(worker->events);
      free(worker);
      return NULL;
   }

   if (pthread_cond_init(&worker->wakeup, NULL) != 0) {
      close(worker->epfd);
      free(worker->events);
      pthread_mutex_destroy(&worker->mutex);
      free(worker);
      return NULL;
   }

   // Initialize worker data
   worker->server = server;
   worker->events_count = 0;
   worker->events_size = 1;
   return worker;
}

void tcp_worker_delete(tcp_worker_t** worker)
{
    // Close poll fd
    close((*worker)->epfd);

    // Free backing store
    if((*worker)->events != NULL)
        free((*worker)->events);

    // Destroy synchronisation
    pthread_mutex_destroy(&(*worker)->mutex);
    pthread_cond_destroy(&(*worker)->wakeup);

    // Free worker
    free((*worker));
    *worker = NULL;
}

void *tcp_master( void *obj )
{
   iohandler_t* worker = (iohandler_t*) obj;
   int sock = worker->fd;

   // Create pool of TCP workers
   // Each worker is responsible for its own set of clients ("bucket")
   int worker_id = 0;
   int worker_count = cute_estimate_threads() - 1; // estimate_threads() - master thread
   if(worker_count < 1) {
      worker_count = 1;
   }

   dpt_dispatcher* tcp_threads = dpt_create(worker_count, &tcp_worker, NULL);
   tcp_worker_t** tcp_workers = malloc(worker_count * sizeof(tcp_worker_t*));
   for(int i = 0; i < worker_count; ++i) {
      tcp_workers[i] = tcp_worker_create(worker->server);
      tcp_threads->routine_obj[i] = tcp_workers[i];
   }

   // Run TCP workers
   debug_net("tcp_master: running %d worker threads\n", worker_count);
   if(dpt_start(tcp_threads) < 0) {
      worker->state = Idle;
   }

   // Accept clients
   while (worker->state & Running) {

      // Accept on master socket
      int incoming = accept(sock, NULL, NULL);

      // Register to worker
      if(incoming < 0) {
         if(errno != EINTR) {
            log_error("tcp_master: cannot accept incoming connection (errno %d): %s.\n", errno, strerror(errno));
         }
      }
      else {

         // Register incoming socket
         tcp_worker_t* tcp_worker = tcp_workers[worker_id];
         pthread_mutex_lock(&tcp_worker->mutex);
         debug_net("tcp_master: accept: assigned socket %d to worker #%d\n", incoming, worker_id);
         if(socket_poll_add(tcp_worker->epfd, incoming, EPOLLIN) == 0)
            ++tcp_worker->events_count;

         // Run worker
         pthread_cond_signal(&tcp_worker->wakeup);
         pthread_mutex_unlock(&tcp_worker->mutex);

         // Select next worker (Round-Robin)
         worker_id = get_next_rr(worker_id, worker_count);
      }
   }


    // Wake up all workers
    debug_net("tcp_master: stopping %d worker threads\n", worker_count);
    int last_wrkr = worker_id;
    for(;;) {

        tcp_worker_t* tcp_worker = tcp_workers[worker_id];
        pthread_mutex_lock(&tcp_worker->mutex);
        tcp_worker->events_count = -1; // Shut down worker
        pthread_cond_signal(&tcp_worker->wakeup);
        pthread_mutex_unlock(&tcp_worker->mutex);
        worker_id = get_next_rr(worker_id, worker_count);

        // Finish with the starting worker
        if(worker_id == last_wrkr)
            break;
    }

    // Wait for TCP workers
    dpt_wait(tcp_threads);
    dpt_destroy(&tcp_threads);

    // Delete TCP workers storage
    debug_net("tcp_master: %d worker threads finished\n", worker_count);
    for(int i = 0; i < worker_count; ++i) {
       tcp_worker_delete(&tcp_workers[i]);
    }

    // Delete TCP threads array
    free(tcp_workers);

    debug_net("tcp_master: finished\n");
    return NULL;
}

static inline void tcp_handler(int fd, uint8_t* inbuf, int inbuf_sz, uint8_t* outbuf, int outbuf_sz, ns_nameserver* ns)
{
    // Receive size
    unsigned short pktsize = 0;
    int n = recv(fd, &pktsize, sizeof(unsigned short), 0);
    pktsize = ntohs(pktsize);
    debug_net("tcp: incoming packet size on %d: %u buffer size: %u\n", fd, (unsigned) pktsize, (unsigned) inbuf_sz);

    // Receive payload
    if(n > 0 && pktsize > 0) {
        if(pktsize <= inbuf_sz)
            n = recv(fd, inbuf, pktsize, 0); /// \todo Check buffer overflow.
        else
            n = 0;
    }

    // Check read result
    if(n > 0) {

        // Send answer
        size_t answer_size = outbuf_sz;
        int res = ns_answer_request(ns, inbuf, n, outbuf + sizeof(short), &answer_size);

        debug_net("tcp: answer wire format (size %u, result %d).\n", (unsigned) answer_size, res);
        if(res >= 0) {

            /*! Cork, @see http://vger.kernel.org/~acme/unbehaved.txt */
            int cork = 1;
            setsockopt(fd, SOL_TCP, TCP_CORK, &cork, sizeof(cork));

            // Copy header
            ((unsigned short*) outbuf)[0] = htons(answer_size);
            int sent = -1;
            while(sent < 0) {
                sent = send(fd, outbuf, answer_size + sizeof(unsigned short), 0);
            }

            // Uncork
            cork = 0;
            setsockopt(fd, SOL_TCP, TCP_CORK, &cork, sizeof(cork));

            debug_net("tcp: sent answer to %d\n", fd);
        }
    }
}

void *tcp_worker( void *obj )
{
    tcp_worker_t* worker = (tcp_worker_t *)obj;
    uint8_t buf[SOCKET_MTU_SZ];
    uint8_t answer[SOCKET_MTU_SZ];
    int nfds = 0;
    debug_net("tcp: worker #%d started\n", worker->epfd);

    for(;;) {

        // Check
        if(worker->events_count < 0) {
            break;
        }

        // Poll new data
        while (worker->events_count > 0) {

            // Poll sockets
            tcp_reserve_bs(worker, worker->events_count * 2);
            nfds = epoll_wait(worker->epfd, worker->events, worker->events_size, 1000);

            // Evaluate
            //fprintf(stderr, "tcp: worker #%d polled %d events (%d sockets).\n", worker->epfd, nfds, worker->events_count);
            int fd = 0;
            for(int i = 0; i < nfds; ++i) {

                // Get client fd
                fd = worker->events[i].data.fd;

                debug_net("tcp: worker #%d processing fd=%d.\n", worker->epfd, fd);
                tcp_handler(fd, buf, SOCKET_MTU_SZ, answer, SOCKET_MTU_SZ, worker->server->nameserver);
                debug_net("tcp: worker #%d finished fd=%d (remaining %d).\n", worker->epfd, fd, worker->events_count);

                // Disconnect
               debug_net("tcp: disconnected: %d\n", fd);
               pthread_mutex_lock(&worker->mutex);
               socket_poll_remove(worker->epfd, fd);
               --worker->events_count;
               close(fd);
               pthread_mutex_unlock(&worker->mutex);
            }
        }

        // Sleep until new events
        debug_net("tcp: worker #%d suspended.\n", worker->epfd);
        pthread_mutex_lock(&worker->mutex);
        pthread_cond_wait(&worker->wakeup, &worker->mutex);
        debug_net("tcp: worker #%d resumed ... (%d sockets in set).\n", worker->epfd, worker->events_count);
        pthread_mutex_unlock(&worker->mutex);
    }

    debug_net("tcp: worker #%d finished.\n", worker->epfd);
    return NULL;
}
