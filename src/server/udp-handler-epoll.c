#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include "udp-handler-epoll.h"

#if 0

/** Event descriptor.
  */
typedef struct sm_event {
    struct sm_manager* manager;
    int fd;
    uint32_t events;
    void* inbuf;
    void* outbuf;
    size_t size_in;
    size_t size_out;
} sm_event;

static inline void udp_epoll_handler(sm_event *ev)
{
    struct sockaddr_in faddr;
    int addrsize = sizeof(faddr);

    int n = 0;

    // Loop until all data is read
    while(n >= 0) {

        // Receive data
        // \todo Global I/O lock means ~ 8% overhead; recvfrom() should be thread-safe
        n = socket_recvfrom(ev->fd, ev->inbuf, ev->size_in, MSG_DONTWAIT, (struct sockaddr *)&faddr, (socklen_t *)&addrsize);
        //char _str[INET_ADDRSTRLEN];
        //inet_ntop(AF_INET, &(faddr.sin_addr), _str, INET_ADDRSTRLEN);
        //fprintf(stderr, "recvfrom() in %p: received %d bytes from %s:%d.\n", (void*)pthread_self(), n, _str, faddr.sin_port);

        // Socket not ready
        if(n == -1 && errno == EWOULDBLOCK) {
            return;
        }

        // Error
        if(n <= 0) {
            log_error("udp: reading data from the socket failed: %d - %s\n", errno, strerror(errno));
            return;
        }

        debug_sm("udp: received %d bytes.\n", n);
        size_t answer_size = ev->size_out;
        int res = ns_answer_request(ev->manager->nameserver, ev->inbuf, n, ev->outbuf,
                          &answer_size);

        debug_sm("udp: got answer of size %u.\n", (unsigned) answer_size);

        if (res == 0) {
            assert(answer_size > 0);

            debug_sm("udp: answer wire format (size %u):\n", answer_size);
            debug_sm_hex(answer, answer_size);

            for(;;) {
                res = socket_sendto(ev->fd, ev->outbuf, answer_size, MSG_DONTWAIT,
                             (struct sockaddr *) &faddr,
                             (socklen_t) addrsize);

                //fprintf(stderr, "sendto() in %p: written %d bytes to %d.\n", (void*)pthread_self(), res, ev->fd);
                if(res != answer_size) {
                    log_error("udp: failed to send datagram (errno %d): %s.\n", res, strerror(res));
                    continue;
                }

                break;
            }
        }
    }
}

void *udp_epoll_master( void *obj )
{
    int worker_id = 0, nfds = 0;
    sm_manager* manager = (sm_manager *)obj;
    sm_worker* master = &manager->master;

    while (manager->is_running) {

        // Select next worker
        sm_worker* worker = &manager->workers[worker_id];
        pthread_mutex_lock(&worker->mutex);

        // Reserve backing-store and wait
        pthread_mutex_lock(&master->mutex);
        int current_fds = master->events_count;
        sm_reserve_events(worker, current_fds * 2);
        pthread_mutex_unlock(&master->mutex);
        nfds = epoll_wait(master->epfd, worker->events, current_fds, 1000);
        if (nfds < 0) {
            debug_sm("udp: epoll_wait: %s\n", strerror(errno));
            worker->events_count = 0;
            pthread_cond_signal(&worker->wakeup);
            pthread_mutex_unlock(&worker->mutex);
            continue; // Keep the same worker
        }

        // Signalize
        worker->events_count = nfds;
        pthread_cond_signal(&worker->wakeup);
        pthread_mutex_unlock(&worker->mutex);

        // Next worker
        worker_id = next_worker(worker_id, manager);
    }

    // Wake up all workers
    int last_wrkr = worker_id;
    for(;;) {

        sm_worker* worker = &manager->workers[worker_id];
        pthread_mutex_lock(&worker->mutex);
        worker->events_count = -1; // Shut down worker
        pthread_cond_signal(&worker->wakeup);
        pthread_mutex_unlock(&worker->mutex);
        worker_id = next_worker(worker_id, manager);

        // Finish with the starting worker
        if(worker_id == last_wrkr)
            break;
    }

    return NULL;
}

void *udp_epoll_worker( void *obj )
{
    sm_worker* worker = (sm_worker *)obj;
    char buf[SOCKET_BUFF_SIZE];
    char answer[SOCKET_BUFF_SIZE];

    sm_event event;
    event.manager = worker->mgr;
    event.fd = 0;
    event.events = 0;
    event.inbuf = buf;
    event.outbuf = answer;
    event.size_in = event.size_out = SOCKET_BUFF_SIZE;

    for(;;) {
        pthread_mutex_lock(&worker->mutex);
        pthread_cond_wait(&worker->wakeup, &worker->mutex);

        // Check
        if(worker->events_count < 0) {
            pthread_mutex_unlock(&worker->mutex);
            break;
        }

        // Evaluate
        debug_sm("udp: worker #%d polled %d events.\n", worker->epfd, worker->events_count);
        for(int i = 0; i < worker->events_count; ++i) {
            event.fd = worker->events[i].data.fd;
            event.events = worker->events[i].events;
            udp_epoll_handler(&event);
        }

        pthread_mutex_unlock(&worker->mutex);
    }

    debug_sm("udp: worker #%d finished.\n", worker->epfd);
    return NULL;
}

#endif
