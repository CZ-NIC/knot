#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include "tcp-handler.h"

/** Event descriptor.
  */
typedef struct sm_event {
    struct sm_worker* worker;
    int fd;
    uint32_t events;
    void* inbuf;
    void* outbuf;
    size_t size_in;
    size_t size_out;
} sm_event;

static inline void tcp_handler(sm_event *ev)
{
    // Receive size
    unsigned short pktsize = 0;
    int n = recv(ev->fd, &pktsize, sizeof(unsigned short), 0);
    pktsize = ntohs(pktsize);
    debug_sm("tcp: incoming packet size on %d: %u buffer size: %u\n", ev->fd, (unsigned) pktsize, (unsigned) ev->size_in);

    // Receive payload
    if(n > 0 && pktsize > 0) {
        if(pktsize <= ev->size_in)
            n = recv(ev->fd, ev->inbuf, pktsize, 0); /// \todo Check buffer overflow.
        else
            n = 0;
    }

    // Check read result
    if(n > 0) {

        // Send answer
        size_t answer_size = ev->size_out;
        int res = ns_answer_request(ev->worker->mgr->nameserver, ev->inbuf, n, ev->outbuf + sizeof(short),
                                    &answer_size);

        debug_sm("tcp: answer wire format (size %u, result %d).\n", (unsigned) answer_size, res);
        if(res >= 0) {

            // Copy header
            pktsize = htons(answer_size);
            memcpy(ev->outbuf, &pktsize, sizeof(unsigned short));
            int sent = -1;
            while(sent < 0) {
                sent = send(ev->fd, ev->outbuf, answer_size + sizeof(unsigned short), 0);
            }

            debug_sm("tcp: sent answer to %d\n", ev->fd);
        }
    }

    // Disconnect
   debug_sm("tcp: disconnected: %d\n", ev->fd);
   pthread_mutex_lock(&ev->worker->mutex);
   sm_remove_event(ev->worker->epfd, ev->fd);
   --ev->worker->events_count;
   close(ev->fd);
   pthread_mutex_unlock(&ev->worker->mutex);
}


void *tcp_master( void *obj )
{
    sm_manager* manager = (sm_manager *)obj;
    sm_worker* master = &manager->master;
    struct sockaddr_in faddr;
    int addrsize = sizeof(faddr);
    int worker_id = 0;
    int incoming = 0;
    int nfds = 0;

    while (manager->is_running) {

        // Poll master sockets
        nfds = epoll_wait(master->epfd, master->events, master->events_size, 1000);
        if (nfds < 0) {
            continue;
        }

        // Accept on master socket
        for(int i = 0; i < nfds; ++i) {

            incoming = accept(master->events[i].data.fd, (struct sockaddr *)&faddr, (socklen_t *)&addrsize);

            // Register to epoll
            if(incoming < 0) {
                log_error("tcp: cannot accept incoming connection (errno %d): %s.\n", errno, strerror(errno));
            }
            else {
                sm_worker* worker = &manager->workers[worker_id];

                // Register incoming socket
                pthread_mutex_lock(&worker->mutex);
                debug_sm("tcp accept: assigned socket %d to worker #%d\n", incoming, worker->epfd);
                if(sm_add_event(worker->epfd, incoming, EPOLLIN) == 0)
                    ++worker->events_count;

                pthread_cond_signal(&worker->wakeup);
                pthread_mutex_unlock(&worker->mutex);

                worker_id = next_worker(worker_id, manager);

            }
        }
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

void *tcp_worker( void *obj )
{
    sm_worker* worker = (sm_worker *)obj;
    char buf[SOCKET_BUFF_SIZE];
    char answer[SOCKET_BUFF_SIZE];
    int nfds = 0;

    sm_event event;
    event.worker = worker;
    event.fd = 0;
    event.events = 0;
    event.inbuf = buf;
    event.outbuf = answer;
    event.size_in = event.size_out = SOCKET_BUFF_SIZE;

    for(;;) {

        // Check
        if(worker->events_count < 0) {
            break;
        }

        // Poll new data
        while (worker->events_count > 0 && worker->mgr->is_running) {

            // Poll sockets
            sm_reserve_events(worker, worker->events_count * 2);
            nfds = epoll_wait(worker->epfd, worker->events, worker->events_size, 1000);

            // Evaluate
            //fprintf(stderr, "tcp: worker #%d polled %d events (%d sockets).\n", worker->epfd, nfds, worker->events_count);
            for(int i = 0; i < nfds; ++i) {
                event.fd = worker->events[i].data.fd;
                event.events = worker->events[i].events;
                debug_sm("tcp: worker #%d processing fd=%d.\n", worker->epfd, event.fd);
                tcp_handler(&event);
                debug_sm("tcp: worker #%d finished fd=%d (remaining %d).\n", worker->epfd, event.fd, worker->events_count);
            }
        }


        // Sleep until new events
        debug_sm("tcp: worker #%d suspended.\n", worker->epfd);
        pthread_mutex_lock(&worker->mutex);
        pthread_cond_wait(&worker->wakeup, &worker->mutex);
        debug_sm("tcp: worker #%d resumed ... (%d sockets in set).\n", worker->epfd, worker->events_count);
        pthread_mutex_unlock(&worker->mutex);
    }

    debug_sm("tcp: worker #%d finished.\n", worker->epfd);
    return NULL;
}

