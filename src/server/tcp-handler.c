#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include "tcp-handler.h"

void tcp_handler(sm_event *ev)
{
    struct sockaddr_in faddr;
    int addrsize = sizeof(faddr);
    int incoming = 0;

    // Master socket
    /// \todo Lock per-socket.
    if(ev->fd == ev->manager->sockets->socket) {

        // Accept on master socket
        while(incoming >= 0) {

            pthread_mutex_lock(&ev->manager->sockets_mutex);
            incoming = accept(ev->fd, (struct sockaddr *)&faddr, (socklen_t *)&addrsize);

            // Register to epoll
            if(incoming < 0) {
                //log_error("cannot accept incoming TCP connection (errno %d): %s.\n", errno, strerror(errno));
            }
            else {
                sm_add_event(ev->manager, incoming, EPOLLIN);
                debug_sm("tcp accept: accepted %d\n", incoming);
            }

            pthread_mutex_unlock(&ev->manager->sockets_mutex);
        }

        return;
    }

    // Receive size
    unsigned short pktsize = 0;
    pthread_mutex_lock(&ev->manager->sockets_mutex);
    int n = recv(ev->fd, &pktsize, sizeof(unsigned short), 0);
    pktsize = ntohs(pktsize);
    debug_sm("Incoming packet size on %d: %u buffer size: %u\n", ev->fd, (unsigned) pktsize, (unsigned) ev->size_in);

    // Receive payload
    if(n > 0 && pktsize > 0) {
        if(pktsize <= ev->size_in)
            n = recv(ev->fd, ev->inbuf, pktsize, 0); /// \todo Check buffer overflow.
        else
            n = 0;
    }

    // Check read result
    pthread_mutex_unlock(&ev->manager->sockets_mutex);
    if(n > 0) {

        // Send answer
        size_t answer_size = ev->size_out;
        int res = ns_answer_request(ev->manager->nameserver, ev->inbuf, n, ev->outbuf + sizeof(short),
                                    &answer_size);

        debug_sm("Answer wire format (size %u, result %d).\n", (unsigned) answer_size, res);
        if(res >= 0) {

            // Copy header
            pktsize = htons(answer_size);
            memcpy(ev->outbuf, &pktsize, sizeof(unsigned short));
            int sent = send(ev->fd, ev->outbuf, answer_size + sizeof(unsigned short), 0);
            if (sent < 0) {
                log_error("tcp send failed (errno %d): %s\n", errno, strerror(errno));
            }

            debug_sm("Sent answer to %d\n", ev->fd);
        }
    }

    // Evaluate
    /// \todo Do not close if there is a pending write in another thread.
    if(n <= 0) {

        // Zero read or error other than would-block
        debug_sm("tcp disconnected: %d\n", ev->fd);
        pthread_mutex_lock(&ev->manager->sockets_mutex);
        sm_remove_event(ev->manager, ev->fd);
        pthread_mutex_unlock(&ev->manager->sockets_mutex);
        close(ev->fd);
    }
}


void *tcp_master( void *obj )
{
    int worker_id = 0, nfds = 0;
    sm_manager* manager = (sm_manager *)obj;

    while (manager->is_running) {

        // Select next worker
        sm_worker* worker = &manager->workers[worker_id];
        pthread_mutex_lock(&worker->mutex);

        // Reserve backing-store and wait
        pthread_mutex_lock(&manager->sockets_mutex);
        int current_fds = manager->fd_count;
        sm_reserve_events(worker, current_fds * 2);
        pthread_mutex_unlock(&manager->sockets_mutex);
        nfds = epoll_wait(manager->epfd, worker->events, current_fds, 1000);
        if (nfds < 0) {
            debug_server("epoll_wait: %s\n", strerror(errno));
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

void *tcp_worker( void *obj )
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
        //fprintf(stderr, "Worker [%d] wakeup %d events.\n", worker->id, worker->events_count);
        for(int i = 0; i < worker->events_count; ++i) {
            event.fd = worker->events[i].data.fd;
            event.events = worker->events[i].events;
            tcp_handler(&event);
        }

        pthread_mutex_unlock(&worker->mutex);
    }

    debug_server("Worker %d finished.\n", worker->id);
    return NULL;
}

