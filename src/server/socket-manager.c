#include "common.h"
#include "socket-manager.h"
#include "name-server.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
//#include <pthread.h>
#include <err.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

//#define SM_DEBUG

const uint SOCKET_BUFF_SIZE = 4096;  /// \todo <= MTU size
const uint DEFAULT_EVENTS_COUNT = 1;

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

void *sm_listen_routine( void *obj );
void *sm_worker_routine( void *obj );

sm_socket *sm_create_socket( unsigned short port, socket_t type )
{
    // create new socket structure
    sm_socket *socket_new = malloc(sizeof(sm_socket));
    if (socket_new == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }

    socket_new->port = port;

    // create new socket
    int stype = SOCK_DGRAM;
    if(type == TCP) {
        stype = SOCK_STREAM;
    }

    /// \todo IPv6
    socket_new->socket = socket( AF_INET, stype, 0 );

    if (socket_new->socket == -1) {
        free(socket_new);
        return NULL;
    }

    return socket_new;
}

/*----------------------------------------------------------------------------*/

int sm_reserve_events( sm_worker *worker, uint size )
{
    assert(size > 0);

    if( size <= worker->events_size )
        return 0;

    struct epoll_event *new_events = realloc(worker->events, size * sizeof(struct epoll_event));
    if (new_events == NULL) {
        return -1;
    }

    worker->events = new_events;
    worker->events_size = size;
    return 0;
}

/*----------------------------------------------------------------------------*/

int sm_remove_event( sm_manager *manager, int socket )
{
    // Compatibility with kernels < 2.6.9, require non-NULL ptr.
    struct epoll_event ev;

    // Needs to be synchronised
    assert(pthread_mutex_trylock(&manager->sockets_mutex) != 0);

    // find socket ptr
    if(epoll_ctl(manager->epfd, EPOLL_CTL_DEL, socket, &ev) != 0) {
        perror ("epoll_ctl");
        return -1;
    }

    --manager->fd_count;
    return 0;
}

/*----------------------------------------------------------------------------*/

int sm_add_event( sm_manager *manager, int socket, uint32_t events )
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));

    // Needs to be synchronised
    assert(pthread_mutex_trylock(&manager->sockets_mutex) != 0);

    // All polled events should use non-blocking mode.
    int old_flag = fcntl(socket, F_GETFL, 0);
    if (fcntl(socket, F_SETFL, old_flag | O_NONBLOCK) == -1) {
        fprintf(stderr, "sm_add_event(): Error setting non-blocking mode on "
                "the socket.\n");
        return -1;
    }

    // Register to epoll
    ev.data.fd = socket;
    ev.events = events;
    if (epoll_ctl(manager->epfd, EPOLL_CTL_ADD, socket, &ev) != 0) {
        log_error("failed to add socket to event set (errno %d): %s.\n", errno, strerror(errno));
        return -1;
    }

    // Increase registered event count
    ++manager->fd_count;
    return 0;
}

void *sm_listen_routine( void *obj )
{
    int worker_id = 0, nfds = 0;
    sm_manager* manager = (sm_manager *)obj;

    // Check handler
    if(manager->handler == NULL) {
        fprintf(stderr, "ERROR: Socket manager has no registered handler.\n");
        return NULL;
    }

    while (manager->is_running) {

        // Select next worker
        sm_worker* worker = &manager->workers[worker_id];
        pthread_mutex_lock(&worker->mutex);

        // Reserve backing-store and wait
        sm_reserve_events(worker, manager->fd_count * 2);
        nfds = epoll_wait(manager->epfd, worker->events, manager->fd_count, 1000);
        if (nfds < 0) {
            perror("sm_listen epoll_wait");
            return NULL;
        }

        // Signalized finish
        if(!manager->is_running) {
            pthread_mutex_unlock(&worker->mutex);
            break;
        }

        // Signalize
        worker->events_count = nfds;
        pthread_cond_signal(&worker->wakeup);
        pthread_mutex_unlock(&worker->mutex);

        // Next worker
        worker_id = (worker_id + 1) % manager->workers_dpt->thread_count;
    }

    // Wake up all workers
    for(int i = 0; i < manager->workers_dpt->thread_count; ++i) {
        sm_worker* worker = &manager->workers[i];
        pthread_mutex_lock(&worker->mutex);
        worker->events_count = 0;
        pthread_cond_signal(&worker->wakeup);
        pthread_mutex_unlock(&worker->mutex);
    }

    return NULL;
}

void *sm_worker_routine( void *obj )
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
    while (worker->mgr->is_running) {
        pthread_mutex_lock(&worker->mutex);
        pthread_cond_wait(&worker->wakeup, &worker->mutex);

        // Evaluate
        for(int i = 0; i < worker->events_count; ++i) {
            event.fd = worker->events[i].data.fd;
            event.events = worker->events[i].events;
            worker->mgr->handler(&event);
        }

        pthread_mutex_unlock(&worker->mutex);
    }

    printf("Worker finished.\n");
    return NULL;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

sm_manager *sm_create( ns_nameserver *nameserver, int thread_count )
{
    sm_manager *manager = malloc(sizeof(sm_manager));
    manager->handler = NULL;
    manager->sockets = NULL;
    manager->fd_count = 0;

    // Create epoll
    manager->epfd = epoll_create(DEFAULT_EVENTS_COUNT);
    if (manager->epfd == -1) {
        log_error("failed to create epoll set (errno %d): %s.\n", errno, strerror(errno));
        free(manager);
        return NULL;
    }

    // Create listener
    manager->listener = dpt_create(1, &sm_listen_routine, manager);
    if(manager->listener == NULL) {
        perror("sm_create listener");
        sm_destroy(&manager);
        return NULL;
    }

    // Create workers
    manager->workers = malloc(thread_count * sizeof(sm_worker));
    if (manager->workers == NULL) {
        perror("sm_create workers");
        sm_destroy(&manager);
        return NULL;
    }

    // Create worker dispatcher
    manager->workers_dpt = dpt_create(thread_count, &sm_worker_routine, NULL);
    if(manager->workers_dpt == NULL) {
        sm_destroy(&manager);
        return NULL;
    }

    // Initialize workers
    memset(manager->workers, 0, thread_count * sizeof(sm_worker));
    for(int i = 0; i < thread_count; ++i) {
        sm_worker *worker = &manager->workers[i];
        worker->events = malloc(DEFAULT_EVENTS_COUNT * sizeof(struct epoll_event));
        if (worker->events == NULL) {
            perror("sm_create worker_init");
            sm_destroy(&manager);
            return NULL;
        }

        worker->id = i;
        worker->events_count = 0;
        worker->events_size = DEFAULT_EVENTS_COUNT;
        worker->mgr = manager;

        if (pthread_mutex_init(&worker->mutex, NULL) != 0) {
            perror("sm_create worker_mutex");
            sm_destroy(&manager);
            return NULL;
        }

        if (pthread_cond_init(&worker->wakeup, NULL) != 0) {
            perror("sm_create worker_wakeup");
            sm_destroy(&manager);
            return NULL;
        }

        // Assign to worker dispatcher
        manager->workers_dpt->routine_obj[i] = (void*) worker;
    }

    // Initialize lock
    int ret = 0;
    if ((ret = pthread_mutex_init(&manager->sockets_mutex, NULL)) != 0) {
        perror("sm_create mutex");
        sm_destroy(&manager);
        return NULL;
    }

    // Initialize nameserver
    manager->nameserver = nameserver;
    return manager;
}

int sm_start( sm_manager* manager )
{
    // Set as running
    manager->is_running = 1;

    // Start dispatchers
    return dpt_start(manager->workers_dpt) + dpt_start(manager->listener);
}

void sm_stop( sm_manager *manager )
{
    manager->is_running = 0;
}

int sm_wait( sm_manager* manager )
{
    return dpt_wait(manager->workers_dpt) + dpt_wait(manager->listener);
}

/*----------------------------------------------------------------------------*/

int sm_open_socket( sm_manager *manager, unsigned short port, socket_t type )
{
    sm_socket *socket_new = sm_create_socket(port, type);
    if (socket_new == NULL) {
        return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons( port );
    addr.sin_addr.s_addr = htonl( INADDR_ANY ); /// \todo Bind to localhost only.

    // Reuse old address if taken
    int flag = 1;
    if(setsockopt(socket_new->socket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        close(socket_new->socket);
        free(socket_new);
        return -1;
    }

    int res = bind(socket_new->socket, (struct sockaddr *)&addr, sizeof(addr));
    if (res == -1) {
        log_error("cannot bind socket (errno %d): %s.\n", errno, strerror(errno));
        close(socket_new->socket);
        free(socket_new);
        return -1;
    }

    // TCP needs listen
    if(type == TCP) {
        res = listen(socket_new->socket, 10); /// \todo Tweak backlog size.
        if (res == -1) {
            close(socket_new->socket);
            free(socket_new);
            return -1;
        }
    }

    // if everything went well, connect the socket to the list
    pthread_mutex_lock(&manager->sockets_mutex);
    socket_new->next = manager->sockets;
    manager->sockets = socket_new;

    // add new event
    /// \todo Edge-Triggered mode.
    if (sm_add_event(manager, socket_new->socket, EPOLLIN) != 0) {
        sm_close_socket(manager, port);
        pthread_mutex_unlock(&manager->sockets_mutex);
        return -1;
    }

    pthread_mutex_unlock(&manager->sockets_mutex);
    return 0;
}

/*----------------------------------------------------------------------------*/

int sm_close_socket( sm_manager *manager, unsigned short port )
{   
    // Synchronise to prevent list corruption
    pthread_mutex_lock(&manager->sockets_mutex);
    sm_socket *s = manager->sockets, *p = NULL;
    while (s != NULL && s->port != port) {
        p = s;
        s = s->next;
    }
    
    if (s == NULL) {
        pthread_mutex_unlock(&manager->sockets_mutex);
        return -1;
    }
    
    assert(s->port == port);

    // Unregister from epoll
    sm_remove_event(manager, s->socket);

    // Disconnect the found socket entry
    if(p != NULL) {
        p->next = s->next;
    }

    free(s);

    // Cleanup on last entry
    if(p == NULL) {
        manager->sockets = NULL;
    }
    pthread_mutex_unlock(&manager->sockets_mutex);
    
    return 0;
}

/*----------------------------------------------------------------------------*/

void sm_destroy( sm_manager **manager )
{
    // Notify close
    (*manager)->is_running = 0;

    // Destroy all sockets
    /// \todo Synchronise this, may result in list corruption.
    while((*manager)->sockets != NULL) {
        sm_close_socket(*manager, (*manager)->sockets->port);
    }

    // Close epoll
    pthread_mutex_lock(&(*manager)->sockets_mutex);
    close((*manager)->epfd);

    // Destroy workers
    for(int i = 0; i < (*manager)->workers_dpt->thread_count; ++i) {
        sm_worker* worker = &(*manager)->workers[i];
        if(worker->events != NULL)
            free(worker->events);
        pthread_mutex_destroy(&worker->mutex);
        pthread_cond_destroy(&worker->wakeup);
    }
    free((*manager)->workers);

    // Free dispatchers
    dpt_destroy(&(*manager)->listener);
    dpt_destroy(&(*manager)->workers_dpt);

    // Destroy socket list mutex
    pthread_mutex_unlock(&(*manager)->sockets_mutex);
    pthread_mutex_destroy(&(*manager)->sockets_mutex);

    free(*manager);
    *manager = NULL;
}

/*----------------------------------------------------------------------------*/

void sm_tcp_handler(sm_event *ev)
{
    struct sockaddr_in faddr;
    int addrsize = sizeof(faddr);
    int incoming = -1;

    // Master socket
    /// \todo Lock per-socket.
    if(ev->fd == ev->manager->sockets->socket) {

        // Accept on master socket
        incoming = accept(ev->fd, (struct sockaddr *)&faddr, (socklen_t *)&addrsize);

        // Register to epoll
        if(incoming < 0) {
            perror("tcp accept");
        }
        else {
            pthread_mutex_lock(&ev->manager->sockets_mutex);
            sm_add_event(ev->manager, incoming, EPOLLIN);
            pthread_mutex_unlock(&ev->manager->sockets_mutex);
            printf("tcp accept: accepted %d\n", incoming);
        }

        return;
    }

    // Receive data
    /// \todo What if data comes fragmented?
    int readb = 0, n = 0;
    while((readb = recv(ev->fd, ev->inbuf + n, ev->size_in - n, 0)) > 0) {
        printf("Received fragment from %d of %dB.\n", ev->fd, readb);
        n += readb;
    }

    if(n <= 0) {

        // Zero read or error other than would-block
        //if(n == 0 || (n == -1 && errno != EWOULDBLOCK)) {
            printf("tcp disconnected: %d\n", ev->fd);
            pthread_mutex_lock(&ev->manager->sockets_mutex);
            sm_remove_event(ev->manager, ev->fd);
            pthread_mutex_unlock(&ev->manager->sockets_mutex);
            close(ev->fd);
        //}

        // No more data to read
        return;
    }

    // Send answer
    printf("Received %d bytes from %d\n", n, ev->fd);
    uint answer_size = ev->size_out;
    int res = ns_answer_request(ev->manager->nameserver, ev->inbuf, n, ev->outbuf,
                                &answer_size);
#ifdef SM_DEBUG
    printf("Got answer of size %d result %d.\n", answer_size, res);
#endif

    /// \todo Risky, socket may be used for reading at this time and send() may return EAGAIN.
    if (res == 0) {

        assert(answer_size > 0);
#ifdef SM_DEBUG
        printf("Answer wire format (size %u):\n", answer_size);
        hex_print(ev->outbuf, answer_size);
#endif

        int sent = send(ev->fd, ev->outbuf, answer_size, 0);
        printf("Sent answer to %d\n", ev->fd);
        if (sent < 0) {
            perror("tcp send");
        }
    }
}

void sm_udp_handler(sm_event *ev)
{
    struct sockaddr_in faddr;
    int addrsize = sizeof(faddr);

    // If fd is a TCP server socket, accept incoming TCP connection, else recvfrom()
    int n = 0;
    while((n = recvfrom(ev->fd, ev->inbuf, ev->size_in, 0, (struct sockaddr *)&faddr, (socklen_t *)&addrsize)) > 0) {

        debug_sm("Received %d bytes.\n", n);

        //printf("unlocking mutex from thread %ld\n", pthread_self());
        uint answer_size = ev->size_out;
        int res = ns_answer_request(ev->manager->nameserver, ev->inbuf, n, ev->outbuf,
                          &answer_size);

        debug_sm("Got answer of size %d.\n", answer_size);

        if (res == 0) {
            assert(answer_size > 0);
            debug_sm("Answer wire format (size %u):\n", answer_size);
            debug_sm_hex(answer, answer_size);

            /// \todo Risky, socket may be used for reading at this time and send() may return EAGAIN.
            /// \todo MSG_DONTWAIT not needed anyway, as O_NONBLOCK is set by fcntl().
            int sent = sendto(ev->fd, ev->outbuf, answer_size, MSG_DONTWAIT,
                              (struct sockaddr *)&faddr,
                              (socklen_t)addrsize);

            if (sent < 0) {
                const int error = errno;
                log_error("failed to send datagram (errno %d): %s.\n", error, strerror(error));
            }
        }
    }
}
