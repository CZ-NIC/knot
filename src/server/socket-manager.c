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

void sm_destroy_socket( sm_socket **socket )
{
    close((*socket)->socket);   // TODO: can we close the socket like this?
                                // what about non-opened socket?
    free(*socket);
    *socket = NULL;
}

/*----------------------------------------------------------------------------*/

int sm_reserve_events( sm_manager *manager, uint size )
{
    assert(size > 0);

    if( size < manager->events_max )
        return 0;

    struct epoll_event *new_events = realloc(manager->events, size * sizeof(struct epoll_event));
    if (new_events == NULL) {
        return -1;
    }

    manager->events = new_events;
    manager->events_max = size;
    return 0;
}

/*----------------------------------------------------------------------------*/

int sm_realloc_events( sm_manager *manager )
{
    assert(manager->events_count == manager->events_max);

    // the mutex should be already locked
    assert(pthread_mutex_trylock(&manager->mutex) != 0);
    int ret = sm_reserve_events(manager, manager->events_max * 2);
    if (ret < 0) {
        perror("sm_reserve_events");
        return ret;
    }

    return ret;
}

/*----------------------------------------------------------------------------*/

int sm_remove_event( sm_manager *manager, int socket )
{
    /// \todo Not socket mutex, but global mutex may need locking. Maybe not.
    struct epoll_event ev;

    // find socket ptr
    if(epoll_ctl(manager->epfd, EPOLL_CTL_DEL, socket, &ev) != 0) {
        perror ("epoll_ctl");
        return -1;
    }

    --manager->events_count;

    return 0;
}

/*----------------------------------------------------------------------------*/

/** \bug In epoll, events should not be initialized, it is handled by epoll_wait.
  * \todo Do we need locking? epoll_wait() won't be affected anyway and add_event
  *       is called from synchronised environment.
  */
int sm_add_event( sm_manager *manager, int socket, uint32_t events )
{
    struct epoll_event ev;
    //pthread_mutex_lock(&manager->mutex);

    // enough space?
    if (manager->events_count == manager->events_max) {
        if (sm_realloc_events(manager) != 0) {
            return -1;
        }
    }

    // All polled events should use non-blocking mode.
    int old_flag = fcntl(socket, F_GETFL, 0);
    if (fcntl(socket, F_SETFL, old_flag | O_NONBLOCK) == -1) {
        fprintf(stderr, "sm_add_event(): Error setting non-blocking mode on "
                "the socket.\n");
        //pthread_mutex_unlock(&manager->mutex);
        return -1;
    }

    // Register to epoll
    ev.data.fd = socket;
    ev.events = events;
    if (epoll_ctl(manager->epfd, EPOLL_CTL_ADD, socket, &ev) != 0) {
        log_error("failed to add socket to event set (errno %d): %s.\n", errno, strerror(errno));
        //pthread_mutex_unlock(&manager->mutex);
        return -1;
    }

    // Increase registered event count
    ++manager->events_count;
    //pthread_mutex_unlock(&manager->mutex);
    return 0;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

sm_manager *sm_create( ns_nameserver *nameserver, int thread_count )
{
    sm_manager *manager = malloc(sizeof(sm_manager));

    // Create epoll
    manager->epfd = epoll_create(DEFAULT_EVENTS_COUNT);
    if (manager->epfd == -1) {
        log_error("failed to create epoll set (errno %d): %s.\n", errno, strerror(errno));
        free(manager);
        return NULL;
    }

    // Create mutex
    int errval;
    if ((errval = pthread_mutex_init(&manager->mutex, NULL)) != 0) {
        perror("sm_create");
        free(manager);
        return NULL;
    }

    // Initialize epoll backing store
    manager->handler = NULL;
    manager->sockets = NULL;
    manager->events_count = 0;
    manager->events_max = DEFAULT_EVENTS_COUNT;
    manager->events = malloc(DEFAULT_EVENTS_COUNT * sizeof(struct epoll_event));
    if (manager->events == NULL) {
        perror("sm_create");
        sm_destroy(&manager);
        return NULL;
    }

    // Create listener
    manager->listener = dpt_create(1, &sm_listen, manager);
    if(manager->listener == NULL) {
        log_error("failed to initialize mutex (errno %d): %s.\n", errval, strerror(errval));
        sm_destroy(&manager);
        return NULL;
    }

    // Create workers
    manager->workers = dpt_create(thread_count, &sm_worker, manager);
    if(manager->workers == NULL) {
        perror("sm_create");
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
    return dpt_start(manager->workers) + dpt_start(manager->listener);
}

int sm_wait( sm_manager* manager )
{
    return dpt_wait(manager->workers) + dpt_wait(manager->listener);
}

/*----------------------------------------------------------------------------*/

int sm_open_socket( sm_manager *manager, unsigned short port, socket_t type )
{
    sm_socket *socket_new = sm_create_socket(port, type);

    if (socket_new == NULL) {
        return -1;
    }

    struct sockaddr_in addr;

    //log_info("Creating socket for listen on port %hu.\n", port);

    addr.sin_family = AF_INET;
    addr.sin_port = htons( port );
    addr.sin_addr.s_addr = htonl( INADDR_ANY ); /// \todo Bind to localhost only.

    // Reuse old address if taken
    int flag = 1;
    if(setsockopt(socket_new->socket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        sm_destroy_socket(&socket_new);
        return -1;
    }

    int res = bind(socket_new->socket, (struct sockaddr *)&addr, sizeof(addr));
    if (res == -1) {
        log_error("cannot bind socket (errno %d): %s.\n", errno, strerror(errno));
        sm_destroy_socket(&socket_new);
        return -1;
    }

    // TCP needs listen
    if(type == TCP) {
        res = listen(socket_new->socket, 10); /// \todo Tweak backlog size.
        if (res == -1) {
            sm_destroy_socket(&socket_new);
            return -1;
        }
    }

    // if everything went well, connect the socket to the list
    socket_new->next = manager->sockets;

    // TODO: this should be atomic by other means than locking the mutex:
    pthread_mutex_lock(&manager->mutex);
    manager->sockets = socket_new;

    // add new event
    // TODO: what are the other events for??
    if (sm_add_event(manager, socket_new->socket, EPOLLIN) != 0) {
        sm_destroy_socket(&socket_new);
        return -1;
    }

    pthread_mutex_unlock(&manager->mutex);

    return 0;
}

/*----------------------------------------------------------------------------*/

int sm_close_socket( sm_manager *manager, unsigned short port )
{   
    // find the socket entry, close the socket, remove the event
    // and destroy the entry
    // do we have to lock the mutex while searching for the socket??
    pthread_mutex_lock(&manager->mutex);

    sm_socket *s = manager->sockets, *p = NULL;
    while (s != NULL && s->port != port) {
        p = s;
        s = s->next;
    }
    
    if (s == NULL) {
        pthread_mutex_unlock(&manager->mutex);
        return -1;
    }
    
    assert(s->port == port);

    // Unregister from epoll
    sm_remove_event(manager, s->socket);

    // disconnect the found socket entry
    p->next = s->next;
    pthread_mutex_unlock(&manager->mutex);
    sm_destroy_socket(&s);
    
    return 0;
}

/*----------------------------------------------------------------------------*/

void sm_destroy( sm_manager **manager )
{
    pthread_mutex_lock(&(*manager)->mutex);

    // Notify close
    (*manager)->is_running = 0;

    // Destroy all sockets
    sm_socket *s = (*manager)->sockets;
    if (s != NULL) {
        sm_socket *next = s->next;
        while (next != NULL) {
            s->next = next->next;
            sm_destroy_socket(&next);
            next = s->next;
        }
        sm_destroy_socket(&s);
    }

    // Close epoll
    close((*manager)->epfd);

    // Destroy events backing store
    if((*manager)->events != NULL)
        free((*manager)->events);

    // Free dispatchers
    dpt_destroy(&(*manager)->listener);
    dpt_destroy(&(*manager)->workers);

    // Destroy mutex
    pthread_mutex_unlock(&(*manager)->mutex);
    pthread_mutex_destroy(&(*manager)->mutex);

    free(*manager);
    *manager = NULL;
}

/*----------------------------------------------------------------------------*/

void sm_tcp_handler(sm_event *ev)
{
    struct sockaddr_in faddr;
    int addrsize = sizeof(faddr);
    int incoming = -1;

    // Lock the socket
    pthread_mutex_lock(&ev->manager->mutex);

    // Master socket
    if(ev->fd == ev->manager->sockets->socket) {

        // Accept on master socket
        incoming = accept(ev->fd, (struct sockaddr *)&faddr, (socklen_t *)&addrsize);

        // Register to epoll
        if(incoming < 0) {
            perror("tcp accept");
        }
        else {
            sm_add_event(ev->manager, incoming, EPOLLIN);
            printf("tcp accept: accepted %d\n", incoming);
        }

        // Unlock master socket
        pthread_mutex_unlock(&ev->manager->mutex);
        return;
    }

    // Receive data
    /// \todo What if data comes fragmented?
    int readb = 0, n = 0;
    while((readb = recv(ev->fd, ev->inbuf + n, ev->size_in - n, 0)) > 0) {
        printf("Received fragment from %d of %dB.\n", ev->fd, readb);
        n += readb;
    }
    pthread_mutex_unlock(&ev->manager->mutex);
    if(n <= 0) {

        // Zero read or error other than would-block
        //if(n == 0 || (n == -1 && errno != EWOULDBLOCK)) {
            printf("tcp disconnected: %d\n", ev->fd);
            sm_remove_event(ev->manager, ev->fd);
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

    pthread_mutex_lock(&ev->manager->mutex);

    // If fd is a TCP server socket, accept incoming TCP connection, else recvfrom()
    int n = recvfrom(ev->fd, ev->inbuf, ev->size_in, 0, (struct sockaddr *)&faddr, (socklen_t *)&addrsize);
    if(n >= 0) {

        debug_sm("Received %d bytes.\n", n);

        //printf("unlocking mutex from thread %ld\n", pthread_self());
        pthread_mutex_unlock(&ev->manager->mutex);
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
            int sent = sendto(ev->fd, ev->outbuf, answer_size, 0,
                              (struct sockaddr *)&faddr,
                              (socklen_t)addrsize);

            if (sent < 0) {
                const int error = errno;
                log_error("failed to send datagram (errno %d): %s.\n", error, strerror(error));
            }
        }
    } else {
        pthread_mutex_unlock(&ev->manager->mutex);
    }
}

/*----------------------------------------------------------------------------*/

void *sm_listen( void *obj )
{
    sm_manager* manager = (sm_manager *)obj;
    char buf[SOCKET_BUFF_SIZE];
    char answer[SOCKET_BUFF_SIZE];
    sm_event event;
    event.manager = manager;
    event.fd = 0;
    event.events = 0;
    event.inbuf = buf;
    event.outbuf = answer;
    event.size_in = event.size_out = SOCKET_BUFF_SIZE;

    // Check handler
    if(manager->handler == NULL) {
        printf("ERROR: Socket manager has no registered handler.\n");
        return NULL;
    }

    while (manager->is_running) {
        /// \bug What if events count changes in another thread and backing
        ///      store gets reallocated? Memory error in loop reading probably.
        // Reserve 2x backing-store size
        sm_reserve_events(manager, manager->events_count * 2);
        int nfds = epoll_wait(manager->epfd, manager->events,
                              manager->events_count, 1000);

        if (nfds < 0) {
            printf("ERROR: %d: %s.\n", errno, strerror(errno));
            return NULL;
        }

        // Signalized finish
        if(!manager->is_running) {
            break;
        }

        // for each ready socket
        for(int i = 0; i < nfds; i++) {
            //printf("locking mutex from thread %ld\n", pthread_self());
            event.fd = manager->events[i].data.fd;
            event.events = manager->events[i].events;
            manager->handler(&event);
        }
    }

    return NULL;
}

void *sm_worker( void *obj )
{
    sm_manager* manager = (sm_manager *)obj;
    while (manager->is_running) {
        sleep(1);
    }

    printf("Worker finished.\n");
    return NULL;
}

void sm_stop( sm_manager *manager )
{
    manager->is_running = 0;
}
