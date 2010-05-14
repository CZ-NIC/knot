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

const uint SOCKET_BUFF_SIZE = 4096;
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
        log_error("failed to create socket (errno %d): %s\n", errno, strerror(errno));
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

int sm_realloc_events( sm_manager *manager )
{
    assert(manager->events_count == manager->events_max);
    // the mutex should be already locked
    assert(pthread_mutex_trylock(&manager->mutex) != 0);

    struct epoll_event *new_events = realloc(manager->events,
                                             manager->events_max * 2);
    if (new_events == NULL) {
        ERR_ALLOC_FAILED;
        return -1;
    }

    manager->events = new_events;
    manager->events_max *= 2;

    return 0;
}

/*----------------------------------------------------------------------------*/

int sm_add_event( sm_manager *manager, int socket, uint32_t events )
{
    pthread_mutex_lock(&manager->mutex);
    // enough space?
    if (manager->events_count == manager->events_max) {
        if (sm_realloc_events(manager) != 0) {
            return -1;
        }
    }

    manager->events[manager->events_count].data.u64 = 0; // NULL union (all 64 bits)
    manager->events[manager->events_count].events = events;
    manager->events[manager->events_count].data.fd = socket;

    if (epoll_ctl(manager->epfd, EPOLL_CTL_ADD, socket,
                         &manager->events[manager->events_count]) != 0) {
        log_error("failed to add socket to event set (errno %d): %s.\n", errno, strerror(errno));
        // TODO: some cleanup??
        return -1;
    }

    ++manager->events_count;

    pthread_mutex_unlock(&manager->mutex);

    return 0;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

sm_manager *sm_create( ns_nameserver *nameserver )
{
    sm_manager *manager = malloc(sizeof(sm_manager));

    // create epoll
    manager->epfd = epoll_create(DEFAULT_EVENTS_COUNT);
    if (manager->epfd == -1) {
        log_error("failed to create epoll set (errno %d): %s.\n", errno, strerror(errno));
        free(manager);
        return NULL;
    }

    manager->handler = NULL;
    manager->sockets = NULL;

    // create space for events
    manager->events_count = 0;
    manager->events_max = DEFAULT_EVENTS_COUNT;
    manager->events = malloc(DEFAULT_EVENTS_COUNT * sizeof(struct epoll_event));

    if (manager->events == NULL) {
        ERR_ALLOC_FAILED;
        close(manager->epfd);
        free(manager);
        return NULL;
    }

    int errval;
    if ((errval = pthread_mutex_init(&manager->mutex, NULL)) != 0) {
        log_error("failed to initialize mutex (errno %d): %s.\n", errval, strerror(errval));
        close(manager->epfd);
        free(manager);
        manager = NULL;
        return NULL;
    }

    manager->nameserver = nameserver;

    return manager;
}

/*----------------------------------------------------------------------------*/

int sm_open_socket( sm_manager *manager, unsigned short port, socket_t type )
{
    sm_socket *socket_new = sm_create_socket(port, type);

    if (socket_new == NULL) {
        return -1;
    }

    // Reuse old address if taken
    int flag = 1;
    if(setsockopt(socket_new->socket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        fprintf(stderr, "sm_open_socket(): Error setting SO_REUSEADDR attribute on "
                        "the socket.\n");
    }

    // Set non-blocking mode on the socket
    int old_flag = fcntl(socket_new->socket, F_GETFL, 0);
    if (fcntl(socket_new->socket, F_SETFL, old_flag | O_NONBLOCK) == -1) {
        log_error("%s: error setting non-blocking mode on the socket.\n", __func__);
        sm_destroy_socket(&socket_new);
        return -1;
    }

    struct sockaddr_in addr;

    //log_info("Creating socket for listen on port %hu.\n", port);

    addr.sin_family = AF_INET;
    addr.sin_port = htons( port );
    addr.sin_addr.s_addr = htonl( INADDR_ANY ); /// \todo Bind to localhost only.

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
            printf( "ERROR: %d: %s.\n", errno, strerror(errno) );
            sm_destroy_socket(&socket_new);
            return -1;
        }
    }

    // add new event
    // TODO: what are the other events for??
    if (sm_add_event(manager, socket_new->socket, EPOLLIN
                     /*| EPOLLPRI | EPOLLERR | EPOLLHUP*/) != 0)
    {
        sm_destroy_socket(&socket_new);
        return -1;
    }

    // if everything went well, connect the socket to the list
    socket_new->next = manager->sockets;

    // TODO: this should be atomic by other means than locking the mutex:
    pthread_mutex_lock(&manager->mutex);
    manager->sockets = socket_new;
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

    // remove the event (last argument is ignored, so we may use the first event
    if (epoll_ctl(manager->epfd, EPOLL_CTL_DEL, s->socket, manager->events)
        != 0) {
        log_error("failed to remote socket from event set (errno %d): %s.\n", errno, strerror(errno));
        pthread_mutex_unlock(&manager->mutex);
        return -1;
    }
    // TODO: maybe remove the event from the event array?
    // it would need to move all items after it or use some pointer to
    // first free place in the array and reuse the place

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
    // TODO: even the listen function should acquire the mutex maybe,
    // because otherwise it can use uninitialized values

    // close the epoll file descriptor to not receive any new events
    // is it ok to just close the epoll file descriptor and not delete each
    // event with epoll_ctl() ?
    close((*manager)->epfd);

    // destroy all sockets
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

    // destroy events
    free((*manager)->events);

    pthread_mutex_unlock(&(*manager)->mutex);
    // TODO: what if something happens here?
    pthread_mutex_destroy(&(*manager)->mutex);

    free(*manager);
    *manager = NULL;
}

/*----------------------------------------------------------------------------*/

void sm_tcp_handler(sm_manager *manager, int fd, void *buf, size_t bufsize, void* answer, size_t answer_size)
{
    struct sockaddr_in faddr;
    int addrsize = sizeof(faddr);

    printf("fixme: TCP incoming connection (stub handler).\n");
    accept(fd, (struct sockaddr *)&faddr, (socklen_t *)&addrsize);
}

void sm_udp_handler(sm_manager *manager, int fd, void *buf, size_t bufsize, void* answer, size_t answer_size)
{
    struct sockaddr_in faddr;
    int addrsize = sizeof(faddr);

    pthread_mutex_lock(&manager->mutex);

    // If fd is a TCP server socket, accept incoming TCP connection, else recvfrom()
    int n = recvfrom(fd, buf, bufsize, 0, (struct sockaddr *)&faddr, (socklen_t *)&addrsize);
    if(n >= 0) {

        debug_sm("Received %d bytes.\n", n);

        //log_info("unlocking mutex from thread %ld\n", pthread_self());
        pthread_mutex_unlock(&manager->mutex);

        int res = ns_answer_request(manager->nameserver, buf, n, answer,
                          &answer_size);

        debug_sm("Got answer of size %d.\n", answer_size);

        if (res == 0) {
            assert(answer_size > 0);
                    
            debug_sm("Answer wire format (size %u):\n", answer_size);
            debug_sm_hex(answer, answer_size);

            /// \todo Destination addr and addrsize must be NULL on TCP, may return EISCONN otherwise.
            int sent = sendto(fd, answer, answer_size, MSG_DONTWAIT,
                              (struct sockaddr *)&faddr,
                              (socklen_t)addrsize);

            if (sent < 0) {
                const int error = errno;
                log_error("failed to send datagram (errno %d): %s.\n", error, strerror(error));
            }
        }
    } else {
        pthread_mutex_unlock(&manager->mutex);
    }
}

/*----------------------------------------------------------------------------*/

void *sm_listen( void *obj )
{
    sm_manager* manager = (sm_manager *)obj;
    char buf[SOCKET_BUFF_SIZE];
    char answer[SOCKET_BUFF_SIZE];

    // Check handler
    if(manager->handler == NULL) {
        printf("ERROR: Socket manager has no registered handler.\n");
        return NULL;
    }

    while (1) {
        int nfds = epoll_wait(manager->epfd, manager->events,
                              manager->events_count, -1);
        if (nfds < 0) {
            printf("ERROR: %d: %s.\n", errno, strerror(errno));
            return NULL;
        }

        // for each ready socket
        for(int i = 0; i < nfds; i++) {
            //printf("locking mutex from thread %ld\n", pthread_self());
            manager->handler(manager, manager->events[i].data.fd, buf, SOCKET_BUFF_SIZE, answer, SOCKET_BUFF_SIZE);
        }
    }

}
