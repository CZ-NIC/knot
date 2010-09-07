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
#include <arpa/inet.h>

//#define SM_DEBUG

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

int sm_reserve_events( sm_worker *worker, uint size )
{
    assert(size > 0);

    // If backing-store is large enough, return
    if( size <= worker->events_size )
        return 0;

    // Realloc events backing-store
    /// \todo Maybe free + malloc will be faster.
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
        log_error("error setting non-blocking mode on the socket.\n");
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



/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

sm_manager *sm_create(ns_nameserver *nameserver, sockhandler_t pmaster, sockhandler_t pworker, int thread_count)
{
    sm_manager *manager = malloc(sizeof(sm_manager));
    manager->sockets = NULL;
    manager->fd_count = 0;

    // Create epoll
    manager->epfd = epoll_create(DEFAULT_EVENTS_COUNT);
    if (manager->epfd == -1) {
        log_error("failed to create epoll set (errno %d): %s.\n", errno, strerror(errno));
        free(manager);
        return NULL;
    }

    // Create master thread
    manager->master = dpt_create(1, pmaster, manager);
    if(manager->master == NULL) {
        perror("sm_create master");
        sm_destroy(&manager);
        return NULL;
    }

    // Create workers
    manager->workers = NULL;
    manager->workers_dpt = NULL;
    if(pworker != NULL) {

        manager->workers = malloc(thread_count * sizeof(sm_worker));
        if (manager->workers == NULL) {
            perror("sm_create workers");
            sm_destroy(&manager);
            return NULL;
        }

        // Create worker dispatcher
        manager->workers_dpt = dpt_create(thread_count, pworker, NULL);
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
                log_error("unable to initialize workers\n");
                sm_destroy(&manager);
                return NULL;
            }

            if (pthread_cond_init(&worker->wakeup, NULL) != 0) {
                log_error("unable to initialize workers\n");
                sm_destroy(&manager);
                return NULL;
            }

            // Assign to worker dispatcher
            manager->workers_dpt->routine_obj[i] = (void*) worker;
        }
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

    // Start workers
    int ret = 0;
    if(manager->workers != NULL)
        ret = dpt_start(manager->workers_dpt);

    // Start master
    return ret + dpt_start(manager->master);
}

void sm_stop( sm_manager *manager )
{
    manager->is_running = 0;
}

int sm_wait( sm_manager* manager )
{
    // Wait for workers
    int ret = 0;
    if(manager->workers != NULL)
        ret = dpt_wait(manager->workers_dpt);

    // Wait for master
    return ret + dpt_wait(manager->master);
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
    // Destroy all sockets
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
    dpt_destroy(&(*manager)->master);
    dpt_destroy(&(*manager)->workers_dpt);

    // Destroy socket list mutex
    pthread_mutex_unlock(&(*manager)->sockets_mutex);
    pthread_mutex_destroy(&(*manager)->sockets_mutex);

    free(*manager);
    *manager = NULL;
}

/*----------------------------------------------------------------------------*/

