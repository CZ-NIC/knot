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

int sm_worker_init(sm_worker* worker, int id, sm_manager* manager)
{
    // Create epoll
    worker->epfd = epoll_create(DEFAULT_EVENTS_COUNT);
    if (worker->epfd == -1) {
        return -1;
    }

    // Alloc backing store
    worker->events = malloc(DEFAULT_EVENTS_COUNT * sizeof(struct epoll_event));
    if (worker->events == NULL) {
        return -1;
    }

    // Initialize worker data
    worker->id = id;
    worker->events_count = 0;
    worker->events_size = DEFAULT_EVENTS_COUNT;
    worker->mgr = manager;

    // Initialize synchronisation
    if (pthread_mutex_init(&worker->mutex, NULL) != 0) {
        return -1;
    }
    if (pthread_cond_init(&worker->wakeup, NULL) != 0) {
        return -1;
    }

    return 0;
}

int sm_worker_deinit(sm_worker* worker)
{
    if(worker == NULL)
        return -1;

    close(worker->epfd);

    if(worker->events != NULL)
        free(worker->events);

    pthread_mutex_destroy(&worker->mutex);
    pthread_cond_destroy(&worker->wakeup);

    return 0;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

sm_manager *sm_create(ns_nameserver *nameserver, sockhandler_t pmaster, sockhandler_t pworker, int thread_count)
{
    sm_manager *manager = malloc(sizeof(sm_manager));
    manager->sockets = NULL;

    // Create master thread
    manager->master_dpt = dpt_create(1, pmaster, manager);
    if(manager->master_dpt == NULL) {
        log_error("failed to create master thread (errno %d): %s.\n", errno, strerror(errno));
        sm_destroy(&manager);
        return NULL;
    }

    // Create workers
    manager->workers = NULL;
    manager->workers_dpt = NULL;
    if(pworker != NULL) {

        manager->workers = malloc(thread_count * sizeof(sm_worker));
        if (manager->workers == NULL) {
            log_error("failed to alloc workers (errno %d): %s.\n", errno, strerror(errno));
            sm_destroy(&manager);
            return NULL;
        }

        // Create worker dispatcher
        manager->workers_dpt = dpt_create(thread_count, pworker, NULL);
        if(manager->workers_dpt == NULL) {
            log_error("failed to create workers dispatcher (errno %d): %s.\n", errno, strerror(errno));
            sm_destroy(&manager);
            return NULL;
        }

        // Initialize workers
        memset(manager->workers, 0, thread_count * sizeof(sm_worker));
        for(int i = 0; i < thread_count; ++i) {
            sm_worker *worker = &manager->workers[i];
            if(sm_worker_init(worker, i, manager) < 0) {
                log_error("failed to initialize workers (errno %d): %s.\n", errno, strerror(errno));
                sm_destroy(&manager);
                return NULL;
            }

            // Assign to worker dispatcher
            manager->workers_dpt->routine_obj[i] = (void*) worker;
        }
    }

    // Initialize master
    sm_worker_init(&manager->master, 0, manager);

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
    return ret + dpt_start(manager->master_dpt);
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
    return ret + dpt_wait(manager->master_dpt);
}

/*----------------------------------------------------------------------------*/

int sm_open( sm_manager *manager, unsigned short port, socket_t type )
{
    // Create socket
    sm_worker* master = &manager->master;
    sm_socket *socket_new = sm_create_socket(port, type);
    if (socket_new == NULL) {
        return -1;
    }

    // Initialize socket address
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

    // Bind to specified address
    int res = bind(socket_new->socket, (struct sockaddr *)&addr, sizeof(addr));
    if (res == -1) {
        log_error("cannot bind socket (errno %d): %s.\n", errno, strerror(errno));
        close(socket_new->socket);
        free(socket_new);
        return -1;
    }

    // TCP needs listen
    if(type == TCP) {
        res = listen(socket_new->socket, 5); /// \todo Tweak backlog size.
        if (res == -1) {
            close(socket_new->socket);
            free(socket_new);
            return -1;
        }
    }

    // If everything went well, connect the socket to the list
    pthread_mutex_lock(&master->mutex);
    socket_new->next = manager->sockets;
    manager->sockets = socket_new;

    // Register socket to epoll
    /// \todo Edge-Triggered mode.
    if (sm_add_event(master->epfd, socket_new->socket, EPOLLIN) != 0) {
        sm_close(manager, port);
        pthread_mutex_unlock(&master->mutex);
        return -1;
    } else {
        ++master->events_count;
    }

    pthread_mutex_unlock(&master->mutex);
    return 0;
}

/*----------------------------------------------------------------------------*/

int sm_close( sm_manager *manager, unsigned short port )
{   
    // Synchronise to prevent list corruption
    sm_worker* master = &manager->master;
    pthread_mutex_lock(&master->mutex);
    sm_socket *s = manager->sockets, *p = NULL;
    while (s != NULL && s->port != port) {
        p = s;
        s = s->next;
    }
    
    if (s == NULL) {
        pthread_mutex_unlock(&master->mutex);
        return -1;
    }
    
    assert(s->port == port);

    // Unregister from epoll
    if(sm_remove_event(master->epfd, s->socket) == 0) {
        --master->events_count;
    }

    // Disconnect the found socket entry
    if(p != NULL) {
        p->next = s->next;
    }

    free(s);

    // Cleanup on last entry
    if(p == NULL) {
        manager->sockets = NULL;
    }
    pthread_mutex_unlock(&master->mutex);
    
    return 0;
}

/*----------------------------------------------------------------------------*/

void sm_destroy( sm_manager **manager )
{
    // Destroy all sockets
    sm_worker* master = &(*manager)->master;
    while((*manager)->sockets != NULL) {
        sm_close(*manager, (*manager)->sockets->port);
    }

    // Close epoll
    pthread_mutex_lock(&master->mutex);
    close(master->epfd);

    // Destroy workers
    for(int i = 0; i < (*manager)->workers_dpt->thread_count; ++i) {
        sm_worker* worker = &(*manager)->workers[i];
        sm_worker_deinit(worker);
    }
    free((*manager)->workers);

    // Free dispatchers
    dpt_destroy(&(*manager)->master_dpt);
    dpt_destroy(&(*manager)->workers_dpt);

    // Destroy master mutex
    pthread_mutex_unlock(&master->mutex);
    pthread_mutex_destroy(&master->mutex);

    free(*manager);
    *manager = NULL;
}

/*----------------------------------------------------------------------------*/

int sm_remove_event( int epfd, int socket )
{
    // Compatibility with kernels < 2.6.9, require non-NULL ptr.
    struct epoll_event ev;

    // find socket ptr
    if(epoll_ctl(epfd, EPOLL_CTL_DEL, socket, &ev) != 0) {
        perror ("epoll_ctl");
        return -1;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/

int sm_add_event( int epfd, int socket, uint32_t events )
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
