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

const uint SOCKET_BUFF_SIZE = 4096;
const uint DEFAULT_SOCKET_COUNT = 1;

/*----------------------------------------------------------------------------*/

sm_manager *sm_create( ns_nameserver *nameserver )
{
    sm_manager *manager = malloc(sizeof(sm_manager));

    // create epoll
    manager->epfd = epoll_create(DEFAULT_SOCKET_COUNT);

    //manager->socket_count = 0;
//    manager->max_sockets = DEFAULT_SOCKET_COUNT;
//    manager->sockets = malloc(DEFAULT_SOCKET_COUNT * sizeof(int));
//    manager->ports = malloc(DEFAULT_SOCKET_COUNT * sizeof(unsigned short));
    manager->sockets = NULL;

    //printf("Creating mutex\n");
    int errval;
    if ((errval = pthread_mutex_init(&manager->mutex, NULL)) != 0) {
        printf( "ERROR: %d: %s.\n", errval, strerror(errval) );
        free(manager);
        manager = NULL;
        return NULL;
    } /*else {
        printf("Successful\n");
    }*/

    manager->nameserver = nameserver;

    return manager;
}

/*----------------------------------------------------------------------------*/

sm_socket *sm_create_socket( sm_manager *manager, unsigned short port ) {
    // create new socket structure
    sm_socket *socket_new = malloc(sizeof(sm_socket));
    if (socket_new == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }

    socket_new->port = port;
    // create new socket
    socket_new->socket = socket( AF_INET, SOCK_DGRAM, 0 );

    if (socket_new->socket == -1) {
        fprintf(stderr, "ERROR: %d: %s.\n", errno, strerror(errno));
        free(socket_new);
        return NULL;
    }

    return socket_new;
}

///*----------------------------------------------------------------------------*/
//
//inline int sm_add_socket( sm_manager *manager )
//{
//    if (manager->socket_count == manager->max_sockets) {
//        pthread_mutex_lock(manager->mutex);
//
//        // reallocate to have more place for sockets (twice)
//        int *sockets_new = realloc(manager->sockets,
//                                   (manager->max_sockets * 2) * sizeof(int));
//        if (sockets_new == NULL) {
//            fprintf("add_socket(): Allocation failed.\n");
//            return -1;
//        }
//
//        // TODO initialize the allocated space (to -1?)
//
//        // reallocate place for ports as well
//        int *ports_new = realloc(manager->ports,
//                                 (manager->max_sockets * 2)
//                                 * sizeof(unsigned short));
//        if (ports_new == NULL) {
//            fprintf(stderr, "add_socket(): Allocation failed.\n");
//            free(sockets_new);
//            return -1;
//        }
//
//        // reallocate place for events as well
//        struct epoll_event *events_new = realloc(manager->events,
//                                                 (manager->max_sockets * 2)
//                                                 * sizeof(struct epoll_event));
//
//        assert((manager->max_sockets * 2) - manager->socket_count
//               == manager->socket_count);
//
//        // initialize new array items to 0
//        memset(&ports_new[manager->socket_count], 0, manager->socket_count);
//
//        manager->sockets = sockets_new;
//        manager->ports = ports_new;0
//        manager->max_sockets *= 2;
//
//        pthread_mutex_unlock(manager->mutex);
//    }
//
//    create_socket(manager);
//}

/*----------------------------------------------------------------------------*/

void sm_destroy_socket( sm_socket **socket )
{
    close((*socket)->socket);   // TODO: can we close the socket like this?
                                // what about non-opened socket?
    free(*socket);
    *socket = NULL;
}

/*----------------------------------------------------------------------------*/

int sm_realloc_events()
{
    // TODO
    return -1;
}

/*----------------------------------------------------------------------------*/

int sm_add_event( sm_manager *manager, int socket, uint32_t events )
{
    // enough space?
    if (manager->events_count == manager->events_max) { // TODO: initialize
        if (sm_realloc_events(manager) != 0) {
            return -1;
        }
    }

    // TODO: lock?
    manager->events[manager->events_count].events = events;
    manager->events[manager->events_count].data.fd = socket;

    if (epoll_ctl(manager->epfd, EPOLL_CTL_ADD, socket,
                         &manager->events[manager->events_count])!= 0) {
        printf( "ERROR: %d: %s.\n", errno, strerror(errno) );
        // TODO: some cleanup??
        return -1;
    }

    ++manager->events_count;
    return 0;
}

/*----------------------------------------------------------------------------*/

int sm_open_socket( sm_manager *manager, unsigned short port )
{
    sm_socket *socket_new = sm_create_socket(manager, port);

    if (socket_new == NULL) {
        return -1;
    }

    // Set non-blocking mode on the socket
    // TODO: lock the socket
    int old_flag = fcntl(socket_new->socket, F_GETFL, 0);
    if (fcntl(socket_new->socket, F_SETFL, old_flag | O_NONBLOCK) == -1) {
        //err(1, "fcntl");
        fprintf(stderr, "sm_open_socket(): Error setting non-blocking mode on "
                "the socket.\n");
        // cleanup
        sm_destroy_socket(&socket_new);  // TODO
        return -1;
    }

    struct sockaddr_in addr;

    //printf("Creating socket for listen on port %hu.\n", port);

    addr.sin_family = AF_INET;
    addr.sin_port = htons( port );
    addr.sin_addr.s_addr = htonl( INADDR_ANY );

    int res = bind(socket_new->socket, (struct sockaddr *)&addr, sizeof(addr));
    if (res == -1) {
        printf( "ERROR: %d: %s.\n", errno, strerror(errno) );
        // cleanup
        sm_destroy_socket(&socket_new);  // TODO
        return -1;
    }

    // add new event
    // TODO: what are the other events for??
    if (sm_add_event(manager, socket_new->socket, EPOLLIN
                     /*| EPOLLPRI | EPOLLERR | EPOLLHUP*/) != 0)
    {
        sm_destroy_socket(&socket_new);  // TODO
        return -1;
    }

    // if everything went well, connect the socket to the list
    socket_new->next = manager->sockets;

    // TODO: this should be atomic:
    manager->sockets = socket_new;
    //++manager->socket_count;

    return 0;
}

/*----------------------------------------------------------------------------*/

int sm_close_socket( sm_manager *manager, unsigned short port )
{
    // TODO find the socket entry, close the socket, remove the event
    // and destroy the entry
    return -1;
}

/*----------------------------------------------------------------------------*/

void sm_destroy( sm_manager **manager )
{
    pthread_mutex_lock(&(*manager)->mutex);

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

    // TODO: destroy events


    pthread_mutex_unlock(&(*manager)->mutex);
    // TODO: what if something happens here?
    pthread_mutex_destroy(&(*manager)->mutex);

    free(*manager);
    *manager = NULL;
}

/*----------------------------------------------------------------------------*/

void *sm_listen( void *obj )
{
    sm_manager *manager = (sm_manager *)obj;
    char buf[SOCKET_BUFF_SIZE];
    struct sockaddr_in faddr;
    int addrsize = sizeof(faddr);
    int n, i ,fd;
    char answer[SOCKET_BUFF_SIZE];
    uint answer_size;

    while (1) {
        int nfds = epoll_wait(manager->epfd, manager->events,
                              manager->events_count, -1);
        if (nfds < 0)
            err(1, "epoll_wait");

        // for each ready socket
        for(i = 0; i < nfds; i++) {
            //printf("locking mutex from thread %ld\n", pthread_self());
            pthread_mutex_lock(&manager->mutex);
            fd = manager->events[i].data.fd;

            if ((n = recvfrom(fd, buf, SOCKET_BUFF_SIZE, 0,
                              (struct sockaddr *)&faddr,
                             (socklen_t *)&addrsize)) > 0) {

#ifdef SM_DEBUG
                printf("Received %d bytes.\n", n);
#endif

                //printf("unlocking mutex from thread %ld\n", pthread_self());
                pthread_mutex_unlock(&manager->mutex);

                answer_size = SOCKET_BUFF_SIZE;
                int res = ns_answer_request(manager->nameserver, buf, n, answer,
                                  &answer_size);

#ifdef SM_DEBUG
                printf("Got answer of size %d.\n", answer_size);
#endif

                if (res == 0) {
                    assert(answer_size > 0);
#ifdef SM_DEBUG
                    printf("Answer wire format (size %u):\n", answer_size);
                    hex_print(answer, answer_size);
#endif

                    int sent = sendto(fd, answer, answer_size, MSG_DONTWAIT,
                                      (struct sockaddr *)&faddr,
                                      (socklen_t)addrsize);

                    if (sent < 0) {
                        const int error = errno;
                        printf( "Error sending: %d, %s.\n", error, strerror(error) );
                    }
                }
            } else {
                pthread_mutex_unlock(&manager->mutex);
            }
        }
    }

}
