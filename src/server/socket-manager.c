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

sm_manager *sm_create()
{
    sm_manager *manager = malloc(sizeof(sm_manager));

    manager->epfd = epoll_create(DEFAULT_SOCKET_COUNT);

    manager->socket_count = 0;
    manager->max_sockets = DEFAULT_SOCKET_COUNT;
    manager->sockets = malloc(DEFAULT_SOCKET_COUNT * sizeof(int));
    manager->ports = malloc(DEFAULT_SOCKET_COUNT * sizeof(unsigned short));

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

inline int create_socket( sm_manager *manager, unsigned short port ) {
    assert(manager->socket_count != manager->max_sockets);

    manager->sockets[manager->socket_count] =
            socket( AF_INET, SOCK_DGRAM, 0 );

    if (manager->sockets[manager->socket_count] == -1) {
        fprintf(stderr, "ERROR: %d: %s.\n", errno, strerror(errno));
        return -1;
    }

    manager->ports[manager->socket_count] = port;
    ++manager->socket_count;
}

/*----------------------------------------------------------------------------*/

inline int add_socket( sm_manager *manager )
{
    if (manager->socket_count == manager->max_sockets) {
        pthread_mutex_lock(manager->mutex);

        // reallocate to have more place for sockets (twice)
        int *sockets_new = realloc(manager->sockets,
                                   (manager->max_sockets * 2) * sizeof(int));
        if (sockets_new == NULL) {
            fprintf("add_socket(): Allocation failed.\n");
            return -1;
        }

        // TODO initialize the allocated space (to -1?)

        // reallocate place for ports as well
        int *ports_new = realloc(manager->ports,
                                 (manager->max_sockets * 2)
                                 * sizeof(unsigned short));
        if (ports_new == NULL) {
            fprintf(stderr, "add_socket(): Allocation failed.\n");
            free(sockets_new);
            return -1;
        }

        // reallocate place for events as well
        struct epoll_event *events_new = realloc(manager->events,
                                                 (manager->max_sockets * 2)
                                                 * sizeof(struct epoll_event));

        assert((manager->max_sockets * 2) - manager->socket_count
               == manager->socket_count);

        // initialize new array items to 0
        memset(&ports_new[manager->socket_count], 0, manager->socket_count);

        manager->sockets = sockets_new;
        manager->ports = ports_new;
        manager->max_sockets *= 2;

        pthread_mutex_unlock(manager->mutex);
    }

    create_socket(manager);
}

/*----------------------------------------------------------------------------*/

int sm_open_socket( sm_manager *manager, unsigned short port )
{
    int res = add_socket(manager);

    if (res != 0) {
        return res;
    }

    int i = manager->socket_count - 1;

    // Set non-blocking mode on the socket
    // TODO: lock the socket
    int old_flag = fcntl(manager->sockets[i], F_GETFL, 0);
    if (fcntl(manager->sockets[i], F_SETFL, old_flag | O_NONBLOCK) == -1) {
        //err(1, "fcntl");
        fprintf(stderr, "sm_open_socket(): Error setting non-blocking mode on "
                "the socket.\n");

        // cleanup
        manager->sockets[i] = -1;
        manager->ports[i] = -1;
        --manager->socket_count;

        return -1;
    }

    struct sockaddr_in addr;

    //printf("Creating socket for listen on port %hu.\n", port);

    addr.sin_family = AF_INET;
    addr.sin_port = htons( port );
    addr.sin_addr.s_addr = htonl( INADDR_ANY );

    int res = bind(manager->sockets[i], (struct sockaddr *)&addr, sizeof(addr));
    if (res == -1) {
        printf( "ERROR: %d: %s.\n", errno, strerror(errno) );

        // cleanup
        manager->sockets[i] = -1;
        manager->ports[i] = -1;
        --manager->socket_count;

        return -1;
    }

    // TODO: what are the other events for??
    manager->events[i].events = EPOLLIN /*| EPOLLPRI | EPOLLERR | EPOLLHUP*/;
    manager->events[i].data.fd = manager->sockets[i];
    if ((res = epoll_ctl(manager->epfd, EPOLL_CTL_ADD, manager->socket,
                         &manager->event))
        != 0) {
        printf( "ERROR: %d: %s.\n", errno, strerror(errno) );
        free(manager);
        manager = NULL;
        return NULL;
    }
}

/*----------------------------------------------------------------------------*/

<<<<<<< Updated upstream:src/server/socket-manager.c
    manager->nameserver = nameserver;
=======
int sm_close_socket( sm_manager *manager, unsigned short port )
{
>>>>>>> Stashed changes:src/socket-manager.c

}

/*----------------------------------------------------------------------------*/

void sm_destroy( sm_manager **manager )
{
    close((*manager)->socket);
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
        int nfds = epoll_wait(manager->epfd, &manager->event, 1, -1);
        if (nfds < 0)
            err(1, "epoll_wait");

        // for each ready socket
        for(i = 0; i < nfds; i++) {
            //printf("locking mutex from thread %ld\n", pthread_self());
            pthread_mutex_lock(&manager->mutex);
            fd = manager->event.data.fd;

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
