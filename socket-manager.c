#include "common.h"
#include "socket-manager.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <err.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const uint BUFF_SIZE = 4096;

/*----------------------------------------------------------------------------*/

sm_manager *sm_create( short port, uint thr_count,
                       void (*answer_fnc)( const char *, uint, char *, uint ) )
{
    sm_manager *manager = malloc(sizeof(sm_manager));

    manager->socket = socket( AF_INET, SOCK_DGRAM, 0 );
    if (manager->socket == -1) {
        fprintf(stderr, "ERROR: %d: %s.\n", errno, strerror(errno));
        free(manager);
        return NULL;
    }

    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons( port );
    addr.sin_addr.s_addr = htonl( INADDR_ANY );

    // Set non-blocking mode on the socket
    int old_flag = fcntl(manager->socket, F_GETFL, 0);
    if (fcntl(manager->socket, F_SETFL, old_flag | O_NONBLOCK) == -1) {
        free(manager);
        err(1, "fcntl");
    }

    int res = bind( manager->socket, (struct sockaddr *)&addr, sizeof(addr) );
    if (res == -1) {
        printf( "ERROR: %d: %s.\n", errno, strerror(errno) );
        free(manager);
        return NULL;
    }

    manager->epfd = epoll_create(1);

    manager->event.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
    manager->event.data.fd = manager->socket;
    if ((res = epoll_ctl(manager->epfd, EPOLL_CTL_ADD, manager->socket,
                         &manager->event))
        != 0) {
        printf( "ERROR: %d: %s.\n", errno, strerror(errno) );
        free(manager);
        return NULL;
    }

    //printf("Creating mutex\n");
    int errval;
    if ((errval = pthread_mutex_init(&manager->mutex, NULL)) != 0) {
        printf( "ERROR: %d: %s.\n", errval, strerror(errval) );
        free(manager);
        return NULL;
    } /*else {
        printf("Successful\n");
    }*/

    manager->thread_count = thr_count;
    manager->answer_fnc = answer_fnc;

    return manager;
}

/*----------------------------------------------------------------------------*/

void sm_destroy( sm_manager *manager )
{
    close(manager->socket);
    free(manager);
}

/*----------------------------------------------------------------------------*/

void *sm_listen( void *obj )
{
    sm_manager *manager = (sm_manager *)obj;
    char buf[BUFF_SIZE];
    struct sockaddr_in faddr;
    int addrsize = sizeof(faddr);
    int n, i ,fd;
    char answer[BUFF_SIZE];
    uint answer_size = 0;

    while (1) {
        int nfds = epoll_wait(manager->epfd, &manager->event, 1, -1);
        if (nfds < 0)
            err(1, "epoll_wait");

        // for each ready socket
        for(i = 0; i < nfds; i++) {
            //printf("locking mutex from thread %ld\n", pthread_self());
            pthread_mutex_lock(&manager->mutex);
            fd = manager->event.data.fd;

            if ((n = recvfrom(fd, buf, BUFF_SIZE, 0, (struct sockaddr *)&faddr,
                             (socklen_t *)&addrsize)) > 0) {

                //printf("unlocking mutex from thread %ld\n", pthread_self());
                pthread_mutex_unlock(&manager->mutex);

                manager->answer_fnc(buf, n, answer, answer_size);

                int sent = sendto(fd, answer, answer_size, MSG_DONTWAIT,
                                  (struct sockaddr *)&faddr,
                                  (socklen_t)addrsize);

                if (sent < 0) {
                    const int error = errno;
                    printf( "Error sending: %d, %s.\n", error, strerror(error) );
                }
            } else {
                pthread_mutex_unlock(&manager->mutex);
            }
        }
    }

}

/*----------------------------------------------------------------------------*/

int sm_start( sm_manager *manager )
{
    pthread_t threads[manager->thread_count];

    int i;

    for (i = 0; i < manager->thread_count; ++i)
    {
        if (pthread_create(&threads[i], NULL, sm_listen, (void *)manager))
        {
            printf( "ERROR CREATING THREAD %d", i );
            return -1;
        }
    }
    for (i = 0; i < manager->thread_count; ++i)
    {
        if ( pthread_join( threads[i], NULL ) )
        {
            printf( "ERROR JOINING THREAD %d", i );
            return -1;
        }
    }

    return 0;
}
