#include "socket.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int socket_bind( int socket, const char* addr, unsigned short port )
{
    // Initialize socket address
    struct sockaddr_in saddr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    if(getsockname(socket, &saddr, &addrlen) < 0) {
       return -1;
    }

    // Set address and port
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = inet_addr(addr);
    if(saddr.sin_addr.s_addr == INADDR_NONE) {
       log_error("socket_listen: address %s is invalid, using 0.0.0.0 instead", addr);
       saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

     // Reuse old address if taken
     int flag = 1;
     if(setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
         return -2;
     }

     // Bind to specified address
     int res = bind(socket, (struct sockaddr *)& saddr, sizeof(saddr));
     if (res == -1) {
         log_error("cannot bind socket (errno %d): %s.\n", errno, strerror(errno));
         return -3;
     }

     return 0;
}

int socket_listen( int socket, int backlog_size )
{
    return listen(socket, backlog_size);
}

int socket_close( int socket )
{
    return close(socket);
}

int socket_poll_create( int events_count )
{
    return epoll_create(events_count);
}

int socket_poll_remove( int epfd, int socket )
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

int socket_poll_add( int epfd, int socket, uint32_t events )
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
