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

socket_t* socket_create( unsigned short port, socktype_t type )
{
    // Create new socket structure
    socket_t *socket_new = malloc(sizeof(socket_t));
    if (socket_new == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }

    socket_new->port = port;

    // create new socket
    socket_new->type = type;
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

int socket_listen(socket_t* socket, const char* addr)
{
   // Check
   if(socket == NULL)
      return -1;

    // Initialize socket address
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons( socket->port );
    saddr.sin_addr.s_addr = inet_addr(addr);
    if(saddr.sin_addr.s_addr == INADDR_NONE) {
       log_error("socket_listen: address %s is invalid, using 0.0.0.0 instead", addr);
       saddr.sin_addr.s_addr = htonl( INADDR_ANY );
    }

     // Reuse old address if taken
     int flag = 1;
     if(setsockopt(socket->socket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
         return -2;
     }

     // Bind to specified address
     int res = bind(socket->socket, (struct sockaddr *)& saddr, sizeof(saddr));
     if (res == -1) {
         log_error("cannot bind socket (errno %d): %s.\n", errno, strerror(errno));
         return -3;
     }

     // TCP needs listen
     if(socket->type & TCP) {
         res = listen(socket->socket, TCP_BACKLOG_SIZE);
         if (res == -1) {
             return -4;
         }
     }

     return 0;
}

int socket_remove( socket_t* socket )
{
   if(socket == NULL)
      return -1;

   close(socket->socket);
   free(socket);
   return 0;
}

int socket_create_pollfd(int events_count)
{
   return epoll_create(events_count);
}

int socket_unregister_poll( int epfd, int socket )
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

int socket_register_poll( int epfd, int socket, uint32_t events )
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
