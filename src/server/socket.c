#include "socket.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int socket_create( int family, int type )
{
    // Create socket
    int sock = socket(family, type, 0);

    // Reuse open socket
    int on = 1;
    if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                  (const char*)&on, sizeof(on)) < 0) {
        return socket_close(sock);
    }

    return sock;
}

int socket_connect( int socket, const char* addr, unsigned short port )
{
    // Create socket
    struct hostent* hent = gethostbyname(addr);
    if(hent == 0)
        return -1;

    // Prepare host address
    struct sockaddr_in saddr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    memcpy(&saddr.sin_addr, hent->h_addr, hent->h_length);

    // Connect to host
    return connect(socket, (struct sockaddr *)&saddr, addrlen);
}

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
        log_error("socket_listen: address %s is invalid, using 0.0.0.0 instead",
                 addr);
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
         log_error("cannot bind socket (errno %d): %s.\n",
                   errno, strerror(errno));
         return -3;
     }

     return 0;
}

int socket_listen( int socket, int backlog_size )
{
    return listen(socket, backlog_size);
}

ssize_t socket_recv( int socket, void *buf, size_t len, int flags )
{
    return recv(socket, buf, len, flags);
}

ssize_t socket_recvfrom( int socket, void *buf, size_t len, int flags,
                         struct sockaddr *from, socklen_t *fromlen )
{
    return recvfrom(socket, buf, len, flags, from, fromlen);
}

ssize_t socket_send( int socket, const void *buf, size_t len, int flags )
{
    return send(socket, buf, len, flags);
}

ssize_t socket_sendto( int socket, const void *buf, size_t len, int flags,
                      const struct sockaddr *to, socklen_t tolen )
{
    return sendto(socket, buf, len, flags, to, tolen);
}

int socket_close( int socket )
{
    return close(socket);
}
