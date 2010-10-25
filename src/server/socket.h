/*!
  * \file socket.h
  *
  * Generic sockets APIs.
  */

#ifndef SOCKET_H
#define SOCKET_H
#include "common.h"

typedef enum {
    SOCKET_BUFF_SIZE = 8192,  /// \todo <= MTU size
    DEFAULT_EVENTS_COUNT = 1,
} socket_const_t;

typedef enum {
    UDP = 0x01,
    TCP = 0x02,
} socktype_t;

/*----------------------------------------------------------------------------*/

/** Socket descriptor item.
  *
  * Used only for state-keeping on master sockets.
  */
typedef struct socket_t {
    int socket;
    unsigned short port;
    socktype_t type;
    struct socket_t *next;
} socket_t;

/** Create and initialize socket.
  * \param port Socket port.
  * \param type Socket type (TCP|UDP).
  * \return instance or NULL
  */
socket_t* socket_create( unsigned short port, socktype_t type );

/** Listen on given socket.
  * \param socket Given socket instance.
  * \param addr Socket address.
  * \return >=0 If successful, negative integer on failure.
  */
int socket_listen(socket_t* socket, const char* addr);

/** Close and deinitialize socket.
  * \param socket Socket instance.
  * \return >=0 If successful, negative integer on failure.
  */
int socket_remove( socket_t* socket );

/** Create fd for polling.
  * \param events_count Initial events count.
  * \return >=0 If successful, negative integer on failure.
  */
int socket_create_pollfd(int events_count);

/** Add socket to poll set.
  * \param epfd Poll set fd.
  * \param socket Given socket.
  * \param events Poll flags.
  * \return >=0 If successful, negative integer on failure.
  */
int socket_register_poll( int epfd, int socket, uint32_t events);

/** Remove socket from poll set.
  * \param epfd Poll set fd.
  * \param socket Given socket.
  * \return >=0 If successful, negative integer on failure.
  */
int socket_unregister_poll( int epfd, int socket );

#endif
