/*!
  * \file socket.h
  * \date 1.11.2010
  * \author Marek Vavrusa <marek.vavrusa@nic.cz>
  * \group Server
  *
  * \brief Generic sockets APIs.
  *
  * This file provides platform-independent sockets.
  * Functions work on sockets created via system socket(2) functions.
  */

#ifndef CUTE_SOCKET_H
#define CUTE_SOCKET_H
#include "common.h"

/* POSIX only. */
#include <sys/socket.h>

/*! \brief Socket-related constants. */
enum {
    SOCKET_MTU_SZ = 8192,  //!< \todo <= Determine UDP MTU size.
} socket_const_t;

/*!
 *  \brief Listen on given socket.
 *
 *  \param socket Socket filedescriptor.
 *  \param addr Requested address.
 *  \param port Requested port.
 *  \return On success: 0, on failure: <0.
 */
int socket_bind( int socket, const char* addr, unsigned short port );

/*!
 *  \brief Listen on given TCP socket.
 *
 *  \param socket Socket filedescriptor.
 *  \param backlog_size Requested TCP backlog size.
 *  \return On success: 0, on failure: <0.
 */
int socket_listen( int socket, int backlog_size );

/*!
 *  \brief Close and deinitialize socket.
 *
 *  \param socket Socket filedescriptor.
 *  \return On success: 0, on failure: <0.
 */
int socket_close( int socket );

/*!
 *  \brief Create fd for polling.
 *
 *  \deprecated Use libevent http://monkey.org/~provos/libevent/
 *
 *  \param events_count Initial events backing store size.
 *  \return On success: 0, on failure: <0.
 */
int socket_poll_create( int events_count );

/*!
 *  \brief Add socket to poll set.
 *
 *  \deprecated Use libevent http://monkey.org/~provos/libevent/
 *
 *  \param epfd Poll set filedescriptor.
 *  \param socket Socket waiting to be added to set.
 *  \param events Requested poll flags.
 *  \return On success: 0, on failure: <0.
 */
int socket_poll_add( int epfd, int socket, uint32_t events );

/*!
 *  \brief Remove socket from poll set.
 *
 *  \deprecated Use libevent http://monkey.org/~provos/libevent/
 *
 *  \param epfd Poll set filedescriptor.
 *  \param socket Socket waiting to be removed from set.
 *  \return On success: 0, on failure: <0.
 */
int socket_poll_remove( int epfd, int socket );

#endif
