/*!
 * \file socket.h
 *
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief Generic sockets APIs.
 *
 * This file provides platform-independent sockets.
 * Functions work on sockets created via system socket(2) functions.
 *
 * You can use standard I/O functions send(), sendto(), recv(), recvfrom()
 * like you would with a normal sockets.
 *
 * \addtogroup network
 * @{
 */

#ifndef _KNOTDSOCKET_H_
#define _KNOTDSOCKET_H_

/* POSIX only. */
#include <sys/socket.h>
#include "common/sockaddr.h"

/*! \brief Socket-related constants. */
typedef enum {
	SOCKET_MTU_SZ = 8192,  /*!< \todo Determine UDP MTU size. */
} socket_const_t;

/*!
 * \brief Create socket.
 *
 * \param family Socket family (PF_INET, PF_IPX, PF_PACKET, PF_UNIX).
 * \param type   Socket type (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW).
 *
 * \retval new socket filedescriptor on success.
 * \retval KNOTDEINVAL on invalid parameters.
 * \retval KNOTDENOMEM out of memory error.
 * \retval KNOTDEACCES process does not have appropriate privileges.
 * \retval KNOTDERROR unspecified error.
 */
int socket_create(int family, int type);

/*!
 * \brief Connect to remote host.
 *
 * \param fd     Socket filedescriptor.
 * \param addr   Requested address.
 * \param port   Requested port.
 *
 * \retval KNOTDEOK on success.
 * \retval KNOTDEINVAL invalid parameters.
 * \retval KNOTDEACCES process does not have appropriate privileges.
 * \retval KNOTDEAGAIN lack of resources, try again.
 * \retval KNOTDEADDRINUSE address already in use.
 * \retval KNOTDECONNREFUSED connection refused.
 * \retval KNOTDEISCONN already connected.
 * \retval KNOTDERROR unspecified error.
 */
int socket_connect(int fd, const char *addr, unsigned short port);

/*!
 * \brief Listen on given socket.
 *
 * \param fd     Socket filedescriptor.
 * \param family Socket family.
 * \param addr   Requested address.
 * \param port   Requested port.
 *
 * \retval KNOTDEOK on success.
 * \retval KNOTDEINVAL invalid parameters.
 * \retval KNOTDEACCES process does not have appropriate privileges.
 * \retval KNOTDEADDRINUSE address already in use.
 * \retval KNOTDENOMEM out of memory error.
 * \retval KNOTDENOIPV6 IPv6 support is not available.
 * \retval KNOTDERROR unspecified error.
 */
int socket_bind(int fd, int family, const char *addr, unsigned short port);

/*!
 * \brief Listen on given TCP socket.
 *
 * \param fd           Socket filedescriptor.
 * \param backlog_size Requested TCP backlog size.
 *
 * \retval KNOTDEOK on success.
 * \retval KNOTDEADDRINUSE address already in use.
 * \retval KNOTDERROR unspecified error.
 */
int socket_listen(int fd, int backlog_size);

/*!
 * \brief Close and deinitialize socket.
 *
 * \param fd Socket filedescriptor.
 *
 * \retval KNOTDEOK on success.
 * \retval KNOTDEINVAL invalid parameters.
 */
int socket_close(int fd);


#endif // _KNOTDSOCKET_H_

/*! @} */
