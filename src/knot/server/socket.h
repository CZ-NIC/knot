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

#ifndef _KNOTD_SOCKET_H_
#define _KNOTD_SOCKET_H_

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
 * \retval KNOTD_EINVAL on invalid parameters.
 * \retval KNOTD_ENOMEM out of memory error.
 * \retval KNOTD_EACCES process does not have appropriate privileges.
 * \retval KNOTD_ERROR unspecified error.
 */
int socket_create(int family, int type);

/*!
 * \brief Connect to remote host.
 *
 * \param fd     Socket filedescriptor.
 * \param addr   Requested address.
 * \param port   Requested port.
 *
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_EINVAL invalid parameters.
 * \retval KNOTD_EACCES process does not have appropriate privileges.
 * \retval KNOTD_EAGAIN lack of resources, try again.
 * \retval KNOTD_EADDRINUSE address already in use.
 * \retval KNOTD_ECONNREFUSED connection refused.
 * \retval KNOTD_EISCONN already connected.
 * \retval KNOTD_ERROR unspecified error.
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
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_EINVAL invalid parameters.
 * \retval KNOTD_EACCES process does not have appropriate privileges.
 * \retval KNOTD_EADDRINUSE address already in use.
 * \retval KNOTD_ENOMEM out of memory error.
 * \retval KNOTD_ENOIPV6 IPv6 support is not available.
 * \retval KNOTD_ERROR unspecified error.
 */
int socket_bind(int fd, int family, const char *addr, unsigned short port);

/*!
 * \brief Listen on given TCP socket.
 *
 * \param fd           Socket filedescriptor.
 * \param backlog_size Requested TCP backlog size.
 *
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_EADDRINUSE address already in use.
 * \retval KNOTD_ERROR unspecified error.
 */
int socket_listen(int fd, int backlog_size);

/*!
 * \brief Close and deinitialize socket.
 *
 * \param fd Socket filedescriptor.
 *
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_EINVAL invalid parameters.
 */
int socket_close(int fd);


#endif // _KNOTD_SOCKET_H_

/*! @} */
