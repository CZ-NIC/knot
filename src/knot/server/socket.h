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

#ifndef _KNOT_SOCKET_H_
#define _KNOT_SOCKET_H_

/* POSIX only. */
#include <sys/socket.h>

/*! \brief Socket-related constants. */
enum {
	SOCKET_MTU_SZ = 8192,  /*!< \todo Determine UDP MTU size. */
} socket_const_t;

/*!
 * \brief Create socket.
 *
 * \param family Socket family (PF_INET, PF_IPX, PF_PACKET, PF_UNIX).
 * \param type   Socket type (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW).
 *
 * \retval new socket filedescriptor on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOMEM out of memory error.
 * \retval KNOT_EACCES process does not have appropriate privileges.
 * \retval KNOT_ERROR unspecified error.
 */
int socket_create(int family, int type);

/*!
 * \brief Connect to remote host.
 *
 * \param fd     Socket filedescriptor.
 * \param addr   Requested address.
 * \param port   Requested port.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters.
 * \retval KNOT_EACCES process does not have appropriate privileges.
 * \retval KNOT_EAGAIN lack of resources, try again.
 * \retval KNOT_EADDRINUSE address already in use.
 * \retval KNOT_ECONNREFUSED connection refused.
 * \retval KNOT_EISCONN already connected.
 * \retval KNOT_ERROR unspecified error.
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
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters.
 * \retval KNOT_EACCES process does not have appropriate privileges.
 * \retval KNOT_EADDRINUSE address already in use.
 * \retval KNOT_ENOMEM out of memory error.
 * \retval KNOT_ENOIPV6 IPv6 support is not available.
 * \retval KNOT_ERROR unspecified error.
 */
int socket_bind(int fd, int family, const char *addr, unsigned short port);

/*!
 * \brief Listen on given TCP socket.
 *
 * \param fd           Socket filedescriptor.
 * \param backlog_size Requested TCP backlog size.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EADDRINUSE address already in use.
 * \retval KNOT_ERROR unspecified error.
 */
int socket_listen(int fd, int backlog_size);

/*!
 * \brief Close and deinitialize socket.
 *
 * \param fd Socket filedescriptor.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters.
 */
int socket_close(int fd);

#endif // _KNOT_SOCKET_H_

/*! @} */
