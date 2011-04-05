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
 * \retval <0 If an error occured (EACCES, EINVAL, ENOMEM).
 */
int socket_create(int family, int type);

/*!
 * \brief Connect to remote host.
 *
 * \param fd     Socket filedescriptor.
 * \param addr   Requested address.
 * \param port   Requested port.
 *
 * \retval  0 On success (EOK).
 * \retval <0 If an error occured (EADDRINVAL, EACCES, EADDRINUSE, EAGAIN,
 *                                 ECONNREFUSED, EISCONN).
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
 * \retval  0 On success (EOK).
 * \retval <0 If an error occured (EINVAL, EADDRINVAL, EADDRINUSE,
 *                                 EACCES, ENOMEM, ENOIPV6).
 */
int socket_bind(int fd, int family, const char *addr, unsigned short port);

/*!
 * \brief Listen on given TCP socket.
 *
 * \param fd           Socket filedescriptor.
 * \param backlog_size Requested TCP backlog size.
 *
 * \retval  0 On success (EOK).
 * \retval <0 If an error occured (EADDRINUSE).
 */
int socket_listen(int fd, int backlog_size);

/*!
 * \brief Close and deinitialize socket.
 *
 * \param fd Socket filedescriptor.
 *
 * \retval  0 On success (EOK).
 * \retval <0 If an error occured (EINVAL).
 */
int socket_close(int fd);

#endif // _KNOT_SOCKET_H_

/*! @} */
