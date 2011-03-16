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
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int socket_create(int family, int type);

/*!
 * \brief Connect to remote host.
 *
 * \param fd     Socket filedescriptor.
 * \param addr   Requested address.
 * \param port   Requested port.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
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
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int socket_bind(int fd, int family, const char *addr, unsigned short port);

/*!
 * \brief Listen on given TCP socket.
 *
 * \param fd           Socket filedescriptor.
 * \param backlog_size Requested TCP backlog size.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int socket_listen(int fd, int backlog_size);

/*!
 * \brief Receive data from connection-mode socket.
 *
 * \param fd     Socket filedescriptor.
 * \param buf    Destination buffer.
 * \param len    Maximum data length.
 * \param flags  Additional flags.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
static inline ssize_t socket_recv(int socket, void *buf, size_t len, int flags)
{
	return recv(socket, buf, len, flags);
}

/*!
 * \brief Receive data from datagram-mode socket.
 *
 * \param fd      Socket filedescriptor.
 * \param buf     Destination buffer.
 * \param len     Maximum data length.
 * \param flags   Additional flags.
 * \param from    Datagram source address.
 * \param fromlen Address length.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
static inline ssize_t socket_recvfrom(int socket, void *buf, size_t len,
                                      int flags, struct sockaddr *from,
                                      socklen_t *fromlen)
{
	return recvfrom(socket, buf, len, flags, from, fromlen);
}

/*!
 * \brief Send data to connection-mode socket.
 *
 * \param fd     Socket filedescriptor.
 * \param buf    Source buffer.
 * \param len    Data length.
 * \param flags  Additional flags.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
static inline ssize_t socket_send(int socket, const void *buf, size_t len,
                                  int flags)
{
	return send(socket, buf, len, flags);
}

/*!
 * \brief Send data to datagram-mode socket.
 *
 * \param fd     Socket filedescriptor.
 * \param buf    Source buffer.
 * \param len    Data length.
 * \param flags  Additional flags.
 * \param to     Datagram source address.
 * \param tolen  Address length.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
static inline ssize_t socket_sendto(int socket, const void *buf, size_t len,
                                    int flags, const struct sockaddr *to,
                                    socklen_t tolen)
{
	return sendto(socket, buf, len, flags, to, tolen);
}
/*!
 * \brief Close and deinitialize socket.
 *
 * \param fd Socket filedescriptor.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int socket_close(int fd);

#endif // _KNOT_SOCKET_H_

/*! @} */

