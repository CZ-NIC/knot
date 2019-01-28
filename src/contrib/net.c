/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "libknot/errcode.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"

/*
 * OS X doesn't support MSG_NOSIGNAL. Use SO_NOSIGPIPE socket option instead.
 */
#if defined(__APPLE__) && !defined(MSG_NOSIGNAL)
#  define MSG_NOSIGNAL 0
#  define osx_block_sigpipe(sock) sockopt_enable(sock, SOL_SOCKET, SO_NOSIGPIPE)
#else
#  define osx_block_sigpipe(sock) KNOT_EOK
#endif

/*!
 * \brief Enable socket option.
 */
static int sockopt_enable(int sock, int level, int optname)
{
	const int enable = 1;
	if (setsockopt(sock, level, optname, &enable, sizeof(enable)) != 0) {
		return knot_map_errno();
	}

	return KNOT_EOK;
}

/*!
 * \brief Create a non-blocking socket.
 *
 * Prefer SOCK_NONBLOCK if available to save one fcntl() syscall.
 *
 */
static int socket_create(int family, int type, int proto)
{
#ifdef SOCK_NONBLOCK
	type |= SOCK_NONBLOCK;
#endif
	int sock = socket(family, type, proto);
	if (sock < 0) {
		return knot_map_errno();
	}

#ifndef SOCK_NONBLOCK
	if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
		int ret = knot_map_errno();
		close(sock);
		return ret;
	}
#endif

	int ret = osx_block_sigpipe(sock);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return sock;
}

int net_unbound_socket(int type, const struct sockaddr *sa)
{
	if (sa == NULL) {
		return KNOT_EINVAL;
	}

	/* Create socket. */
	return socket_create(sa->sa_family, type, 0);
}

struct option {
	int level;
	int name;
};

/*!
 * \brief Get setsock option for binding non-local address.
 */
static const struct option *nonlocal_option(int family)
{
	static const struct option ipv4 = {
		#if defined(IP_FREEBIND)
			IPPROTO_IP, IP_FREEBIND
		#elif defined(IP_BINDANY)
			IPPROTO_IP, IP_BINDANY
		#else
			0, 0
		#endif
	};

	static const struct option ipv6 = {
		#if defined(IP_FREEBIND)
			IPPROTO_IP, IP_FREEBIND
		#elif defined(IPV6_BINDANY)
			IPPROTO_IPV6, IPV6_BINDANY
		#else
			0, 0
		#endif

	};

	switch (family) {
	case AF_INET:  return &ipv4;
	case AF_INET6: return &ipv6;
	default:
		return NULL;
	}
}

static int enable_nonlocal(int sock, int family)
{
	const struct option *opt = nonlocal_option(family);
	if (opt == NULL || opt->name == 0) {
		return KNOT_ENOTSUP;
	}

	return sockopt_enable(sock, opt->level, opt->name);
}

static int enable_reuseport(int sock)
{
#ifdef ENABLE_REUSEPORT
#  if defined(__FreeBSD__)
	return sockopt_enable(sock, SOL_SOCKET, SO_REUSEPORT_LB);
#  else
	return sockopt_enable(sock, SOL_SOCKET, SO_REUSEPORT);
#  endif
#else
	return KNOT_ENOTSUP;
#endif
}

static void unlink_unix_socket(const struct sockaddr *addr)
{
	char path[SOCKADDR_STRLEN] = { 0 };
	sockaddr_tostr(path, sizeof(path), addr);
	unlink(path);
}

int net_bound_socket(int type, const struct sockaddr *sa, enum net_flags flags)
{
	/* Create socket. */
	int sock = net_unbound_socket(type, sa);
	if (sock < 0) {
		return sock;
	}

	/* Unlink UNIX sock if exists. */
	if (sa->sa_family == AF_UNIX) {
		unlink_unix_socket(sa);
	}

	/* Reuse old address if taken. */
	int ret = sockopt_enable(sock, SOL_SOCKET, SO_REUSEADDR);
	if (ret != KNOT_EOK) {
		close(sock);
		return ret;
	}

	/* Don't bind IPv4 for IPv6 any address. */
	if (sa->sa_family == AF_INET6) {
		ret = sockopt_enable(sock, IPPROTO_IPV6, IPV6_V6ONLY);
		if (ret != KNOT_EOK) {
			close(sock);
			return ret;
		}
	}

	/* Allow bind to non-local address. */
	if (flags & NET_BIND_NONLOCAL) {
		ret = enable_nonlocal(sock, sa->sa_family);
		if (ret != KNOT_EOK) {
			close(sock);
			return ret;
		}
	}

	/* Allow to bind the same address by multiple threads. */
	if (flags & NET_BIND_MULTIPLE) {
		ret = enable_reuseport(sock);
		if (ret != KNOT_EOK) {
			close(sock);
			return ret;
		}
	}

	/* Bind to specified address. */
	ret = bind(sock, sa, sockaddr_len(sa));
	if (ret < 0) {
		ret = knot_map_errno();
		close(sock);
		return ret;
	}

	return sock;
}

int net_connected_socket(int type, const struct sockaddr *dst_addr,
                         const struct sockaddr *src_addr)
{
	if (dst_addr == NULL) {
		return KNOT_EINVAL;
	}

	/* Check port. */
	if (sockaddr_port(dst_addr) == 0) {
		return KNOT_NET_EADDR;
	}

	/* Bind to specific source address - if set. */
	int sock = -1;
	if (src_addr && src_addr->sa_family != AF_UNSPEC) {
		sock = net_bound_socket(type, src_addr, 0);
	} else {
		sock = net_unbound_socket(type, dst_addr);
	}
	if (sock < 0) {
		return sock;
	}

	/* Connect to destination. */
	const struct sockaddr *sa = (const struct sockaddr *)dst_addr;
	int ret = connect(sock, sa, sockaddr_len(sa));
	if (ret != 0 && errno != EINPROGRESS) {
		ret = knot_map_errno();
		close(sock);
		return ret;
	}

	return sock;
}

bool net_is_connected(int sock)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	return (getpeername(sock, (struct sockaddr *)&ss, &len) == 0);
}

int net_socktype(int sock)
{
	int type;
	socklen_t size = sizeof(type);

	if (getsockopt(sock, SOL_SOCKET, SO_TYPE, &type, &size) == 0) {
		return type;
	} else {
		return AF_UNSPEC;
	}
}

bool net_is_stream(int sock)
{
	return net_socktype(sock) == SOCK_STREAM;
}

int net_accept(int sock, struct sockaddr_storage *addr)
{
	socklen_t sa_len = sizeof(*addr);

	int remote = -1;

#if defined(HAVE_ACCEPT4) && defined(SOCK_NONBLOCK)
	remote = accept4(sock, (struct sockaddr *)addr, &sa_len, SOCK_NONBLOCK);
	if (remote < 0) {
		return knot_map_errno();
	}
#else
	remote = accept(sock, (struct sockaddr *)addr, &sa_len);
	if (fcntl(remote, F_SETFL, O_NONBLOCK) != 0) {
		int error = knot_map_errno();
		close(remote);
		return error;
	}
#endif

	return remote;
}

/* -- I/O interface handling partial  -------------------------------------- */

/*!
 * \brief Perform \a poll() on one socket.
 */
static int poll_one(int fd, int events, int timeout_ms)
{
	struct pollfd pfd = {
		.fd = fd,
		.events = events
	};

	return poll(&pfd, 1, timeout_ms);
}

/*!
 * \brief Check if we should wait for I/O readiness.
 *
 * \param error  \a errno set by the failed I/O operation.
 */
static bool io_should_wait(int error)
{
	/* socket data not ready */
	if (error == EAGAIN || error == EWOULDBLOCK) {
		return true;
	}

#ifndef __linux__
	/* FreeBSD: connection in progress */
	if (error == ENOTCONN) {
		return true;
	}
#endif

	return false;
}

/*!
 * \brief I/O operation callbacks.
 */
struct io {
	ssize_t (*process)(int sockfd, struct msghdr *msg);
	int (*wait)(int sockfd, int timeout_ms);
};

/*!
 * \brief Get total size of I/O vector in a message.
 */
static size_t msg_iov_len(const struct msghdr *msg)
{
	size_t total = 0;

	for (int i = 0; i < msg->msg_iovlen; i++) {
		total += msg->msg_iov[i].iov_len;
	}

	return total;
}

/*!
 * \brief Shift processed data out of message IO vectors.
 */
static void msg_iov_shift(struct msghdr *msg, size_t done)
{
	struct iovec *iov = msg->msg_iov;
	int iovlen = msg->msg_iovlen;

	for (int i = 0; i < iovlen && done > 0; i++) {
		if (iov[i].iov_len > done) {
			iov[i].iov_base += done;
			iov[i].iov_len -= done;
			done = 0;
		} else {
			done -= iov[i].iov_len;
			msg->msg_iov += 1;
			msg->msg_iovlen -= 1;
		}
	}

	assert(done == 0);
}

/*!
 * \brief Perform an I/O operation with a socket with waiting.
 *
 * \param oneshot  If set, doesn't wait until the buffer is fully processed.
 *
 */
static ssize_t io_exec(const struct io *io, int fd, struct msghdr *msg,
                       bool oneshot, int timeout_ms)
{
	size_t done = 0;
	size_t total = msg_iov_len(msg);

	for (;;) {
		/* Perform I/O. */
		ssize_t ret = io->process(fd, msg);
		if (ret == -1 && errno == EINTR) {
			continue;
		}
		if (ret > 0) {
			done += ret;
			if (oneshot || done == total) {
				break;
			}
			msg_iov_shift(msg, ret);
		}

		/* Wait for data readiness. */
		if (ret > 0 || (ret == -1 && io_should_wait(errno))) {
			do {
				ret = io->wait(fd, timeout_ms);
			} while (ret == -1 && errno == EINTR);
			if (ret == 1) {
				continue;
			} else if (ret == 0) {
				return KNOT_ETIMEOUT;
			}
		}

		/* Disconnected or error. */
		return KNOT_ECONN;
	}

	return done;
}

static ssize_t recv_process(int fd, struct msghdr *msg)
{
	return recvmsg(fd, msg, MSG_DONTWAIT | MSG_NOSIGNAL);
}

static int recv_wait(int fd, int timeout_ms)
{
	return poll_one(fd, POLLIN, timeout_ms);
}

static ssize_t recv_data(int sock, struct msghdr *msg, bool oneshot, int timeout_ms)
{
	static const struct io RECV_IO = {
		.process = recv_process,
		.wait = recv_wait
	};

	return io_exec(&RECV_IO, sock, msg, oneshot, timeout_ms);
}

static ssize_t send_process(int fd, struct msghdr *msg)
{
	return sendmsg(fd, msg, MSG_NOSIGNAL);
}

static int send_wait(int fd, int timeout_ms)
{
	return poll_one(fd, POLLOUT, timeout_ms);
}

static ssize_t send_data(int sock, struct msghdr *msg, int timeout_ms)
{
	static const struct io SEND_IO = {
		.process = send_process,
		.wait = send_wait
	};

	return io_exec(&SEND_IO, sock, msg, false, timeout_ms);
}

/* -- generic stream and datagram I/O -------------------------------------- */

ssize_t net_send(int sock, const uint8_t *buffer, size_t size,
                 const struct sockaddr *addr, int timeout_ms)
{
	if (sock < 0 || buffer == NULL) {
		return KNOT_EINVAL;
	}

	struct iovec iov = { 0 };
	iov.iov_base = (void *)buffer;
	iov.iov_len = size;

	struct msghdr msg = { 0 };
	msg.msg_name = (void *)addr;
	msg.msg_namelen = sockaddr_len(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	int ret = send_data(sock, &msg, timeout_ms);
	if (ret < 0) {
		return ret;
	} else if (ret != size) {
		return KNOT_ECONN;
	}

	return ret;
}

ssize_t net_recv(int sock, uint8_t *buffer, size_t size,
                 struct sockaddr_storage *addr, int timeout_ms)
{
	if (sock < 0 || buffer == NULL) {
		return KNOT_EINVAL;
	}

	struct iovec iov = { 0 };
	iov.iov_base = buffer;
	iov.iov_len = size;

	struct msghdr msg = { 0 };
	msg.msg_name = (void *)addr;
	msg.msg_namelen = addr ? sizeof(*addr) : 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return recv_data(sock, &msg, true, timeout_ms);
}

ssize_t net_dgram_send(int sock, const uint8_t *buffer, size_t size,
                       const struct sockaddr *addr)
{
	return net_send(sock, buffer, size, addr, 0);
}

ssize_t net_dgram_recv(int sock, uint8_t *buffer, size_t size, int timeout_ms)
{
	return net_recv(sock, buffer, size, NULL, timeout_ms);
}

ssize_t net_stream_send(int sock, const uint8_t *buffer, size_t size, int timeout_ms)
{
	return net_send(sock, buffer, size, NULL, timeout_ms);
}

ssize_t net_stream_recv(int sock, uint8_t *buffer, size_t size, int timeout_ms)
{
	return net_recv(sock, buffer, size, NULL, timeout_ms);
}

/* -- DNS specific I/O ----------------------------------------------------- */

ssize_t net_dns_tcp_send(int sock, const uint8_t *buffer, size_t size, int timeout_ms)
{
	if (sock < 0 || buffer == NULL || size > UINT16_MAX) {
		return KNOT_EINVAL;
	}

	struct iovec iov[2];
	uint16_t pktsize = htons(size);
	iov[0].iov_base = &pktsize;
	iov[0].iov_len = sizeof(uint16_t);
	iov[1].iov_base = (void *)buffer;
	iov[1].iov_len = size;

	struct msghdr msg = { 0 };
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	ssize_t ret = send_data(sock, &msg, timeout_ms);
	if (ret < 0) {
		return ret;
	}

	return size; /* Do not count the size prefix. */
}

ssize_t net_dns_tcp_recv(int sock, uint8_t *buffer, size_t size, int timeout_ms)
{
	if (sock < 0 || buffer == NULL) {
		return KNOT_EINVAL;
	}

	struct iovec iov = { 0 };
	struct msghdr msg = { 0 };
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* Receive size. */
	uint16_t pktsize = 0;
	iov.iov_base = &pktsize;
	iov.iov_len = sizeof(pktsize);
	int ret = recv_data(sock, &msg, false, timeout_ms);
	if (ret != sizeof(pktsize)) {
		return ret;
	}

	pktsize = ntohs(pktsize);

	/* Check packet size */
	if (size < pktsize) {
		return KNOT_ESPACE;
	}

	/* Receive payload. */
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = buffer;
	iov.iov_len = pktsize;
	return recv_data(sock, &msg, false, timeout_ms);
}
