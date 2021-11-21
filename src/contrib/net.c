/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <sys/types.h>   // OpenBSD
#include <netinet/tcp.h> // TCP_FASTOPEN
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "libknot/errcode.h"
#include "contrib/macros.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"

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

/*
 * OS X doesn't support MSG_NOSIGNAL. Use SO_NOSIGPIPE socket option instead.
 */
#if defined(__APPLE__) && !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
	int ret = sockopt_enable(sock, SOL_SOCKET, SO_NOSIGPIPE);
	if (ret != KNOT_EOK) {
		return ret;
	}
#endif

	return sock;
}

int net_unbound_socket(int type, const struct sockaddr_storage *addr)
{
	if (addr == NULL) {
		return KNOT_EINVAL;
	}

	/* Create socket. */
	return socket_create(addr->ss_family, type, 0);
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

static void unlink_unix_socket(const struct sockaddr_storage *addr)
{
	char path[SOCKADDR_STRLEN] = { 0 };
	sockaddr_tostr(path, sizeof(path), addr);
	unlink(path);
}

int net_bound_socket(int type, const struct sockaddr_storage *addr, net_bind_flag_t flags)
{
	/* Create socket. */
	int sock = net_unbound_socket(type, addr);
	if (sock < 0) {
		return sock;
	}

	/* Unlink UNIX sock if exists. */
	if (addr->ss_family == AF_UNIX) {
		unlink_unix_socket(addr);
	}

	/* Reuse old address if taken. */
	int ret = sockopt_enable(sock, SOL_SOCKET, SO_REUSEADDR);
	if (ret != KNOT_EOK) {
		close(sock);
		return ret;
	}

#if defined(__linux__)
	/* Set MSS (Maximum Segment Size) limit. */
	if (addr->ss_family != AF_UNIX && type == SOCK_STREAM) {
		const int mss = KNOT_TCP_MSS;
		if (setsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss)) != 0) {
			ret = knot_map_errno();
			close(sock);
			return ret;
		}
	}
#endif

	/* Don't bind IPv4 for IPv6 any address. */
	if (addr->ss_family == AF_INET6) {
		ret = sockopt_enable(sock, IPPROTO_IPV6, IPV6_V6ONLY);
		if (ret != KNOT_EOK) {
			close(sock);
			return ret;
		}
	}

	/* Allow bind to non-local address. */
	if (flags & NET_BIND_NONLOCAL) {
		ret = enable_nonlocal(sock, addr->ss_family);
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
	ret = bind(sock, (const struct sockaddr *)addr, sockaddr_len(addr));
	if (ret < 0) {
		ret = knot_map_errno();
		close(sock);
		return ret;
	}

	return sock;
}

static int tfo_connect(int sock, const struct sockaddr_storage *addr)
{
#if defined(__linux__)
	/* connect() will be called implicitly with sendmsg(). */
	return KNOT_EOK;
#elif defined(__FreeBSD__)
	return sockopt_enable(sock, IPPROTO_TCP, TCP_FASTOPEN);
#elif defined(__APPLE__)
	/* Connection is performed lazily when first data is sent. */
	sa_endpoints_t ep = {
		.sae_dstaddr = (const struct sockaddr *)addr,
		.sae_dstaddrlen = sockaddr_len(addr)
	};
	int flags =  CONNECT_DATA_IDEMPOTENT | CONNECT_RESUME_ON_READ_WRITE;

	int ret = connectx(sock, &ep, SAE_ASSOCID_ANY, flags, NULL, 0, NULL, NULL);
	return (ret == 0 ? KNOT_EOK : knot_map_errno());
#else
	return KNOT_ENOTSUP;
#endif
}

int net_connected_socket(int type, const struct sockaddr_storage *dst_addr,
                         const struct sockaddr_storage *src_addr, bool tfo)
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
	if (src_addr && src_addr->ss_family != AF_UNSPEC) {
		sock = net_bound_socket(type, src_addr, 0);
	} else {
		sock = net_unbound_socket(type, dst_addr);
	}
	if (sock < 0) {
		return sock;
	}

	/* Connect to destination. */
	if (tfo && net_is_stream(sock)) {
		int ret = tfo_connect(sock, dst_addr);
		if (ret != KNOT_EOK) {
			close(sock);
			return ret;
		}
	} else {
		int ret = connect(sock, (const struct sockaddr *)dst_addr,
		                  sockaddr_len(dst_addr));
		if (ret != 0 && errno != EINPROGRESS) {
			ret = knot_map_errno();
			close(sock);
			return ret;
		}
	}

	return sock;
}

int net_bound_tfo(int sock, int backlog)
{
#if defined(TCP_FASTOPEN)
#if defined(__APPLE__)
	if (backlog > 0) {
		backlog = 1; // just on-off switch on macOS
	}
#endif
	if (setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN, &backlog, sizeof(backlog)) != 0) {
		return knot_map_errno();
	}

	return KNOT_EOK;
#endif
	return KNOT_ENOTSUP;
}

bool net_is_connected(int sock)
{
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	return (getpeername(sock, (struct sockaddr *)&addr, &len) == 0);
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
	socklen_t len = sizeof(*addr);
	socklen_t *addr_len = (addr != NULL) ? &len : NULL;

	int remote = -1;

#if defined(HAVE_ACCEPT4) && defined(SOCK_NONBLOCK)
	remote = accept4(sock, (struct sockaddr *)addr, addr_len, SOCK_NONBLOCK);
	if (remote < 0) {
		return knot_map_errno();
	}
#else
	remote = accept(sock, (struct sockaddr *)addr, addr_len);
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
	if (error == EAGAIN || error == EWOULDBLOCK ||	/* Socket data not ready. */
	    error == ENOMEM || error == ENOBUFS) {	/* Insufficient resources. */
		return true;
	}

#ifndef __linux__
	/* FreeBSD: connection in progress. */
	if (error == ENOTCONN) {
		return true;
	}
#endif

	return false;
}

/*!
 * \brief Check if we should wait again.
 *
 * \param error  \a errno set by the failed wait operation.
 */
static bool wait_should_retry(int error)
{
	if (error == EINTR ||				/* System call interrupted. */
	    error == EAGAIN || error == ENOMEM) {	/* Insufficient resources. */
		return true;
	}
	return false;
}

/*!
 * \brief I/O operation callbacks.
 */
struct io {
	ssize_t (*process)(int sockfd, struct msghdr *msg, int timeout_ms);
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

#define TIMEOUT_CTX_INIT \
	struct timespec begin, end; \
	if (*timeout_ptr > 0) { \
		clock_gettime(CLOCK_MONOTONIC, &begin); \
	}

#define TIMEOUT_CTX_UPDATE \
	if (*timeout_ptr > 0) { \
		clock_gettime(CLOCK_MONOTONIC, &end); \
		int running_ms = time_diff_ms(&begin, &end); \
		*timeout_ptr = MAX(*timeout_ptr - running_ms, 0); \
	}

/*!
 * \brief Perform an I/O operation with a socket with waiting.
 *
 * \param oneshot  If set, doesn't wait until the buffer is fully processed.
 */
static ssize_t io_exec(const struct io *io, int fd, struct msghdr *msg,
                       bool oneshot, int *timeout_ptr)
{
	size_t done = 0;
	size_t total = msg_iov_len(msg);

	for (;;) {
		/* Perform I/O. */
		ssize_t ret = io->process(fd, msg, *timeout_ptr);
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
			for (;;) {
				TIMEOUT_CTX_INIT

				ret = io->wait(fd, *timeout_ptr);

				if (ret == 1) {
					TIMEOUT_CTX_UPDATE
					/* Ready, retry process. */
					break;
				} else if (ret == -1 && wait_should_retry(errno)) {
					TIMEOUT_CTX_UPDATE
					/* Interrupted or transient error, continue waiting. */
					continue;
				} else if (ret == 0) {
					/* Timed out, exit. */
					return KNOT_ETIMEOUT;
				} else {
					/* In specific circumstances with Valgrind,
					 * poll() returns wrong value.
					 */
					assert(ret <= 1);
					assert(ret >= -1);
					/* Other error, exit. */
					return KNOT_ECONN;
				}
			}
		} else {
			/* Disconnect or error. */
			return KNOT_ECONN;
		}
	}

	return done;
}

static ssize_t recv_process(int fd, struct msghdr *msg, int timeout_ms)
{
	return recvmsg(fd, msg, MSG_DONTWAIT | MSG_NOSIGNAL);
}

static int recv_wait(int fd, int timeout_ms)
{
	return poll_one(fd, POLLIN, timeout_ms);
}

static ssize_t recv_data(int sock, struct msghdr *msg, bool oneshot, int *timeout_ptr)
{
	static const struct io RECV_IO = {
		.process = recv_process,
		.wait = recv_wait
	};

	return io_exec(&RECV_IO, sock, msg, oneshot, timeout_ptr);
}

static ssize_t send_process_tfo(int fd, struct msghdr *msg, int timeout_ms)
{
#if defined(__linux__)
	int ret = sendmsg(fd, msg, MSG_FASTOPEN);
	if (ret != 0 && errno == EINPROGRESS) {
		if (poll_one(fd, POLLOUT, timeout_ms) != 1) {
			errno = ETIMEDOUT;
			return -1;
		}
		ret = sendmsg(fd, msg, MSG_NOSIGNAL);
	}
	return ret;
#else
	return sendmsg(fd, msg, MSG_NOSIGNAL);
#endif
}

static ssize_t send_process(int fd, struct msghdr *msg, int timeout_ms)
{
	return sendmsg(fd, msg, MSG_NOSIGNAL);
}

static int send_wait(int fd, int timeout_ms)
{
	return poll_one(fd, POLLOUT, timeout_ms);
}

static ssize_t send_data(int sock, struct msghdr *msg, int *timeout_ptr, bool tfo)
{
	static const struct io SEND_IO = {
		.process = send_process,
		.wait = send_wait
	};
	static const struct io SEND_IO_TFO = {
		.process = send_process_tfo,
		.wait = send_wait
	};

	return io_exec(tfo ? &SEND_IO_TFO : &SEND_IO, sock, msg, false, timeout_ptr);
}

/* -- generic stream and datagram I/O -------------------------------------- */

ssize_t net_base_send(int sock, const uint8_t *buffer, size_t size,
                      const struct sockaddr_storage *addr, int timeout_ms)
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

	int ret = send_data(sock, &msg, &timeout_ms, false);
	if (ret < 0) {
		return ret;
	} else if (ret != size) {
		return KNOT_ECONN;
	}

	return ret;
}

ssize_t net_base_recv(int sock, uint8_t *buffer, size_t size,
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

	return recv_data(sock, &msg, true, &timeout_ms);
}

ssize_t net_dgram_send(int sock, const uint8_t *buffer, size_t size,
                       const struct sockaddr_storage *addr)
{
	return net_base_send(sock, buffer, size, addr, 0);
}

ssize_t net_dgram_recv(int sock, uint8_t *buffer, size_t size, int timeout_ms)
{
	return net_base_recv(sock, buffer, size, NULL, timeout_ms);
}

ssize_t net_stream_send(int sock, const uint8_t *buffer, size_t size, int timeout_ms)
{
	return net_base_send(sock, buffer, size, NULL, timeout_ms);
}

ssize_t net_stream_recv(int sock, uint8_t *buffer, size_t size, int timeout_ms)
{
	return net_base_recv(sock, buffer, size, NULL, timeout_ms);
}

/* -- DNS specific I/O ----------------------------------------------------- */

ssize_t net_dns_tcp_send(int sock, const uint8_t *buffer, size_t size, int timeout_ms,
                         struct sockaddr_storage *tfo_addr)
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
	msg.msg_name = (void *)tfo_addr;
	msg.msg_namelen = tfo_addr ? sizeof(*tfo_addr) : 0;

	ssize_t ret = send_data(sock, &msg, &timeout_ms, tfo_addr != NULL);
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

	uint16_t pktsize = 0;

	struct iovec iov = {
		.iov_base = &pktsize,
		.iov_len = sizeof(pktsize)
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1
	};

	/* Receive size. */
	int ret = recv_data(sock, &msg, false, &timeout_ms);
	if (ret != sizeof(pktsize)) {
		return ret;
	}
	pktsize = ntohs(pktsize);

	/* Check packet size */
	if (size < pktsize) {
		return KNOT_ESPACE;
	}

	/* Receive payload. */
	iov.iov_base = buffer;
	iov.iov_len = pktsize;

	return recv_data(sock, &msg, false, &timeout_ms);
}
