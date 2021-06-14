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

#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "libknot/attribute.h"
#include "libknot/errcode.h"
#include "libknot/probe/probe.h"
#include "contrib/time.h"

struct knot_probe {
	struct sockaddr_un path;
	uint32_t last_unconn_time;
	bool consumer;
	int fd;
};

_public_
knot_probe_t *knot_probe_alloc(void)
{
	knot_probe_t *probe = calloc(1, sizeof(*probe));
	if (probe == NULL) {
		return NULL;
	}

	probe->fd = -1;

	return probe;
}

_public_
void knot_probe_free(knot_probe_t *probe)
{
	if (probe == NULL) {
		return;
	}

	close(probe->fd);
	if (probe->consumer) {
		(void)unlink(probe->path.sun_path);
	}
	free(probe);
}

static int probe_connect(knot_probe_t *probe)
{
	return connect(probe->fd, (const struct sockaddr *)(&probe->path),
	               sizeof(probe->path));
}

static int probe_init(knot_probe_t *probe, const char *dir, uint16_t idx)
{
	if (probe == NULL || dir == NULL || idx == 0) {
		return KNOT_EINVAL;
	}

	probe->path.sun_family = AF_UNIX;
	int ret = snprintf(probe->path.sun_path, sizeof(probe->path.sun_path),
	                   "%s/probe%02u.sock", dir, idx);
	if (ret < 0 || ret >= sizeof(probe->path.sun_path)) {
		return KNOT_ERANGE;
	}

	probe->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (probe->fd < 0) {
		return knot_map_errno();
	}

	if (fcntl(probe->fd, F_SETFL, O_NONBLOCK) == -1) {
		close(probe->fd);
		probe->fd = -1;
		return knot_map_errno();
	}

	return KNOT_EOK;
}

_public_
int knot_probe_set_producer(knot_probe_t *probe, const char *dir, uint16_t idx)
{
	int ret = probe_init(probe, dir, idx);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = probe_connect(probe);
	if (ret != 0) {
		return KNOT_ECONN;
	}

	return KNOT_EOK;
}

_public_
int knot_probe_set_consumer(knot_probe_t *probe, const char *dir, uint16_t idx)
{
	int ret = probe_init(probe, dir, idx);
	if (ret != KNOT_EOK) {
		return ret;
	}

	probe->consumer = true;

	(void)unlink(probe->path.sun_path);

	ret = bind(probe->fd, (const struct sockaddr *)(&probe->path),
	           sizeof(probe->path));
	if (ret != 0) {
		return knot_map_errno();
	}

#if defined(__linux__)
	if (chmod(probe->path.sun_path, S_IRWXU | S_IRWXG | S_IRWXO) != 0) {
		close(probe->fd);
		return knot_map_errno();
	}
#endif

	return KNOT_EOK;
}

_public_
int knot_probe_fd(knot_probe_t *probe)
{
	if (probe == NULL) {
		return -1;
	}

	return probe->fd;
}

_public_
int knot_probe_produce(knot_probe_t *probe, const knot_probe_data_t *data, uint8_t count)
{
	if (probe == NULL || data == NULL || count != 1) {
		return KNOT_EINVAL;
	}

	size_t used_len = sizeof(*data) - KNOT_DNAME_MAXLEN + data->query.qname_len;
	if (send(probe->fd, data, used_len, 0) == -1) {
		struct timespec now = time_now();
		if (now.tv_sec - probe->last_unconn_time > 2) {
			probe->last_unconn_time = now.tv_sec;
			if ((errno == ENOTCONN || errno == ECONNREFUSED) &&
			    probe_connect(probe) == 0 &&
			    send(probe->fd, data, used_len, 0) > 0) {
				return KNOT_EOK;
			}
		}
		return knot_map_errno();
	}

	return KNOT_EOK;
}

_public_
int knot_probe_consume(knot_probe_t *probe, knot_probe_data_t *data, uint8_t count,
                       int timeout_ms)
{
	if (probe == NULL || data == NULL || count == 0) {
		return KNOT_EINVAL;
	}

#ifdef ENABLE_RECVMMSG
	struct mmsghdr msgs[count];
	struct iovec iovecs[count];

	memset(msgs, 0, sizeof(msgs));
	for (int i = 0; i < count; i++) {
		iovecs[i].iov_base         = &(data[i]);
		iovecs[i].iov_len          = sizeof(*data);
		msgs[i].msg_hdr.msg_iov    = &iovecs[i];
		msgs[i].msg_hdr.msg_iovlen = 1;
	}
#else
	struct iovec iov = {
		.iov_base = data,
		.iov_len  = sizeof(*data)
	};
	struct msghdr msg = {
		.msg_iov    = &iov,
		.msg_iovlen = 1
	};
#endif

	struct pollfd pfd = { .fd = probe->fd, .events = POLLIN };
	int ret = poll(&pfd, 1, timeout_ms);
	if (ret == -1) {
		return knot_map_errno();
	} else if ((pfd.revents & POLLIN) == 0) {
		return 0;
	}

#ifdef ENABLE_RECVMMSG
	ret = recvmmsg(probe->fd, msgs, count, 0, NULL);
#else
	ret = recvmsg(probe->fd, &msg, 0);
#endif
	if (ret == -1) {
		return knot_map_errno();
	}

#ifdef ENABLE_RECVMMSG
	return ret;
#else
	return (ret > 0 ? 1 : 0);
#endif
}
