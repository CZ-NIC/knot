/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "libknot/attribute.h"
#include "libknot/errcode.h"
#include "libknot/probe/client.h"

_public_
int knot_probe_init(knot_probe_pollfd_t *p, const uint16_t channel_count)
{
	assert(p && channel_count);
	// .pfds
	p->pfds = (struct pollfd *)calloc(channel_count, sizeof(struct pollfd));
	if (!p->pfds) {
		return KNOT_ENOMEM;
	}
	for (struct pollfd *it = p->pfds; it < &p->pfds[channel_count]; ++it) {
		it->fd = INT_MIN;
		it->events = POLLIN;
		it->revents = 0;
	}
	// .nfds
	p->nfds = channel_count;
	return KNOT_EOK;
}

_public_
int knot_probe_bind(knot_probe_pollfd_t *p, const char *prefix)
{
	assert(p && p->pfds && p->nfds);
	if (strlen(prefix) > KNOT_PROBE_PREFIX_MAXSIZE) {
		return KNOT_EINVAL;
	}

	for (struct pollfd *it = p->pfds; it < &p->pfds[p->nfds]; ++it) {
		if ((it->fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
			int ret = knot_map_errno();
			knot_probe_close(p);
			return ret;
		}

		struct sockaddr_un name = {
			.sun_family = AF_UNIX
		};
		snprintf(name.sun_path, sizeof(name.sun_path), "%s%04x.unix",
		         prefix, (uint16_t)(it - p->pfds));
		if (bind(it->fd, (struct sockaddr *)&name, sizeof(name)) < 0) {
			int ret = knot_map_errno();
			knot_probe_close(p);
			return ret;
		}
	}

	return KNOT_EOK;
}

_public_
void knot_probe_close(knot_probe_pollfd_t *p)
{
	assert(p && p->pfds && p->nfds);
	struct pollfd *it;
	for (it = p->pfds; it < &p->pfds[p->nfds]; ++it) {
		if (it->fd >= 0) {
			struct sockaddr_un name;
			socklen_t namelen = sizeof(name);
			getsockname(it->fd, (struct sockaddr *)&name, &namelen);
			close(it->fd);
			unlink(name.sun_path);
			it->fd = INT_MIN;
		}
	}
}

_public_
void knot_probe_deinit(knot_probe_pollfd_t *p)
{
	assert(p);
	free(p->pfds);
	p->pfds = NULL;
}
