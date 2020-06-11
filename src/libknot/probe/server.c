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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "libknot/attribute.h"
#include "libknot/errcode.h"
#include "libknot/probe/server.h"

_public_
int knot_probe_channel_init(knot_probe_channel_t *s, const char *prefix, const uint16_t id)
{
	assert(s && prefix);
	s->path.sun_family = AF_UNIX;
	if (snprintf(s->path.sun_path, UNIX_PATH_MAX, "%s%04x.unix", prefix, id) > UNIX_PATH_MAX) {
		return KNOT_ECONN;
	}
	s->socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s->socket < 0) {
		return KNOT_ECONN;
	}
	return KNOT_EOK;
}

_public_
int knot_probe_channel_send(const knot_probe_channel_t *s, const uint8_t *base, const size_t len, const int flags)
{
	assert(s && base && len);
	return sendto(s->socket, base, len, flags, (struct sockaddr *)&s->path, sizeof(s->path));
}

_public_
void knot_probe_channel_close(knot_probe_channel_t *s)
{
	assert(s);
	close(s->socket);
	s->socket = INT_MIN;
}
