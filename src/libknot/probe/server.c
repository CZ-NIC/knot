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
