#include "unix.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "libknot/errcode.h"

int knot_probe_pollfd_init(knot_probe_pollfd_t *p, const uint16_t channel_count, const char *prefix)
{
	assert(p && channel_count && prefix);
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
	// .prefix
	strncpy(p->prefix, prefix, KNOT_PROBE_PREFIX_MAXSIZE);
	// .nfds
	p->nfds = channel_count;
	return KNOT_EOK;
}

int knot_probe_pollfd_bind(knot_probe_pollfd_t *p)
{
	assert(p && p->pfds && p->nfds);
	struct pollfd *it;
	int ret;
	for (it = p->pfds; it < &p->pfds[p->nfds]; ++it) {
		if ((it->fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
			perror("Unable to create socket");
			ret = KNOT_ECONN;
			goto err;
		}

		struct sockaddr_un name = {
			.sun_family = AF_UNIX
		};
		snprintf(name.sun_path, sizeof(name.sun_path), "%s%04x.unix", p->prefix, (uint16_t)(it - p->pfds));

		if (bind(it->fd, (struct sockaddr *)&name, sizeof(name)) < 0) {
			perror("Unable to bind socket");
			ret = KNOT_ECONN;
			goto err;
		}
	}
	return 0;

	err: knot_probe_pollfd_close(p);
	return ret;
}

void knot_probe_pollfd_close(knot_probe_pollfd_t *p)
{
	assert(p && p->pfds && p->nfds);
	struct pollfd *it;
	for (it = p->pfds; it < &p->pfds[p->nfds]; ++it) {
		if(it->fd >= 0) {
			close(it->fd);
			char name[UNIX_PATH_MAX];
			snprintf(name, sizeof(name), "%s%04x.unix", p->prefix, (uint16_t)(it - p->pfds));
			unlink(name);
			it->fd = INT_MIN;
		}
    }
}

void knot_probe_pollfd_deinit(knot_probe_pollfd_t *p)
{
	assert(p);
	free(p->pfds);
	p->pfds = NULL;
}

int knot_probe_channel_wo_init(knot_probe_channel_wo_t *s, const char *prefix, const uint16_t id)
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

int knot_probe_channel_send(const knot_probe_channel_wo_t *s, const uint8_t *base, const size_t len, const int flags)
{
	assert(s && base && len);
	return sendto(s->socket, base, len, flags, (struct sockaddr *)&s->path, sizeof(s->path));
}

void knot_probe_channel_close(knot_probe_channel_wo_t *s)
{
	assert(s);
	close(s->socket);
	s->socket = INT_MIN;
}
