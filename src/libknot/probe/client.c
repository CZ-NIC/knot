#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "libknot/attribute.h"
#include "libknot/errcode.h"
#include "libknot/probe/client.h"

_public_
int knot_probe_pollfd_init(knot_probe_pollfd_t *p, const uint16_t channel_count)
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
int knot_probe_pollfd_bind(knot_probe_pollfd_t *p, char *prefix)
{
	assert(p && p->pfds && p->nfds);
	if (strlen(prefix) > KNOT_PROBE_PREFIX_MAXSIZE) {
		perror("Prefix is too long");
		return KNOT_EINVAL;
	}

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
		snprintf(name.sun_path, sizeof(name.sun_path), "%s%04x.unix", prefix, (uint16_t)(it - p->pfds));
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

_public_
void knot_probe_pollfd_close(knot_probe_pollfd_t *p)
{
	assert(p && p->pfds && p->nfds);
	struct pollfd *it;
	for (it = p->pfds; it < &p->pfds[p->nfds]; ++it) {
		if(it->fd >= 0) {
			struct sockaddr_un name;
			socklen_t namelen = sizeof(name);
			getsockname(it->fd, &name, &namelen);
			close(it->fd);
			unlink(name.sun_path);
			it->fd = INT_MIN;
		}
    }
}

_public_
void knot_probe_pollfd_deinit(knot_probe_pollfd_t *p)
{
	assert(p);
	free(p->pfds);
	p->pfds = NULL;
}
