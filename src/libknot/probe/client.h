#pragma once

#include <stdint.h>
#include <stddef.h>
#include <poll.h>
#include <sys/un.h>

#include "libknot/probe/common.h"

typedef struct knot_probe_pollfd {
	struct pollfd *pfds;
	uint16_t nfds;
} knot_probe_pollfd_t;

int knot_probe_pollfd_init(knot_probe_pollfd_t *p, uint16_t size);

int knot_probe_pollfd_bind(knot_probe_pollfd_t *p, char *prefix);

void knot_probe_pollfd_close(knot_probe_pollfd_t *p);

void knot_probe_pollfd_deinit(knot_probe_pollfd_t *p);

