#pragma once

#include <stdint.h>
#include <stddef.h>
#include <poll.h>
#include <sys/un.h>

#include "libknot/probe/common.h"

typedef struct knot_probe_channel_wo {
	struct sockaddr_un path;
	int socket;
} knot_probe_channel_wo_t;

int knot_probe_channel_wo_init(knot_probe_channel_wo_t *s, const char *path, const uint16_t id);

int knot_probe_channel_send(const knot_probe_channel_wo_t *s, const uint8_t *base, const size_t len, const int flags);

void knot_probe_channel_close(knot_probe_channel_wo_t *s);
