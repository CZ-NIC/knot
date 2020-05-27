#pragma once

#include <stdint.h>
#include <stddef.h>
#include <poll.h>
#include <sys/un.h>

#ifndef UNIX_PATH_MAX
struct sockaddr_un sizecheck;
#define UNIX_PATH_MAX sizeof(sizecheck.sun_path)
#endif

#define KNOT_PROBE_PREFIX_MAXSIZE (UNIX_PATH_MAX - sizeof("ffff.unix"))

typedef struct knot_probe_datagram {
	uint8_t ip_src[16];
	uint8_t ip_dst[16];
	uint8_t dns_header[12];
	uint16_t port_src;
	uint16_t port_dst;
	uint8_t proto;
} knot_probe_datagram_t;

typedef struct knot_probe_channel_wo {
	struct sockaddr_un path; 
	int socket;
} knot_probe_channel_wo_t;

typedef struct knot_probe_pollfd {
	struct pollfd *pfds;
	uint16_t nfds;
	char prefix[KNOT_PROBE_PREFIX_MAXSIZE];
} knot_probe_pollfd_t;

int knot_probe_pollfd_init(knot_probe_pollfd_t *p, uint16_t size, const char *prefix);

int knot_probe_pollfd_bind(knot_probe_pollfd_t *p);

void knot_probe_pollfd_close(knot_probe_pollfd_t *p);

void knot_probe_pollfd_deinit(knot_probe_pollfd_t *p);

int knot_probe_channel_wo_init(knot_probe_channel_wo_t *s, const char *path, const uint16_t id);

int knot_probe_channel_send(const knot_probe_channel_wo_t *s, const uint8_t *base, const size_t len, const int flags);

void knot_probe_channel_close(knot_probe_channel_wo_t *s);
