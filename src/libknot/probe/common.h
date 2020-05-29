#pragma once

#include <stdint.h>
#include <sys/un.h>

#ifndef UNIX_PATH_MAX
struct sockaddr_un sizecheck;
#define UNIX_PATH_MAX sizeof(sizecheck.sun_path)
#endif

typedef struct knot_probe_datagram {
	uint8_t ip_src[16];
	uint8_t ip_dst[16];
	uint8_t dns_header[12];
	uint16_t port_src;
	uint16_t port_dst;
	uint8_t proto;
} knot_probe_datagram_t;
