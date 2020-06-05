#pragma once

#include <stdint.h>
#include <sys/un.h>

#include "libknot/consts.h"
#include "libknot/rrtype/opt.h"

#ifndef UNIX_PATH_MAX
struct sockaddr_un sizecheck;
#define UNIX_PATH_MAX sizeof(sizecheck.sun_path)
#endif

#define KNOT_PROBE_PREFIX_MAXSIZE (UNIX_PATH_MAX - sizeof("ffff.unix"))
#define KNOT_EDNS_NSID_TRUNCATE_MAXLEN 255

typedef struct {
	uint8_t client_subnet[KNOT_EDNS_CLIENT_SUBNET_ADDRESS_MAXLEN];
	uint8_t nsid[KNOT_EDNS_NSID_TRUNCATE_MAXLEN];
} edns_opts_t;

typedef struct {
	uint16_t family;
	uint16_t port;
	uint8_t addr[16];
} addr_t;


typedef struct knot_probe_datagram {
	edns_opts_t edns_opts;
	uint8_t dname[KNOT_DNAME_MAXLEN];
	addr_t src;
	addr_t dst;
	uint8_t query_wire[12];
	uint8_t response_wire[12];
	uint32_t tcp_rtt;
	uint8_t proto;
} knot_probe_datagram_t;
