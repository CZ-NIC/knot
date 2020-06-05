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
} knot_probe_edns_t;

typedef struct {
	uint16_t family;
	uint16_t port;
	uint8_t addr[16];
} knot_addr_t;


typedef struct knot_probe_data {
	knot_probe_edns_t edns_opts;
	uint8_t dname[KNOT_DNAME_MAXLEN];
	knot_addr_t src;
	knot_addr_t dst;
	uint8_t query_hdr[12];
	uint8_t response_hdr[12];
	uint32_t tcp_rtt;
	uint8_t proto;
} knot_probe_data_t;
