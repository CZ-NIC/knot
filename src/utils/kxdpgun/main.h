/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>

#include "contrib/json.h"
#include "libknot/xdp/eth.h"
#include "libknot/xdp/tcp.h"

#define PROGRAM_NAME "kxdpgun"
#define SPACE        "  "

#define REMOTE_PORT_DEFAULT        53
#define REMOTE_PORT_DOQ_DEFAULT   853
#define LOCAL_PORT_MIN           2000
#define LOCAL_PORT_MAX          65535
#define QUIC_THREAD_PORTS         100

enum {
	KXDPGUN_WAIT,
	KXDPGUN_START,
	KXDPGUN_STOP,
};

typedef enum {
	KXDPGUN_IGNORE_NONE     = 0,
	KXDPGUN_IGNORE_QUERY    = (1 << 0),
	KXDPGUN_IGNORE_LASTBYTE = (1 << 1),
	KXDPGUN_IGNORE_CLOSE    = (1 << 2),
	KXDPGUN_REUSE_CONN      = (1 << 3),
} xdp_gun_ignore_t;

typedef struct xdp_gun_ctx {
	union {
		struct sockaddr_in local_ip4;
		struct sockaddr_in6 local_ip;
		struct sockaddr_storage local_ip_ss;
	};
	union {
		struct sockaddr_in target_ip4;
		struct sockaddr_in6 target_ip;
		struct sockaddr_storage target_ip_ss;
	};
	char                   dev[IFNAMSIZ];
	uint64_t               qps, duration;
	uint64_t               runid;
	uint64_t               stats_start_us;
	uint64_t               stats_period_ns; // 0 means no periodic stats
	unsigned               at_once;
	uint16_t               msgid;
	uint16_t               edns_size;
	uint16_t               vlan_tci;
	uint8_t                local_mac[6], target_mac[6];
	uint8_t                local_ip_range;
	bool                   ipv6;
	bool                   tcp;
	bool                   quic;
	bool                   quic_full_handshake;
	const char             *qlog_dir;
	const char             *sending_mode;
	xdp_gun_ignore_t       ignore1;
	knot_tcp_ignore_t      ignore2;
	uint16_t               target_port;
	knot_xdp_filter_flag_t flags;
	unsigned               n_threads, thread_id;
	knot_eth_rss_conf_t    *rss_conf;
	jsonw_t                *jw;
	char                   **argv;
	knot_xdp_config_t      xdp_config;
} xdp_gun_ctx_t;
