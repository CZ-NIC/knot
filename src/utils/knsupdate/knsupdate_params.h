/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdint.h>

#include "utils/common/netio.h"
#include "utils/common/params.h"
#include "utils/common/quic.h"
#include "utils/common/sign.h"
#include "utils/common/tls.h"
#include "libknot/libknot.h"
#include "libzscanner/scanner.h"
#include "contrib/ucw/lists.h"

#define PROGRAM_NAME "knsupdate"

/*! \brief knsupdate-specific params data. */
typedef struct {
	/*!< Stop processing - just print help, version,... */
	bool		stop;
	/*!< List of files with query data. */
	list_t		qfiles;
	/*!< List of nameservers to query to. */
	srv_info_t	*server;
	/*!< Local interface (optional). */
	srv_info_t	*srcif;
	/*!< Version of ip protocol to use. */
	ip_t		ip;
	/*!< Type (TCP, UDP) protocol to use. */
	protocol_t	protocol;
	/*!< Default class number. */
	uint16_t	class_num;
	/*!< Number of UDP retries. */
	uint32_t	retries;
	/*!< Wait for network response in seconds (-1 means forever). */
	int32_t		wait;
	/*!< Current zone. */
	char		*zone;
	/*!< RR parser. */
	zs_scanner_t	parser;
	/*!< Current packet. */
	knot_pkt_t	*query;
	/*!< Current response. */
	knot_pkt_t	*answer;
	/*< Lists of RRSets. */
	list_t		update_list, prereq_list;
	/*!< Transaction signature context. */
	knot_tsig_key_t tsig_key;
	/*!< Default output settings. */
	style_t		style;
	/*!< Memory context. */
	knot_mm_t	mm;
	/*!< TLS params. */
	tls_params_t	tls_params;
	/*!< QUIC params. */
	quic_params_t	quic_params;
} knsupdate_params_t;

int knsupdate_parse(knsupdate_params_t *params, int argc, char *argv[]);
int knsupdate_set_ttl(knsupdate_params_t *params, const uint32_t ttl);
int knsupdate_set_origin(knsupdate_params_t *params, const char *origin);
void knsupdate_clean(knsupdate_params_t *params);
void knsupdate_reset(knsupdate_params_t *params);
