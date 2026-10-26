/*  Copyright (C) 2026 CZ.NIC, z.s.p.o.
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "libknot/consts.h"
#include "libknot/dname.h"
#include "libknot/packet/pkt.h"
#include "libknot/rrtype/opt.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* Part A: parse a full DNS packet and exercise the EDNS API surface
	 * on the parsed OPT RR (any DNS peer controls these bytes). */
	if (size >= KNOT_WIRE_HEADER_SIZE && size <= UINT16_MAX) {
		uint8_t copy[1 + size];
		memcpy(copy, data, size);

		knot_pkt_t *pkt = knot_pkt_new(copy, size, NULL);
		if (pkt != NULL) {
			knot_pkt_parse(pkt, 0);
			if (knot_pkt_has_edns(pkt)) {
				(void)knot_edns_wire_size(pkt->opt_rr);
				(void)knot_edns_do(pkt->opt_rr);
				(void)knot_edns_de(pkt->opt_rr);

				knot_edns_options_t *opts = NULL;
				if (knot_edns_get_options(pkt->opt_rr, &opts, NULL) == KNOT_EOK &&
				    opts != NULL) {
					for (int i = 0; i <= KNOT_EDNS_MAX_OPTION_CODE; i++) {
						if (opts->ptr[i] != NULL) {
							(void)opts->ptr[i];
						}
					}
					/* The options struct is owned by the caller (mm=NULL). */
					free(opts);
				}
			}
			knot_pkt_free(pkt);
		}
	}

	/* Part B: the pure option-data parsers on the raw bytes. */
	const uint8_t *option = data;
	uint16_t option_len = (size > UINT16_MAX) ? UINT16_MAX : (uint16_t)size;

	knot_edns_client_subnet_t ecs;
	if (knot_edns_client_subnet_parse(&ecs, option, option_len) == KNOT_EOK) {
		struct sockaddr_storage addr;
		(void)knot_edns_client_subnet_get_addr(&addr, &ecs);
		(void)knot_edns_client_subnet_size(&ecs);
	}

	uint16_t timeout = 0;
	(void)knot_edns_keepalive_parse(&timeout, option, option_len);

	knot_dname_t *point = NULL;
	if (knot_edns_chain_parse(&point, option, option_len, NULL) == KNOT_EOK &&
	    point != NULL) {
		(void)knot_edns_chain_size(point);
		knot_dname_free(point, NULL);
	}

	knot_edns_cookie_t cc, sc;
	(void)knot_edns_cookie_parse(&cc, &sc, option, option_len);

	/* Fixed valid qname so the label arithmetic paths are reachable. */
	static const uint8_t qname[] = "\x03""www\x07""example\x03""com\x00";
	knot_dname_storage_t zone;
	uint8_t zv_type = 0;
	uint32_t zv_version = 0;
	(void)knot_edns_zoneversion_parse(zone, &zv_type, &zv_version,
	                                  option, option_len, qname);

	return 0;
}
