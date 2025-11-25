/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdint.h>

#include "libknot/packet/pkt.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t copy[1 + size];
	memcpy(copy, data, size);

	knot_pkt_t *pkt = knot_pkt_new(copy, size, NULL);
	if (pkt != NULL) {
		knot_pkt_parse(pkt, 0);
		knot_pkt_free(pkt);
	}

	return 0;
}
