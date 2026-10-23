/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdint.h>
#include <string.h>

#include "libknot/errcode.h"
#include "libknot/rrset-dump.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0 || size > 1 + 4096) {
		return 0;
	}

	const knot_dname_t owner[] = { 0 };
	uint16_t type = (data[0] & 1) ? KNOT_RRTYPE_HTTPS : KNOT_RRTYPE_SVCB;
	knot_rrset_t *rrset = knot_rrset_new(owner, type, KNOT_CLASS_IN, 1, NULL);
	if (rrset == NULL) {
		return 0;
	}

	uint8_t rdata[3 + 4096] = { 0, 1, 0 };
	memcpy(rdata + 3, data + 1, size - 1);
	if (knot_rrset_add_rdata(rrset, rdata, 3 + size - 1, NULL) == KNOT_EOK) {
		knot_dump_style_t style = KNOT_DUMP_STYLE_DEFAULT;
		style.wrap = (data[0] & 2) != 0;
		char output[32768];
		(void)knot_rrset_txt_dump_data(rrset, 0, output, sizeof(output), &style);
	}

	knot_rrset_free(rrset, NULL);
	return 0;
}