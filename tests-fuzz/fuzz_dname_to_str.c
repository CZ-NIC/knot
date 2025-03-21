/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "libknot/dname.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	// Skip invalid dnames.
	if (knot_dname_wire_check(data, data + size, NULL) <= 0) {
		return 0;
	}

	// Transform the input.
	knot_dname_txt_storage_t txt;
	(void)knot_dname_to_str(txt, (const knot_dname_t *)data, sizeof(txt));

	return 0;
}
