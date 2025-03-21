/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdint.h>

#include "libzscanner/scanner.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	zs_scanner_t s;
	if (zs_init(&s, ".", 1, 0) == 0 &&
	    zs_set_input_string(&s, (const char *)data, size) == 0) {
		zs_parse_all(&s);
	}
	zs_deinit(&s);
	
	return 0;
}
