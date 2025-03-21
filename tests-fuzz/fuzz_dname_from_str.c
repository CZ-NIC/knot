/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdlib.h>
#include <string.h>

#include "libknot/dname.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	// Prepare 0-terminated dname string.
	char *txt = malloc(size + 1);
	if (txt == NULL) {
		return 0;
	}
	memcpy(txt, data, size);
	txt[size] = '\0';

	// Transform the input.
	knot_dname_storage_t dname;
	(void)knot_dname_from_str(dname, txt, sizeof(dname));

	free(txt);

	return 0;
}
