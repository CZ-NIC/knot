/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <string.h>

#include "libdnssec/error.h"
#include "libdnssec/keyid.h"
#include "libdnssec/shared/shared.h"

#include "contrib/ctype.h"
#include "contrib/tolower.h"

/* -- public API ----------------------------------------------------------- */

_public_
bool dnssec_keyid_is_valid(const char *id)
{
	if (!id) {
		return false;
	}

	if (strlen(id) % 2 != 0) {
		return false;
	}

	for (int i = 0; id[i] != '\0'; i++) {
		if (!is_xdigit(id[i])) {
			return false;
		}
	}

	return true;
}

_public_
void dnssec_keyid_normalize(char *id)
{
	if (!id) {
		return;
	}

	for (size_t i = 0; id[i] != '\0'; i++) {
		assert(id[i] != '\0' && is_xdigit(id[i]));
		id[i] = knot_tolower(id[i]);
	}
}

_public_
char *dnssec_keyid_copy(const char *id)
{
	if (!id) {
		return NULL;
	}

	char *copy = strdup(id);
	if (!copy) {
		return NULL;
	}

	dnssec_keyid_normalize(copy);

	return copy;
}

_public_
bool dnssec_keyid_equal(const char *one, const char *two)
{
	if (!one || !two) {
		return NULL;
	}

	return (strcasecmp(one, two) == 0);
}
