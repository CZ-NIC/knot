/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <string.h>

#include "libknot/errcode.h"
#include "libknot/dnssec/keyid.h"
#include "libknot/dnssec/shared/shared.h"

#include "contrib/ctype.h"
#include "contrib/tolower.h"

/* -- public API ----------------------------------------------------------- */

_public_
bool dnssec_keyid_is_valid(const char *id)
{
	if (!id) {
		return false;
	}

	size_t id_len = strlen(id);
	bool with_colons = (id_len > 3 && id[2] == ':'); // p11tool format XX:XX:XX:<..>:XX
	if ((id_len - (with_colons ? id_len / 3 : 0)) % 2 != 0) {
		return false;
	}

	for (int i = 0; id[i] != '\0'; i++) {
		if (with_colons && i > 0 && i < id_len - 1 && i % 3 == 2 && id[i] == ':') {
			continue;
		}
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

	size_t j = 0;
	for (size_t i = 0; id[i] != '\0'; i++) {
		if (id[i] == ':') {
			assert(i % 3 == 2);
			continue;
		}
		assert(id[i] != '\0' && is_xdigit(id[i]));
		id[j++] = knot_tolower(id[i]);
	}
	id[j] = '\0';
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
