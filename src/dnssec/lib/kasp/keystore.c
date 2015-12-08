/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>

#include "shared.h"
#include "kasp.h"

_public_
dnssec_kasp_keystore_t *dnssec_kasp_keystore_new(const char *name)
{
	dnssec_kasp_keystore_t *keystore = malloc(sizeof(*keystore));
	clear_struct(keystore);

	if (name) {
		keystore->name = strdup(name);
		if (!keystore->name) {
			free(keystore);
			return NULL;
		}
	}

	return keystore;
}

_public_
void dnssec_kasp_keystore_free(dnssec_kasp_keystore_t *keystore)
{
	if (!keystore) {
		return;
	}

	free(keystore->name);
	free(keystore->backend);
	free(keystore->config);

	free(keystore);
}
