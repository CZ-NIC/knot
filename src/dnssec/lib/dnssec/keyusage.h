/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <dnssec/list.h>
#include "kasp.h"

typedef struct record {
	char *key_id;
	dnssec_list_t *zones;
} record_keyusage_t;

typedef dnssec_list_t dnssec_keyusage_t;

char *dnssec_keyusage_path(dnssec_kasp_t *kasp);

int dnssec_keyusage_add(dnssec_keyusage_t *keyusage, const char *key_id, char *zone);

int dnssec_keyusage_remove(dnssec_keyusage_t *keyusage, const char *key_id, char *zone);

bool dnssec_keyusage_is_used(dnssec_keyusage_t *keyusage, const char *key_id);

int dnssec_keyusage_load(dnssec_keyusage_t *keyusage, const char *filename);

int dnssec_keyusage_save(dnssec_keyusage_t *keyusage, const char *filename);

dnssec_keyusage_t *dnssec_keyusage_new(void);

void dnssec_keyusage_free(dnssec_keyusage_t *keyusage);
