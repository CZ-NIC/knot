/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>

#include "clists.h"
#include "error.h"
#include "kasp.h"
#include "kasp/keyset.h"
#include "kasp/zone.h"
#include "shared.h"

_public_
void dnssec_kasp_keyset_init(dnssec_kasp_keyset_t *keyset)
{
	if (!keyset) {
		return;
	}

	clist_init(&keyset->list);
}

_public_
dnssec_kasp_keyset_t *dnssec_kasp_zone_get_keys(dnssec_kasp_zone_t *zone)
{
	if (!zone) {
		return NULL;
	}

	return &zone->keys;
}

_public_
size_t dnssec_kasp_keyset_count(dnssec_kasp_keyset_t *keys)
{
	if (!keys) {
		return 0;
	}

	return clist_size(&keys->list);
}

_public_
dnssec_kasp_key_t *dnssec_kasp_keyset_at(dnssec_kasp_keyset_t *keys, size_t search)
{
	if (!keys) {
		return NULL;
	}

	size_t index = 0;
	CLIST_FOR_EACH(cptrnode_t *, node, keys->list) {
		if (index++ == search) {
			return node->ptr;
		}
	}

	return NULL;
}

_public_
int dnssec_kasp_keyset_add(dnssec_kasp_keyset_t *keys, dnssec_kasp_key_t *kasp_key)
{
	if (!keys || !kasp_key) {
		return DNSSEC_EINVAL;
	}

	cptrnode_t *added = cptrlist_add(&keys->list, kasp_key);
	if (!added) {
		return DNSSEC_ENOMEM;
	}

	return DNSSEC_EOK;
}

static void free_kasp_key(dnssec_kasp_key_t *kasp_key)
{
	dnssec_key_free(kasp_key->key);
	free(kasp_key);
}

_public_
int dnssec_kasp_keyset_remove(dnssec_kasp_keyset_t *keys, dnssec_kasp_key_t *search)
{
	if (!keys || !search) {
		return DNSSEC_EINVAL;
	}

	CLIST_FOR_EACH(cptrnode_t *, node, keys->list) {
		if (node->ptr == search) {
			free_kasp_key(node->ptr);
			clist_remove((cnode_t *)node);
			free(node);
			return DNSSEC_EOK;
		}
	}

	return DNSSEC_EINVAL;
}

_public_
void dnssec_kasp_keyset_empty(dnssec_kasp_keyset_t *keys)
{
	if (!keys) {
		return;
	}

	cptrnode_t *current = NULL, *next = NULL;
	CLIST_WALK_DELSAFE(current, keys->list, next) {
		free_kasp_key(current->ptr);
		free(current);
	}

	dnssec_kasp_keyset_init(keys);
}
