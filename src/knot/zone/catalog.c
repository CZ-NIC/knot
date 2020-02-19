/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "knot/zone/catalog.h"

#include <stdlib.h>
#include <string.h>

knot_catalog_t *knot_catalog_new()
{
	return trie_create(NULL);
}

struct catcb {
	knot_catalog_cb_t *cb;
	void *ctx;
};

static int _catcb(trie_val_t *tval, void *ctx)
{
	knot_catalog_val_t *val = *(knot_catalog_val_t **)tval;
	struct catcb *cb = ctx;
	return ctx->cb(val, ctx->ctx);
}

int knot_catalog_foreach(knot_catalog_t *catalog, knot_catalog_cb_t *cb, void *ctx)
{
	struct catcb cb = { cb, ctx };
	return trie_apply(catalog, _catcb, &cb);
}

int knot_catalog_add(knot_catalog_t *catalog, const knot_dname_t *zone, const char *tpl)
{
	size_t len_zone = knot_dname_size(zone);
	size_t len_tpl = tpl == NULL ? 0 : strlen(tpl) + 1;

	knot_catalog_val_t *val = malloc(sizeof(*val) + len_zone + len_tpl);
	if (val == NULL) {
		return KNOT_ENOMEM;
	}

	val->zone = (knot_dname_t *)(val + 1);
	memcpy(val->zone, zone, len_zone);
	if (tpl == NULL) {
		val->conf_template = NULL;
	} else {
		val->conf_template = (char *)(val->zone + len_zone);
		memcpy(val->conf_template, tpl, len_tpl);
	}

	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(zone, lf_storage);
	assert(lf);

	trie_val_t *tval = trie_get_ins(catalog, lf + 1, *lf);
	if (*tval != NULL) {
		free(*tval);
	}
	*tval = val;
}

knot_catalog_val_t *knot_catalog_get(knot_catalog_t *catalog, const knot_dname_t *zone)
{
	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(zone, lf_storage);
	assert(lf);

	trie_val_t *val = trie_get_try(catalog, lf + 1, *lf);
	return val == NULL ? NULL : *val;
}

void knot_catalog_del(knot_catalog_t *catalog, const knot_dname_t *zone)
{
	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(zone, lf_storage);
	assert(lf);

	trie_val_t *val = trie_get_try(catalog, lf + 1, *lf);
	if (val != NULL) {
		trie_del(catalog, lf + 1, *lf, NULL);
		free(*(void **)val);
	}
}

static int freecb(trie_val_t *tval, void *unused)
{
	(void)unused;
	free(*(void **)tval);
}

void knot_catalog_clear(knot_catalog_t *catalog)
{
	trie_apply(catalog, freecb, NULL);
	trie_clear(catalog);
}

void knot_catalog_free(knot_catalog_t *catalog)
{
	trie_apply(catalog, freecb, NULL);
	trie_free(catalog);
}

int knot_catalog_change_new(knot_catalog_change_t *ch)
{
	ch->add = knot_catalog_new();
	if (ch->add == NULL) {
		return KNOT_ENOMEM;
	}
	ch->rem = knot_catalog_new();
	if (ch->rem == NULL) {
		knot_catalog_free(ch->add);
		return KNOT_ENOMEM;
	}
	return KNOT_EOK;
}

void knot_catalog_change_free(knot_catalog_change_t *ch)
{
	knot_catalog_free(ch->add);
	knot_catalog_free(ch->rem);
}
