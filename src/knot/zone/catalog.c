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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "knot/conf/conf.h"
#include "knot/zone/node.h"

knot_catalog_t *knot_catalog_new()
{
	return trie_create(NULL);
}

struct catcb {
	knot_catalog_cb_t cb;
	void *ctx;
};

static int _catcb(trie_val_t *tval, void *ctx)
{
	knot_catalog_val_t *val = *(knot_catalog_val_t **)tval;
	struct catcb *cb = ctx;
	return cb->cb(val, cb->ctx);
}

int knot_catalog_foreach(knot_catalog_t *catalog, knot_catalog_cb_t cb, void *ctx)
{
	struct catcb _cb = { cb, ctx };
	return trie_apply(catalog, _catcb, &_cb);
}

int knot_catalog_add(knot_catalog_t *catalog, const knot_dname_t *zone, const uint8_t *tpl, size_t tpl_len)
{
	size_t len_zone = knot_dname_size(zone);

	knot_catalog_val_t *val = malloc(sizeof(*val) + len_zone + tpl_len);
	if (val == NULL) {
		return KNOT_ENOMEM;
	}

	val->zone = (knot_dname_t *)(val + 1);
	memcpy(val->zone, zone, len_zone);
	if (tpl == NULL) {
		val->conf_tpl = NULL;
		val->conf_tpl_len = 0;
	} else {
		val->conf_tpl = (uint8_t *)(val->zone + len_zone);
		memcpy(val->conf_tpl, tpl, tpl_len);
		val->conf_tpl_len = tpl_len;
	}

	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(zone, lf_storage);
	assert(lf);

	trie_val_t *tval = trie_get_ins(catalog, lf + 1, *lf);
	if (*tval != NULL) {
		free(*tval);
	}
	*tval = val;
	return KNOT_EOK;
}

struct cat_zone_ctx {
	knot_catalog_t *catalog;
	const uint8_t *tpl;
	size_t tpl_len;
};

static int cat_zone_cb(zone_node_t *node, void *data)
{
	struct cat_zone_ctx *ctx = data;
	knot_rdataset_t *ptrs = node_rdataset(node, KNOT_RRTYPE_PTR);
	if (ptrs == NULL) {
		return KNOT_EOK;
	}
	knot_rdata_t *ptr = ptrs->rdata;
	int ret = KNOT_EOK;
	for (int i = 0; i < ptrs->count && ret == KNOT_EOK; i++) {
		ret = knot_catalog_add(ctx->catalog, (const knot_dname_t *)ptr->data,
		                       ctx->tpl, ctx->tpl_len);
		ptr = knot_rdataset_next(ptr);
	}
	return ret;
}

int knot_catalog_from_zone(knot_catalog_t *catalog, zone_contents_t *zone, conf_t *conf)
{
	conf_val_t val = conf_zone_get(conf, C_CATALOG_TPL, zone->apex->owner);
	conf_val(&val);
	if (val.code != KNOT_EOK) {
		return KNOT_EINVAL;
	}
	struct cat_zone_ctx ctx = { catalog, val.data, val.len };
	return zone_contents_apply(zone, cat_zone_cb, &ctx);
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
	return 0;
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
	pthread_mutex_init(&ch->mutex, 0);
	return KNOT_EOK;
}

void knot_catalog_change_free(knot_catalog_change_t *ch)
{
	pthread_mutex_destroy(&ch->mutex);
	knot_catalog_free(ch->add);
	knot_catalog_free(ch->rem);
}

int print_cb(knot_catalog_val_t *val, void *unused)
{
	UNUSED(unused);
	printf("%s [%.*s]\n", val->zone, (int)val->conf_tpl_len, val->conf_tpl);
	return 0;
}

void knot_catalog_print(knot_catalog_t *catalog, const char *intro)
{
	printf("%s:\n", intro);
	(void)knot_catalog_foreach(catalog, print_cb, NULL);
}
