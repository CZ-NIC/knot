/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <pthread.h>
#include <stdio.h>

#include "knot/catalog/interpret.h"
#include "knot/journal/serialization.h"

struct cat_upd_ctx;
typedef int (*cat_interpret_cb_t)(zone_node_t *node, struct cat_upd_ctx *ctx);

typedef struct cat_upd_ctx {
	catalog_update_t *u;
	const zone_contents_t *complete_conts;
	int apex_labels;
	bool remove;
	bool zone_diff;
	catalog_t *check;
	cat_interpret_cb_t member_cb;
	cat_interpret_cb_t property_cb;
} cat_upd_ctx_t;

static bool label_eq(const knot_dname_t *a, const char *_b)
{
	const knot_dname_t *b = (const knot_dname_t *)_b;
	return a[0] == b[0] && memcmp(a + 1, b + 1, a[0]) == 0;
}

static bool check_zone_version(const zone_contents_t *zone)
{
	size_t zone_size = knot_dname_size(zone->apex->owner);
	knot_dname_t sub[zone_size + 8];
	memcpy(sub, "\x07""version", 8);
	memcpy(sub + 8, zone->apex->owner, zone_size);

	const zone_node_t *ver_node = zone_contents_find_node(zone, sub);
	knot_rdataset_t *ver_rr = node_rdataset(ver_node, KNOT_RRTYPE_TXT);
	if (ver_rr == NULL) {
		return false;
	}

	knot_rdata_t *rdata = ver_rr->rdata;
	for (int i = 0; i < ver_rr->count; i++) {
		if (rdata->len == 2 && rdata->data[1] == CATALOG_ZONE_VERSION[0]) {
			return true;
		}
		rdata = knot_rdataset_next(rdata);
	}
	return false;
}

static int interpret_node(zone_node_t *node, void * _ctx)
{
	cat_upd_ctx_t *ctx = _ctx;

	int labels_diff = knot_dname_labels(node->owner, NULL) - ctx->apex_labels
	                  - 1 /* "zones" label */ - 1 /* unique-N label */;
	assert(labels_diff >= 0);

	switch (labels_diff) {
	case 0:
		return ctx->member_cb(node, ctx);
	case 1:
		return ctx->property_cb(node, ctx);
	default:
		return KNOT_EOK;
	}
}

static int interpret_zone(zone_diff_t *zdiff, cat_upd_ctx_t *ctx)
{
	knot_dname_storage_t sub;
	if (knot_dname_store(sub, (uint8_t *)CATALOG_ZONES_LABEL) == 0 ||
	    catalog_dname_append(sub, zdiff->apex->owner) == 0) {
		return KNOT_EINVAL;
	}

	if (zone_tree_get(&zdiff->nodes, sub) == NULL) {
		return KNOT_EOK;
	}

	return zone_tree_sub_apply(&zdiff->nodes, sub, true, interpret_node, ctx);
}

static const knot_dname_t *property_get_member(const zone_node_t *prop_node,
                                               const zone_contents_t *complete_conts,
                                               const knot_dname_t **owner)
{
	assert(prop_node != NULL);
	knot_rdataset_t *ptr = node_rdataset(prop_node->parent, KNOT_RRTYPE_PTR);
	if (ptr == NULL) {
		// fallback: search in provided complete zone contents
		const knot_dname_t *memb_name = knot_wire_next_label(prop_node->owner, NULL);
		const zone_node_t *memb_node = zone_contents_find_node(complete_conts, memb_name);
		ptr = node_rdataset(memb_node, KNOT_RRTYPE_PTR);
		if (memb_node != NULL) {
			*owner = memb_node->owner;
		}
	} else {
		*owner = prop_node->parent->owner;
	}
	if (*owner == NULL || ptr == NULL || ptr->count != 1) {
		return NULL;
	}
	return knot_ptr_name(ptr->rdata);
}

static int cat_update_add_memb(zone_node_t *node, cat_upd_ctx_t *ctx)
{
	const knot_rdataset_t *ptr = node_rdataset(node, KNOT_RRTYPE_PTR);
	if (ptr == NULL) {
		return KNOT_EOK;
	} else if (ptr->count != 1) {
		return KNOT_ERROR;
	}

	const knot_rdataset_t *counter_ptr = node_rdataset(binode_counterpart(node), KNOT_RRTYPE_PTR);
	if (knot_rdataset_subset(ptr, counter_ptr)) {
		return KNOT_EOK;
	}

	knot_rdata_t *rdata = ptr->rdata;
	int ret = KNOT_EOK;
	for (int i = 0; ret == KNOT_EOK && i < ptr->count; i++) {
		const knot_dname_t *member = knot_ptr_name(rdata);
		ret = catalog_update_add(ctx->u, member, node->owner, ctx->complete_conts->apex->owner,
		                         ctx->remove ? CAT_UPD_REM : CAT_UPD_ADD,
		                         NULL, 0, ctx->check);
		rdata = knot_rdataset_next(rdata);
	}
	return ret;
}

static int cat_update_add_grp(zone_node_t *node, cat_upd_ctx_t *ctx)
{
	if (!label_eq(node->owner, CATALOG_GROUP_LABEL)) {
		return KNOT_EOK;
	}

	const knot_dname_t *owner = NULL;
	const knot_dname_t *member = property_get_member(node, ctx->complete_conts, &owner);
	if (member == NULL) {
		return KNOT_EOK; // just ignore property w/o member
	}

	const knot_rdataset_t *txt = node_rdataset(node, KNOT_RRTYPE_TXT);
	if (txt == NULL) {
		return KNOT_EOK;
	} else if (txt->count != 1) {
		return KNOT_ERROR;
	}

	const knot_rdataset_t *counter_txt = node_rdataset(binode_counterpart(node), KNOT_RRTYPE_TXT);
	if (knot_rdataset_subset(txt, counter_txt)) {
		return KNOT_EOK;
	}

	const char *newgr = "";
	size_t grlen = 0;
	if (!ctx->remove) {
		assert(txt->count == 1);
		// TXT rdata consists of one or more 1-byte prefixed strings.
		if (txt->rdata->len != txt->rdata->data[0] + 1) {
			return KNOT_EMALF;
		}
		newgr = (const char *)txt->rdata->data + 1;
		grlen = txt->rdata->data[0];
		assert(grlen <= CATALOG_GROUP_MAXLEN);
	}

	return catalog_update_add(ctx->u, member, owner, ctx->complete_conts->apex->owner,
	                          CAT_UPD_PROP, newgr, grlen, ctx->check);
}

int catalog_update_from_zone(catalog_update_t *u, struct zone_contents *zone,
                             const zone_diff_t *zone_diff,
                             const struct zone_contents *complete_contents,
                             bool remove, catalog_t *check, ssize_t *upd_count)
{
	int ret = KNOT_EOK;
	zone_diff_t zdiff;
	assert(zone == NULL || zone_diff == NULL);
	if (zone != NULL) {
		zone_diff_from_zone(&zdiff, zone);
	} else {
		zdiff = *zone_diff;
	}
	cat_upd_ctx_t ctx = { u, complete_contents, knot_dname_labels(zdiff.apex->owner, NULL),
	                      remove, zone_diff != NULL, check, cat_update_add_memb, cat_update_add_grp };

	pthread_mutex_lock(&u->mutex);
	*upd_count -= trie_weight(u->upd);
	if (zone_diff != NULL) {
		zone_diff_reverse(&zdiff);
		ctx.remove = true;
		ret = interpret_zone(&zdiff, &ctx);
		zone_diff_reverse(&zdiff);
		ctx.remove = false;
		ctx.check = NULL;
	}
	if (ret == KNOT_EOK) {
		ret = interpret_zone(&zdiff, &ctx);
	}
	*upd_count += trie_weight(u->upd);
	pthread_mutex_unlock(&u->mutex);
	return ret;
}

static int rr_count(const zone_node_t *node, uint16_t type)
{
	const knot_rdataset_t *rd = node_rdataset(node, type);
	return rd == NULL ? 0 : rd->count;
}

static int member_verify(zone_node_t *node, cat_upd_ctx_t *ctx)
{
	return rr_count(node, KNOT_RRTYPE_PTR) > 1 ? KNOT_EISRECORD : KNOT_EOK;
}

static int prop_verify(zone_node_t *node, cat_upd_ctx_t *ctx)
{
	if (label_eq(node->owner, CATALOG_GROUP_LABEL) &&
	    rr_count(node, KNOT_RRTYPE_TXT) > 1) {
		return KNOT_EISRECORD;
	}

	return KNOT_EOK;
}

int catalog_zone_verify(const struct zone_contents *zone)
{
	cat_upd_ctx_t ctx = { NULL, zone, knot_dname_labels(zone->apex->owner, NULL),
	                      false, false, NULL, member_verify, prop_verify };

	if (!check_zone_version(zone)) {
		return KNOT_EZONEINVAL;
	}

	zone_diff_t zdiff;
	zone_diff_from_zone(&zdiff, zone);

	return interpret_zone(&zdiff, &ctx);
}
