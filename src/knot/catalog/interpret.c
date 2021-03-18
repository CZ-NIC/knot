/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/catalog/interpret.h"
#include "knot/zone/contents.h"

typedef struct {
	catalog_update_t *u;
	const knot_dname_t *apex;
	bool remove;
	catalog_t *check;
} cat_upd_ctx_t;

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

static int cat_update_add_node(zone_node_t *node, void *data)
{
	cat_upd_ctx_t *ctx = data;
	const knot_rdataset_t *ptr = node_rdataset(node, KNOT_RRTYPE_PTR);
	if (ptr == NULL || ptr->count == 0) {
		return KNOT_EOK;
	}
	knot_rdata_t *rdata = ptr->rdata;
	int ret = KNOT_EOK;
	for (int i = 0; ret == KNOT_EOK && i < ptr->count; i++) {
		const knot_dname_t *member = knot_ptr_name(rdata);
		ret = catalog_update_add(ctx->u, member, node->owner, ctx->apex,
		                         ctx->remove, ctx->check);
		rdata = knot_rdataset_next(rdata);
	}
	return ret;
}

int catalog_update_from_zone(catalog_update_t *u, struct zone_contents *zone,
                             bool remove, bool check_ver, catalog_t *check)
{
	if (check_ver && !check_zone_version(zone)) {
		return KNOT_EZONEINVAL;
	}

	knot_dname_storage_t sub;
	if (knot_dname_store(sub, (uint8_t *)CATALOG_ZONES_LABEL) == 0 ||
	    catalog_dname_append(sub, zone->apex->owner) == 0) {
		return KNOT_EINVAL;
	}

	if (zone_contents_find_node(zone, sub) == NULL) {
		return KNOT_EOK;
	}

	cat_upd_ctx_t ctx = { u, zone->apex->owner, remove, check };
	pthread_mutex_lock(&u->mutex);
	int ret = zone_tree_sub_apply(zone->nodes, sub, false, cat_update_add_node, &ctx);
	pthread_mutex_unlock(&u->mutex);
	return ret;
}
