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

#include <stdio.h>
#include <string.h>

#include "knot/catalog/catalog_update.h"
#include "knot/common/log.h"
#include "knot/conf/base.h"

int catalog_update_init(catalog_update_t *u)
{
	u->upd = trie_create(NULL);
	if (u->upd == NULL) {
		return KNOT_ENOMEM;
	}
	pthread_mutex_init(&u->mutex, 0);
	u->error = KNOT_EOK;
	return KNOT_EOK;
}

catalog_update_t *catalog_update_new(void)
{
	catalog_update_t *u = calloc(1, sizeof(*u));
	if (u != NULL) {
		int ret = catalog_update_init(u);
		if (ret != KNOT_EOK) {
			free(u);
			u = NULL;
		}
	}
	return u;
}

static void catalog_upd_val_free(catalog_upd_val_t *val)
{
	free(val->add_owner);
	free(val->rem_owner);
	free(val->new_group);
	free(val);
}

static int freecb(trie_val_t *tval, _unused_ void *unused)
{
	catalog_upd_val_t *val = *tval;
	if (val != NULL) {
		catalog_upd_val_free(val);
	}
	return 0;
}

void catalog_update_clear(catalog_update_t *u)
{
	trie_apply(u->upd, freecb, NULL);
	trie_clear(u->upd);
	u->error = KNOT_EOK;
}

void catalog_update_deinit(catalog_update_t *u)
{
	pthread_mutex_destroy(&u->mutex);
	trie_free(u->upd);
}

void catalog_update_free(catalog_update_t *u)
{
	if (u != NULL) {
		catalog_update_deinit(u);
		free(u);
	}
}

static catalog_upd_val_t *upd_val_new(const knot_dname_t *member, int bail,
                                      const knot_dname_t *owner, catalog_upd_type_t type)
{
	assert(bail <= (int)knot_dname_size(owner));
	size_t member_size = knot_dname_size(member);

	catalog_upd_val_t *val = malloc(sizeof(*val) + member_size);
	if (val == NULL) {
		return NULL;
	}
	val->member = (knot_dname_t *)(val + 1);
	memcpy(val->member, member, member_size);
	knot_dname_t *owner_cpy = knot_dname_copy(owner, NULL);
	if (owner_cpy == NULL) {
		free(val);
		return NULL;
	}
	val->type = type;
	val->new_group = NULL;
	if (type == CAT_UPD_REM) {
		val->add_owner = NULL;
		val->add_catz = NULL;
		val->rem_owner = owner_cpy;
		val->rem_catz = owner_cpy + bail;
	} else {
		val->add_owner = owner_cpy;
		val->add_catz = owner_cpy + bail;
		val->rem_owner = NULL;
		val->rem_catz = NULL;
	}
	return val;
}

static const knot_dname_t *get_uniq(const knot_dname_t *ptr_owner,
                                    const knot_dname_t *catz)
{
	int labels = knot_dname_labels(ptr_owner, NULL);
	labels -= knot_dname_labels(catz, NULL);
	assert(labels >= 2);
	return ptr_owner + knot_dname_prefixlen(ptr_owner, labels - 2, NULL);
}

static bool same_uniq(const knot_dname_t *owner1, const knot_dname_t *catz1,
                      const knot_dname_t *owner2, const knot_dname_t *catz2)
{
	const knot_dname_t *uniq1 = get_uniq(owner1, catz1), *uniq2 = get_uniq(owner2, catz2);
	if (*uniq1 != *uniq2) {
		return false;
	}
	return memcmp(uniq1 + 1, uniq2 + 1, *uniq1) == 0;
}

static int upd_val_update(catalog_upd_val_t *val, int bail,
                          const knot_dname_t *owner, bool rem)
{
	if ((rem  && val->type != CAT_UPD_ADD) ||
	    (!rem && val->type != CAT_UPD_REM)) {
		return KNOT_EEXIST;
	}
	knot_dname_t *owner_cpy = knot_dname_copy(owner, NULL);
	if (owner_cpy == NULL) {
		return KNOT_ENOMEM;
	}
	if (rem) {
		val->rem_owner = owner_cpy;
		val->rem_catz = owner_cpy + bail;
	} else {
		val->add_owner = owner_cpy;
		val->add_catz = owner_cpy + bail;
	}
	if (same_uniq(val->rem_owner, val->rem_catz, val->add_owner, val->add_catz)) {
		val->type = CAT_UPD_MINOR;
	} else {
		val->type = CAT_UPD_UNIQ;
	}
	return KNOT_EOK;
}

static int upd_val_set_prop(catalog_upd_val_t *val, const knot_dname_t *check_ow,
                            const knot_dname_t *check_catz, const char *group,
                            size_t group_len)
{
	if (check_catz != NULL) {
		if (val->type == CAT_UPD_REM ||
		    !knot_dname_is_equal(check_ow, val->add_owner) || // TODO consider removing those checks. Are they worth the performance?
		    !knot_dname_is_equal(check_catz, val->add_catz)) {
			return KNOT_EOK; // ignore invalid property set
		}
	}
	if (val->new_group != NULL) {
		free(val->new_group);
	}
	val->new_group = strndup(group, group_len);
	return val->new_group == NULL ? KNOT_ENOMEM : KNOT_EOK;
}

int catalog_update_add(catalog_update_t *u, const knot_dname_t *member,
                       const knot_dname_t *owner, const knot_dname_t *catzone,
                       catalog_upd_type_t type, const char *group,
                       size_t group_len, catalog_t *check_rem)
{
	if ((type == CAT_UPD_REM || type == CAT_UPD_PROP) && check_rem != NULL &&
	    !catalog_contains_exact(check_rem, member, owner, catzone)) {
		return KNOT_EOK;
		// we need to perform this check immediately because
		// garbage removal would block legitimate removal
	}

	int bail = catalog_bailiwick_shift(owner, catzone);
	if (bail < 0) {
		return KNOT_EOUTOFZONE;
	}
	assert(bail >= 0 && bail <= KNOT_DNAME_MAXLEN);

	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(member, lf_storage);

	trie_val_t *found = trie_get_try(u->upd, lf + 1, lf[0]);
	if (found != NULL) {
		catalog_upd_val_t *val = *found;
		assert(knot_dname_is_equal(val->member, member));
		if (type == CAT_UPD_PROP) {
			return upd_val_set_prop(val, owner, catzone, group, group_len);
		} else {
			return upd_val_update(val, bail, owner, type == CAT_UPD_REM);
		}
	}

	catalog_upd_val_t *val = upd_val_new(member, bail, owner, type);
	if (val == NULL) {
		return KNOT_ENOMEM;
	}
	if (group_len > 0) {
		int ret = upd_val_set_prop(val, NULL, NULL, group, group_len);
		if (ret != KNOT_EOK) {
			catalog_upd_val_free(val);
			return ret;
		}
	}
	trie_val_t *added = trie_get_ins(u->upd, lf + 1, lf[0]);
	if (added == NULL) {
		catalog_upd_val_free(val);
		return KNOT_ENOMEM;
	}
	assert(*added == NULL);
	*added = val;
	return KNOT_EOK;
}

catalog_upd_val_t *catalog_update_get(catalog_update_t *u, const knot_dname_t *member)
{
	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(member, lf_storage);

	trie_val_t *found = trie_get_try(u->upd, lf + 1, lf[0]);
	return found == NULL ? NULL : *(catalog_upd_val_t **)found;
}

static bool check_member(catalog_upd_val_t *val, conf_t *conf, catalog_t *cat)
{
	if (val->type == CAT_UPD_REM || val->type == CAT_UPD_INVALID || val->type == CAT_UPD_PROP) {
		return true;
	}
	if (!conf_rawid_exists(conf, C_ZONE, val->add_catz, knot_dname_size(val->add_catz))) {
		knot_dname_txt_storage_t cat_str;
		(void)knot_dname_to_str(cat_str, val->add_catz, sizeof(cat_str));
		log_zone_error(val->member, "catalog template zone '%s' not configured, ignoring", cat_str);
		return false;
	}
	if (conf_rawid_exists(conf, C_ZONE, val->member, knot_dname_size(val->member))) {
		log_zone_error(val->member, "member zone already configured, ignoring");
		return false;
	}
	if (val->type == CAT_UPD_ADD && catalog_has_member(cat, val->member)) {
		log_zone_error(val->member, "member zone already configured by catalog, ignoring");
		return false;
	}
	return true;
}

typedef struct {
	conf_t *conf;
	catalog_update_t *cup;
} rem_conflict_ctx_t;

static int rem_conf_conflict(const knot_dname_t *mem, const knot_dname_t *ow,
                             const knot_dname_t *cz, _unused_ const char *gr, void *ctx)
{
	rem_conflict_ctx_t *rcctx = ctx;

	if (conf_rawid_exists(rcctx->conf, C_ZONE, mem, knot_dname_size(mem))) {
		return catalog_update_add(rcctx->cup, mem, ow, cz, CAT_UPD_REM, NULL, 0, NULL);
	}
	return KNOT_EOK;
}

void catalog_update_finalize(catalog_update_t *u, catalog_t *cat, conf_t *conf)
{
	catalog_it_t *it = catalog_it_begin(u);
	while (!catalog_it_finished(it)) {
		catalog_upd_val_t *val = catalog_it_val(it);
		if (!check_member(val, conf, cat)) {
			val->type = (val->type == CAT_UPD_ADD ? CAT_UPD_INVALID : CAT_UPD_REM);
		}
		catalog_it_next(it);
	}
	catalog_it_free(it);

	// This checks if the configuration file has not changed in the way
	// it conflicts with existing member zone and let config take precedence.
	if (cat->ro_txn != NULL) {
		rem_conflict_ctx_t rcctx = { conf, u };
		(void)catalog_apply(cat, NULL, rem_conf_conflict, &rcctx, false);
	}
}

int catalog_update_commit(catalog_update_t *u, catalog_t *cat)
{
	catalog_it_t *it = catalog_it_begin(u);
	if (catalog_it_finished(it)) {
		catalog_it_free(it);
		return KNOT_EOK;
	}
	int ret = catalog_begin(cat);
	while (!catalog_it_finished(it) && ret == KNOT_EOK) {
		catalog_upd_val_t *val = catalog_it_val(it);
		switch (val->type) {
		case CAT_UPD_ADD:
		case CAT_UPD_MINOR: // catalog_add will simply update/overwrite existing data
		case CAT_UPD_UNIQ:
		case CAT_UPD_PROP:
			ret = catalog_add(cat, val->member, val->add_owner, val->add_catz,
			                  val->new_group == NULL ? "" : val->new_group);
			break;
		case CAT_UPD_REM:
			ret = catalog_del(cat, val->member);
			break;
		case CAT_UPD_INVALID:
			break; // no action
		default:
			assert(0);
			ret = KNOT_ERROR;
		}
		catalog_it_next(it);
	}
	catalog_it_free(it);
	if (ret == KNOT_EOK) {
		ret = catalog_commit(cat);
	} else {
		catalog_abort(cat);
	}
	return ret;
}

typedef struct {
	const knot_dname_t *zone;
	catalog_update_t *u;
} del_all_ctx_t;

static int del_all_cb(const knot_dname_t *member, const knot_dname_t *owner,
                      const knot_dname_t *catz, _unused_ const char *group, void *dactx)
{
	del_all_ctx_t *ctx = dactx;
	if (knot_dname_is_equal(catz, ctx->zone)) {
		// TODO possible speedup by indexing which member zones belong to a catalog zone
		return catalog_update_add(ctx->u, member, owner, catz, CAT_UPD_REM, NULL, 0, NULL);
	} else {
		return KNOT_EOK;
	}
}

int catalog_update_del_all(catalog_update_t *u, catalog_t *cat, const knot_dname_t *zone, ssize_t *upd_count)
{
	pthread_mutex_lock(&u->mutex);
	del_all_ctx_t ctx = { zone, u };
	*upd_count -= trie_weight(u->upd);
	int ret = catalog_apply(cat, NULL, del_all_cb, &ctx, false);
	*upd_count += trie_weight(u->upd);
	pthread_mutex_unlock(&u->mutex);
	return ret;
}
