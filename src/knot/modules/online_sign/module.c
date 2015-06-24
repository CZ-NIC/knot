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

#include <assert.h>

#include "knot/common/log.h"
#include "knot/conf/base.h"

#include "knot/modules/online_sign/module.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/internet.h"

#include "libknot/internal/mem.h"
#include "dnssec/error.h"
#include "dnssec/kasp.h"
#include "dnssec/sign.h"
const yp_item_t scheme_mod_online_sign[] = {
	{ C_ID, YP_TSTR, YP_VNONE },
	{ NULL }
};

struct online_sign_ctx {
	dnssec_key_t *key;
	knot_rrset_t *dnskey_rrset;
};

typedef struct online_sign_ctx online_sign_ctx_t;

static int get_dnssec_key(dnssec_key_t **key_ptr,
                          const knot_dname_t *zone_name,
                          const char *kasp_path)
{
	// KASP database

	dnssec_kasp_t *kasp = NULL;
	int r = dnssec_kasp_init_dir(&kasp);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = dnssec_kasp_open(kasp, kasp_path);
	if (r != DNSSEC_EOK) {
		dnssec_kasp_deinit(kasp);
		return r;
	}

	// KASP zone

	char *zone_str = knot_dname_to_str_alloc(zone_name);
	if (!zone_str) {
		dnssec_kasp_deinit(kasp);
		return KNOT_ENOMEM;
	}

	dnssec_kasp_zone_t *zone = NULL;
	r = dnssec_kasp_zone_load(kasp, zone_str, &zone);
	free(zone_str);
	if (r != DNSSEC_EOK) {
		dnssec_kasp_deinit(kasp);
		return r;
	}

	// DNSSEC key

	dnssec_list_t *list = dnssec_kasp_zone_get_keys(zone);
	assert(list);
	dnssec_item_t *item = dnssec_list_nth(list, 0);
	if (!item) {
		dnssec_kasp_zone_free(zone);
		dnssec_kasp_deinit(kasp);
		return DNSSEC_NOT_FOUND;
	}

	dnssec_kasp_key_t *kasp_key = dnssec_item_get(item);
	assert(kasp_key);
	dnssec_key_t *key = dnssec_key_dup(kasp_key->key);

	dnssec_kasp_zone_free(zone);
	dnssec_kasp_deinit(kasp);

	if (!key) {
		return KNOT_ENOMEM;
	}

	*key_ptr = key;
	return KNOT_EOK;
}

static int load_private_key(dnssec_key_t *key, const char *kasp_path)
{
	char *keystore_path = sprintf_alloc("%s/keys", kasp_path);
	if (!keystore_path) {
		return KNOT_ENOMEM;
	}

	dnssec_keystore_t *store = NULL;
	dnssec_keystore_init_pkcs8_dir(&store);
	int r = dnssec_keystore_open(store, keystore_path);
	free(keystore_path);
	if (r != DNSSEC_EOK) {
		dnssec_keystore_deinit(store);
		return r;
	}

	r = dnssec_key_import_private_keystore(key, store);
	dnssec_keystore_deinit(store);

	return r;
}

static int get_online_key(dnssec_key_t **key_ptr, const knot_dname_t *zone_name,
                          const char *kasp_path)
{
	dnssec_key_t *key = NULL;

	int r = get_dnssec_key(&key, zone_name, kasp_path);
	if (r != KNOT_EOK) {
		return r;
	}

	r = load_private_key(key, kasp_path);
	if (r != DNSSEC_EOK) {
		dnssec_key_free(key);
		return r;
	}

	*key_ptr = key;

	return KNOT_EOK;
}

static char *conf_kasp_path(const knot_dname_t *zone)
{
	conf_val_t val = { 0 };

	val = conf_zone_get(conf(), C_STORAGE, zone);
	char *storage = conf_abs_path(&val, NULL);
	val = conf_zone_get(conf(), C_KASP_DB, zone);
	char *kasp_db = conf_abs_path(&val, storage);
	free(storage);

	return kasp_db;
}

int online_sign_load(struct query_plan *plan, struct query_module *module,
                     const knot_dname_t *zone)
{
	assert(plan);
	assert(module);
	assert(zone);

	log_zone_info(zone, "online signing initialized");

	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone);
	if (conf_bool(&val)) {
		log_zone_error(zone, "online signing, incompatible with automatic signing");
		return KNOT_ENOTSUP;
	}

	char *kasp_path = conf_kasp_path(zone);
	if (!kasp_path) {
		log_zone_error(zone, "online signing, KASP database is not configured");
		return KNOT_ERROR;
	}

	online_sign_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		free(kasp_path);
		return KNOT_ENOMEM;
	}

	int r = get_online_key(&ctx->key, zone, kasp_path);
	free(kasp_path);
	if (r != KNOT_EOK) {
		free(ctx);
		log_zone_error(zone, "online signing, failed to load signing key (%s)", dnssec_strerror(r));
		return KNOT_ERROR;
	}

	module->ctx = ctx;

	return KNOT_EOK;
}

int online_sign_unload(struct query_module *module)
{
	assert(module);

	online_sign_ctx_t *ctx = module->ctx;

	dnssec_key_free(ctx->key);

	free(module->ctx);

	return KNOT_EOK;
}
