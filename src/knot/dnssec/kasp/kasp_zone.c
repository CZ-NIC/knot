/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/dnssec/kasp/kasp_zone.h"
#include "knot/dnssec/zone-keys.h"
#include "dnssec/lib/dnssec/binary.h"

// FIXME DNSSEC errors versus knot errors

/*!
 * Check if key parameters allow to create a key.
 */
static int key_params_check(key_params_t *params)
{
	assert(params);

	if (params->algorithm == 0) {
		return KNOT_INVALID_KEY_ALGORITHM;
	}

	if (params->public_key.size == 0) {
		return KNOT_NO_PUBLIC_KEY;
	}

	return KNOT_EOK;
}

static int params2dnskey(const knot_dname_t *dname, key_params_t *params,
			 dnssec_key_t **key_ptr)
{
	assert(dname);
	assert(params);
	assert(key_ptr);

	int ret = key_params_check(params);
	if (ret != KNOT_EOK) {
		return ret;
	}

	dnssec_key_t *key = NULL;
	ret = dnssec_key_new(&key);
	if (ret != KNOT_EOK) {
		return knot_error_from_libdnssec(ret);
	}

	ret = dnssec_key_set_dname(key, dname);
	if (ret != KNOT_EOK) {
		dnssec_key_free(key);
		return knot_error_from_libdnssec(ret);
	}

	dnssec_key_set_algorithm(key, params->algorithm);

	uint16_t flags = dnskey_flags(params->is_ksk);
	dnssec_key_set_flags(key, flags);

	ret = dnssec_key_set_pubkey(key, &params->public_key);
	if (ret != KNOT_EOK) {
		dnssec_key_free(key);
		return knot_error_from_libdnssec(ret);
	}

	*key_ptr = key;

	return KNOT_EOK;
}

static int params2kaspkey(const knot_dname_t *dname, key_params_t *params,
			  knot_kasp_key_t *key)
{
	assert(dname != NULL);
	assert(params != NULL);
	assert(key != NULL);

	int ret = params2dnskey(dname, params, &key->key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	key->id = strdup(params->id);
	if (key->id == NULL) {
		dnssec_key_free(key->key);
		return KNOT_ENOMEM;
	}

	key->timing = params->timing;
	key->is_pub_only = params->is_pub_only;
	assert(params->is_ksk || !params->is_csk);
	key->is_ksk = params->is_ksk;
	key->is_zsk = (params->is_csk || !params->is_ksk);
	return KNOT_EOK;
}

static void kaspkey2params(knot_kasp_key_t *key, key_params_t *params)
{
	assert(key);
	assert(params);

	params->id = key->id;
	params->keytag = dnssec_key_get_keytag(key->key);
	dnssec_key_get_pubkey(key->key, &params->public_key);
	params->algorithm = dnssec_key_get_algorithm(key->key);
	params->is_ksk = dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_KSK;
	assert(params->is_ksk == key->is_ksk);
	params->is_csk = (key->is_ksk && key->is_zsk);
	params->timing = key->timing;
	params->is_pub_only = key->is_pub_only;
}

int kasp_zone_load(knot_kasp_zone_t *zone,
		   const knot_dname_t *zone_name,
		   kasp_db_t *kdb)
{
	if (zone == NULL || zone_name == NULL || kdb == NULL) {
	return KNOT_EINVAL;
	}

	knot_kasp_key_t *dkeys = NULL;
	size_t num_dkeys = 0;
	dnssec_binary_t salt = { 0 };
	knot_time_t sc = 0;

	list_t key_params;
	init_list(&key_params);
	int ret = kasp_db_list_keys(kdb, zone_name, &key_params);
	if (ret == KNOT_ENOENT) {
		zone->keys = NULL;
		zone->num_keys = 0;
		ret = KNOT_EOK;
		goto kzl_salt;
	} else if (ret != KNOT_EOK) {
		goto kzl_end;
	}

	num_dkeys = list_size(&key_params);
	dkeys = calloc(num_dkeys, sizeof(*dkeys));
	if (dkeys == NULL) {
		goto kzl_end;
	}

	ptrnode_t *n;
	int i = 0;
	WALK_LIST(n, key_params) {
		key_params_t *parm = n->d;
		ret = params2kaspkey(zone_name, parm, &dkeys[i++]);
		free_key_params(parm);
		if (ret != KNOT_EOK) {
			goto kzl_end;
		}
	}

kzl_salt:
	(void)kasp_db_load_nsec3salt(kdb, zone_name, &salt, &sc);
	// if error, salt was probably not present, no problem to have zero ?

	zone->dname = knot_dname_copy(zone_name, NULL);
	if (zone->dname == NULL) {
		ret = KNOT_ENOMEM;
		goto kzl_end;
	}
	zone->keys = dkeys;
	zone->num_keys = num_dkeys;
	zone->nsec3_salt = salt;
	zone->nsec3_salt_created = sc;

kzl_end:
	ptrlist_deep_free(&key_params, NULL);
	if (ret != KNOT_EOK) {
		free(dkeys);
	}
	return ret;
}

int kasp_zone_append(knot_kasp_zone_t *zone, const knot_kasp_key_t *appkey)
{
	if (zone == NULL || appkey == NULL || (zone->keys == NULL && zone->num_keys > 0)) {
		return KNOT_EINVAL;
	}

	size_t new_num_keys = zone->num_keys + 1;
	knot_kasp_key_t *new_keys = calloc(new_num_keys, sizeof(*new_keys));
	if (!new_keys) {
		return KNOT_ENOMEM;
	}
	if (zone->num_keys > 0) {
		memcpy(new_keys, zone->keys, zone->num_keys * sizeof(*new_keys));
	}
	memcpy(&new_keys[new_num_keys - 1], appkey, sizeof(*appkey));
	free(zone->keys);
	zone->keys = new_keys;
	zone->num_keys = new_num_keys;
	return KNOT_EOK;
}

int kasp_zone_save(const knot_kasp_zone_t *zone,
		   const knot_dname_t *zone_name,
		   kasp_db_t *kdb)
{
	if (zone == NULL || zone_name == NULL || kdb == NULL) {
		return KNOT_EINVAL;
	}

	key_params_t parm;
	for (size_t i = 0; i < zone->num_keys; i++) {
		kaspkey2params(&zone->keys[i], &parm);

		// Force overwrite already existing key-val pairs.
		int ret = kasp_db_add_key(kdb, zone_name, &parm);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (zone->nsec3_salt.size > 0) {
		int ret = kasp_db_store_nsec3salt(kdb, zone_name, &zone->nsec3_salt,
		                                  zone->nsec3_salt_created);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

int kasp_zone_init(knot_kasp_zone_t **zone)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}
	*zone = calloc(1, sizeof(**zone));
	return (*zone ? KNOT_EOK : KNOT_ENOMEM);
}

void kasp_zone_clear(knot_kasp_zone_t *zone)
{
	if (zone == NULL) {
		return;
	}
	knot_dname_free(&zone->dname, NULL);
	for (size_t i = 0; i < zone->num_keys; i++) {
		dnssec_key_free(zone->keys[i].key);
		free(zone->keys[i].id);
	}
	free(zone->keys);
	free(zone->nsec3_salt.data);
	memset(zone, 0, sizeof(*zone));
}

void kasp_zone_free(knot_kasp_zone_t **zone)
{
	if (zone != NULL) {
		kasp_zone_clear(*zone);
		free(*zone);
		*zone = NULL;
	}
}

void free_key_params(key_params_t *parm)
{
	if (parm != NULL) {
		free(parm->id);
		dnssec_binary_free(&parm->public_key);
		memset(parm, 0 , sizeof(*parm));
	}
}
