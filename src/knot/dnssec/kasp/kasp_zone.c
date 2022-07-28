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

#include "knot/dnssec/kasp/kasp_zone.h"
#include "knot/dnssec/kasp/keystore.h"
#include "knot/dnssec/zone-keys.h"
#include "libdnssec/binary.h"

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

/*! \brief Determine presence of SEP bit by trial-end-error using known keytag. */
static int dnskey_guess_flags(dnssec_key_t *key, uint16_t keytag)
{
	dnssec_key_set_flags(key, DNSKEY_FLAGS_KSK);
	if (dnssec_key_get_keytag(key) == keytag) {
		return KNOT_EOK;
	}

	dnssec_key_set_flags(key, DNSKEY_FLAGS_ZSK);
	if (dnssec_key_get_keytag(key) == keytag) {
		return KNOT_EOK;
	}

	dnssec_key_set_flags(key, DNSKEY_FLAGS_REVOKED);
	if (dnssec_key_get_keytag(key) == keytag) {
		return KNOT_EOK;
	}

	return KNOT_EMALF;
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

	ret = dnssec_key_set_pubkey(key, &params->public_key);
	if (ret != KNOT_EOK) {
		dnssec_key_free(key);
		return knot_error_from_libdnssec(ret);
	}

	ret = dnskey_guess_flags(key, params->keytag);
	if (ret != KNOT_EOK) {
		dnssec_key_free(key);
		return ret;
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
	params->is_ksk = key->is_ksk;
	params->is_csk = (key->is_ksk && key->is_zsk);
	params->timing = key->timing;
	params->is_pub_only = key->is_pub_only;
}

static void detect_keytag_conflict(knot_kasp_zone_t *zone, bool *kt_cfl)
{
	*kt_cfl = false;
	if (zone->num_keys == 0) {
		return;
	}
	uint16_t keytags[zone->num_keys];
	for (size_t i = 0; i < zone->num_keys; i++) {
		keytags[i] = dnssec_key_get_keytag(zone->keys[i].key);
		for (size_t j = 0; j < i; j++) {
			if (keytags[j] == keytags[i]) {
				*kt_cfl = true;
				return;
			}
		}
	}
}

int kasp_zone_load(knot_kasp_zone_t *zone,
                   const knot_dname_t *zone_name,
                   knot_lmdb_db_t *kdb,
                   bool *kt_cfl)
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

	detect_keytag_conflict(zone, kt_cfl);

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
		   knot_lmdb_db_t *kdb)
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


	return kasp_db_store_nsec3salt(kdb, zone_name, &zone->nsec3_salt,
	                               zone->nsec3_salt_created);
}

static void kasp_zone_clear_keys(knot_kasp_zone_t *zone)
{
	for (size_t i = 0; i < zone->num_keys; i++) {
		dnssec_key_free(zone->keys[i].key);
		free(zone->keys[i].id);
	}
	free(zone->keys);
	zone->keys = NULL;
	zone->num_keys = 0;
}

void kasp_zone_clear(knot_kasp_zone_t *zone)
{
	if (zone == NULL) {
		return;
	}
	knot_dname_free(zone->dname, NULL);
	kasp_zone_clear_keys(zone);
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

int zone_init_keystore(conf_t *conf, conf_val_t *policy_id,
                       dnssec_keystore_t **keystore, unsigned *backend, bool *key_label)
{
	char *zone_path = conf_db(conf, C_KASP_DB);
	if (zone_path == NULL) {
		return KNOT_ENOMEM;
	}

	conf_id_fix_default(policy_id);

	conf_val_t keystore_id = conf_id_get(conf, C_POLICY, C_KEYSTORE, policy_id);
	conf_id_fix_default(&keystore_id);

	conf_val_t val = conf_id_get(conf, C_KEYSTORE, C_BACKEND, &keystore_id);
	unsigned _backend = conf_opt(&val);

	val = conf_id_get(conf, C_KEYSTORE, C_CONFIG, &keystore_id);
	const char *config = conf_str(&val);

	if (key_label != NULL) {
		val = conf_id_get(conf, C_KEYSTORE, C_KEY_LABEL, &keystore_id);
		*key_label = conf_bool(&val);
	}

	int ret = keystore_load(config, _backend, zone_path, keystore);

	if (backend != NULL) {
		*backend = _backend;
	}

	free(zone_path);
	return ret;
}

int kasp_zone_keys_from_rr(knot_kasp_zone_t *zone,
                           const knot_rdataset_t *zone_dnskey,
                           bool policy_single_type_signing,
                           bool *keytag_conflict)
{
	if (zone == NULL || zone_dnskey == NULL || keytag_conflict == NULL) {
		return KNOT_EINVAL;
	}

	kasp_zone_clear_keys(zone);

	zone->num_keys = zone_dnskey->count;
	zone->keys = calloc(zone->num_keys, sizeof(*zone->keys));
	if (zone->keys == NULL) {
		zone->num_keys = 0;
		return KNOT_ENOMEM;
	}

	knot_rdata_t *zkey = zone_dnskey->rdata;
	for (int i = 0; i < zone->num_keys; i++) {
		int ret = dnssec_key_from_rdata(&zone->keys[i].key, zone->dname,
		                                zkey->data, zkey->len);
		if (ret == KNOT_EOK) {
			ret = dnssec_key_get_keyid(zone->keys[i].key, &zone->keys[i].id);
		}
		if (ret != KNOT_EOK) {
			free(zone->keys);
			zone->keys = NULL;
			zone->num_keys = 0;
			return ret;
		}
		zone->keys[i].is_pub_only = true;

		zone->keys[i].is_ksk = (knot_dnskey_flags(zkey) == DNSKEY_FLAGS_KSK);
		zone->keys[i].is_zsk = policy_single_type_signing || !zone->keys[i].is_ksk;

		zone->keys[i].timing.publish = 1;
		zone->keys[i].timing.active = 1;

		zkey = knot_rdataset_next(zkey);
	}

	detect_keytag_conflict(zone, keytag_conflict);
	return KNOT_EOK;
}

int kasp_zone_from_contents(knot_kasp_zone_t *zone,
                            const zone_contents_t *contents,
                            bool policy_single_type_signing,
                            bool policy_nsec3,
                            uint16_t *policy_nsec3_iters,
                            bool *keytag_conflict)
{
	if (zone == NULL || contents == NULL || contents->apex == NULL) {
		return KNOT_EINVAL;
	}

	memset(zone, 0, sizeof(*zone));
	zone->dname = knot_dname_copy(contents->apex->owner, NULL);
	if (zone->dname == NULL) {
		return KNOT_ENOMEM;
	}

	knot_rdataset_t *zone_dnskey = node_rdataset(contents->apex, KNOT_RRTYPE_DNSKEY);
	if (zone_dnskey == NULL || zone_dnskey->count < 1) {
		free(zone->dname);
		return KNOT_DNSSEC_ENOKEY;
	}

	int ret = kasp_zone_keys_from_rr(zone, zone_dnskey, policy_single_type_signing, keytag_conflict);
	if (ret != KNOT_EOK) {
		free(zone->dname);
		return ret;
	}

	zone->nsec3_salt_created = 0;
	if (policy_nsec3) {
		knot_rdataset_t *zone_ns3p = node_rdataset(contents->apex, KNOT_RRTYPE_NSEC3PARAM);
		if (zone_ns3p == NULL || zone_ns3p->count != 1) {
			kasp_zone_clear(zone);
			return KNOT_ENSEC3PAR;
		}
		zone->nsec3_salt.size = knot_nsec3param_salt_len(zone_ns3p->rdata);
		zone->nsec3_salt.data = malloc(zone->nsec3_salt.size);
		if (zone->nsec3_salt.data == NULL) {
			kasp_zone_clear(zone);
			return KNOT_ENOMEM;
		}
		memcpy(zone->nsec3_salt.data,
		       knot_nsec3param_salt(zone_ns3p->rdata),
		       zone->nsec3_salt.size);

		*policy_nsec3_iters = knot_nsec3param_iters(zone_ns3p->rdata);
	}

	return KNOT_EOK;
}
