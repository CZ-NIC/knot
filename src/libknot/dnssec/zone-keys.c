/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <assert.h>
#include <dirent.h>
#include <stdbool.h>
#include <inttypes.h>
#include "common/errcode.h"
#include "libknot/dname.h"
#include "libknot/consts.h"
#include "libknot/dnssec/nsec3.h"
#include "libknot/dnssec/sign.h"
#include "libknot/dnssec/zone-keys.h"
#include "libknot/rdata.h"
#include "libknot/util/debug.h"

/*!
 * \brief Free DNSSEC signing context for each key.
 */
static void free_sign_contexts(knot_zone_keys_t *keys)
{
	assert(keys);

	for (int i = 0; i < keys->count; i++) {
		knot_dnssec_sign_free(keys->keys[i].context);
		keys->keys[i].context = NULL;
	}
}


/*!
 * \brief Initialize DNSSEC signing context for each key.
 */
static int init_sign_contexts(knot_zone_keys_t *keys)
{
	assert(keys);

	for (int i = 0; i < keys->count; i++) {
		knot_zone_key_t *key = &keys->keys[i];
		key->context = knot_dnssec_sign_init(&key->dnssec_key);
		if (key->context == NULL) {
			free_sign_contexts(keys);
			return KNOT_ENOMEM;
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Get zone key by a keytag.
 */
const knot_zone_key_t *knot_get_zone_key(const knot_zone_keys_t *keys,
                                         uint16_t keytag)
{
	if (!keys) {
		return NULL;
	}

	const knot_zone_key_t *result = NULL;

	for (int i = 0; i < keys->count; i++) {
		const knot_zone_key_t *key = &keys->keys[i];
		if (key->dnssec_key.keytag == keytag) {
			result = key;
			break;
		}
	}

	return result;
}

/*!
 * \brief Get key feature flags from key parameters.
 */
static void set_zone_key_flags(const knot_key_params_t *params,
                               knot_zone_key_t *key)
{
	assert(params);
	assert(key);

	uint32_t now = time(NULL);

	uint32_t next_event = UINT32_MAX;
	uint32_t timestamps[4] = {
		params->time_publish,
		params->time_activate,
		params->time_inactive,
		params->time_delete
	};

	for (int i = 0; i < 4; i++) {
		uint32_t ts = timestamps[i];
		if (ts != 0 && now <= ts && ts < next_event) {
			next_event = ts;
		}
	}

	key->next_event = next_event;

	key->is_ksk = params->flags & KNOT_RDATA_DNSKEY_FLAG_KSK;

	key->is_active = params->time_activate <= now &&
	                 (params->time_inactive == 0 || now <= params->time_inactive);

	key->is_public = params->time_publish <= now &&
	                 (params->time_delete == 0 || now <= params->time_delete);
}

/*!
 * \brief Check if key should be already removed from the zone.
 */
static bool was_removed(const knot_key_params_t *params)
{
	assert(params);

	time_t now = time(NULL);

	return params->time_delete != 0 && now > params->time_delete;
}

/*!
 * \brief Load zone keys from a key directory.
 *
 * \todo Maybe use dynamic list instead of fixed size array.
 */
int knot_load_zone_keys(const char *keydir_name, const knot_dname_t *zone_name,
                        bool nsec3_enabled, knot_zone_keys_t *keys)
{
	if (!keydir_name || !zone_name || !keys) {
		return KNOT_EINVAL;
	}

	DIR *keydir = opendir(keydir_name);
	if (!keydir) {
		return KNOT_DNSSEC_ENOKEYDIR;
	}

	char *zname = knot_dname_to_str(zone_name);
	char *msgpref = sprintf_alloc("DNSSEC: Zone %s -", zname);
	free(zname);
	if (msgpref == NULL) {
		closedir(keydir);
		return KNOT_ENOMEM;
	}

	struct dirent entry_buf = { 0 };
	struct dirent *entry = NULL;
	while (keys->count < KNOT_MAX_ZONE_KEYS &&
	       readdir_r(keydir, &entry_buf, &entry) == 0 &&
	       entry != NULL) {

		char *suffix = strrchr(entry->d_name, '.');
		if (!suffix) {
			continue;
		}

		if (strcmp(suffix, ".private") != 0) {
			continue;
		}

		size_t path_len = strlen(keydir_name) + 1 + strlen(entry->d_name);
		char *path = malloc((path_len + 1) * sizeof(char));
		if (!path) {
			ERR_ALLOC_FAILED;
			closedir(keydir);
			free(msgpref);
			return KNOT_ENOMEM;
		}

		int written = snprintf(path, path_len + 1, "%s/%s",
		                       keydir_name, entry->d_name);
		UNUSED(written);
		assert(written == path_len);

		dbg_dnssec_detail("loading key '%s'\n", path);

		knot_key_params_t params = { 0 };
		int result = knot_load_key_params(path, &params);
		free(path);

		if (result != KNOT_EOK) {
			log_zone_warning("DNSSEC: Failed to load key %s: %s\n",
			                  entry->d_name, knot_strerror(result));
			knot_free_key_params(&params);
			continue;
		}

		if (!knot_dname_is_equal(zone_name, params.name)) {
			dbg_dnssec_detail("skipping key, different zone name\n");
			knot_free_key_params(&params);
			continue;
		}

		if (knot_get_key_type(&params) != KNOT_KEY_DNSSEC) {
			dbg_dnssec_detail("skipping key, different purpose\n");
			knot_free_key_params(&params);
			continue;
		}

		knot_zone_key_t key;
		memset(&key, '\0', sizeof(key));
		set_zone_key_flags(&params, &key);

		dbg_dnssec_detail("next key event %" PRIu32 "\n", key.next_event);

		if (!key.is_active && !key.is_public && !was_removed(&params)) {
			log_zone_notice("%s Ignoring key %d (%s): "
			                "%s, %s.\n", msgpref, params.keytag,
			                entry->d_name,
			                key.is_active ? "active" : "inactive",
			                key.is_public ? "public" : "not-public");
			knot_free_key_params(&params);
			continue;
		}

		if (!knot_dnssec_algorithm_is_zonesign(params.algorithm,
		                                       nsec3_enabled)
		) {
			log_zone_notice("%s Ignoring key %d (%s): unknown "
			                "algorithm or non-NSEC3 algrorithm when"
			                "NSEC is requested.\n", msgpref,
			                params.keytag, entry->d_name);
			knot_free_key_params(&params);
			continue;
		}

		if (knot_get_zone_key(keys, params.keytag) != NULL) {
			log_zone_notice("%s Ignoring key %d (%s): duplicate "
			                "keytag.\n", msgpref, params.keytag,
			                entry->d_name);
			knot_free_key_params(&params);
			continue;
		}

		result = knot_dnssec_key_from_params(&params, &key.dnssec_key);
		if (result != KNOT_EOK) {
			log_zone_error("%s Failed to process key %d (%s): %s\n",
			               msgpref, params.keytag, entry->d_name,
			               knot_strerror(result));
			knot_free_key_params(&params);
			continue;
		}

		log_zone_info("%s - Key is valid, tag %d, file %s, %s, %s, %s\n",
		              msgpref, params.keytag, entry->d_name,
		              key.is_ksk ? "KSK" : "ZSK",
		              key.is_active ? "active" : "inactive",
		              key.is_public ? "public" : "not-public");

		keys->keys[keys->count] = key;
		keys->count += 1;

		knot_free_key_params(&params);
	}

	closedir(keydir);

	if (keys->count == 0) {
		free(msgpref);
		return KNOT_DNSSEC_ENOKEY;
	} else if (keys->count == KNOT_MAX_ZONE_KEYS) {
		log_zone_notice("%s - Reached maximum count of keys.\n",
		                msgpref);
	}
	free(msgpref);

	int result = init_sign_contexts(keys);
	if (result != KNOT_EOK) {
		knot_free_zone_keys(keys);
		return result;
	}

	return KNOT_EOK;
}

/*!
 * \brief Free structure with zone keys and associated DNSSEC contexts.
 */
void knot_free_zone_keys(knot_zone_keys_t *keys)
{
	if (!keys) {
		return;
	}

	free_sign_contexts(keys);

	for (int i = 0; i < keys->count; i++) {
		knot_dnssec_key_free(&keys->keys[i].dnssec_key);
	}

	memset(keys, '\0', sizeof(*keys));
}

/*!
 * \brief Get timestamp of next key event.
 */
uint32_t knot_get_next_zone_key_event(const knot_zone_keys_t *keys)
{
	uint32_t result = UINT32_MAX;

	for (int i = 0; i < keys->count; i++) {
		result = MIN(result, keys->keys[i].next_event);
	}

	return result;
}
