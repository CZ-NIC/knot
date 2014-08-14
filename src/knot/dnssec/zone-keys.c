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

#include <assert.h>
#include <dirent.h>
#include <stdbool.h>
#include <inttypes.h>

#include "common/debug.h"
#include "common/mem.h"
#include "libknot/errcode.h"
#include "libknot/common.h"
#include "libknot/dname.h"
#include "libknot/consts.h"
#include "libknot/rrtype/dnskey.h"
#include "libknot/dnssec/sign.h"
#include "knot/dnssec/zone-keys.h"

/*!
 * \brief Initialize DNSSEC signing context for each key.
 */
static int init_sign_contexts(knot_zone_keys_t *keys)
{
	assert(keys);

	node_t *node = NULL;
	WALK_LIST(node, keys->list) {
		knot_zone_key_t *key = (knot_zone_key_t *)node;
		key->context = knot_dnssec_sign_init(&key->dnssec_key);
		if (key->context == NULL) {
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

	node_t *node = NULL;
	WALK_LIST(node, keys->list) {
		knot_zone_key_t *key = (knot_zone_key_t *)node;
		if (key->dnssec_key.keytag == keytag) {
			return key;
		}
	}

	return NULL;
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
		if (ts != 0 && now < ts && ts < next_event) {
			next_event = ts;
		}
	}

	key->next_event = next_event;

	key->is_ksk = params->flags & KNOT_RDATA_DNSKEY_FLAG_KSK;

	key->is_active = params->time_activate <= now &&
	                 (params->time_inactive == 0 || now < params->time_inactive);

	key->is_public = params->time_publish <= now &&
	                 (params->time_delete == 0 || now < params->time_delete);
}

/*!
 * \brief Check if there is a functional KSK and ZSK for each used algorithm.
 */
static int check_keys_validity(const knot_zone_keys_t *keys)
{
	assert(keys);

	const int MAX_ALGORITHMS = KNOT_DNSSEC_ALG_ECDSAP384SHA384 + 1;
	struct {
		bool published;
		bool ksk_enabled;
		bool zsk_enabled;
	} algorithms[MAX_ALGORITHMS];
	memset(algorithms, 0, sizeof(algorithms));

	/* Make a list of used algorithms */

	const knot_zone_key_t *key = NULL;
	WALK_LIST(key, keys->list) {
		knot_dnssec_algorithm_t a = key->dnssec_key.algorithm;
		assert(a < MAX_ALGORITHMS);

		if (key->is_public) {
			// public key creates a requirement for an algorithm
			algorithms[a].published = true;

			// need fully enabled ZSK and KSK for each algorithm
			if (key->is_active) {
				if (key->is_ksk) {
					algorithms[a].ksk_enabled = true;
				} else {
					algorithms[a].zsk_enabled = true;
				}
			}
		}
	}

	/* Validate enabled algorithms */

	int enabled_count = 0;
	for (int a = 0; a < MAX_ALGORITHMS; a++) {
		if (!algorithms[a].published) {
			continue;
		}

		if (!algorithms[a].ksk_enabled || !algorithms[a].zsk_enabled) {
			return KNOT_DNSSEC_EMISSINGKEYTYPE;
		}

		enabled_count += 1;
	}

	if (enabled_count == 0) {
		return KNOT_DNSSEC_ENOKEY;
	}

	return KNOT_EOK;
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

	int result = KNOT_EOK;

	struct dirent entry_buf = { 0 };
	struct dirent *entry = NULL;
	while (readdir_r(keydir, &entry_buf, &entry) == 0 && entry != NULL) {

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
			return KNOT_ENOMEM;
		}

		int written = snprintf(path, path_len + 1, "%s/%s",
		                       keydir_name, entry->d_name);
		UNUSED(written);
		assert(written == path_len);

		knot_key_params_t params = { 0 };
		int ret = knot_load_key_params(path, &params);
		free(path);

		if (ret != KNOT_EOK) {
			log_zone_warning(zone_name, "DNSSEC, failed to load "
			                 "key, file '%s' (%s)",
			                 entry->d_name, knot_strerror(ret));
			knot_free_key_params(&params);
			continue;
		}

		if (!knot_dname_is_equal(zone_name, params.name)) {
			knot_free_key_params(&params);
			continue;
		}

		if (knot_get_key_type(&params) != KNOT_KEY_DNSSEC) {
			knot_free_key_params(&params);
			continue;
		}

		knot_zone_key_t *key = malloc(sizeof(*key));
		if (!key) {
			result = KNOT_ENOMEM;
			break;
		}
		memset(key, '\0', sizeof(*key));
		set_zone_key_flags(&params, key);

		if (!knot_dnssec_algorithm_is_zonesign(params.algorithm,
		                                       nsec3_enabled)
		) {
			log_zone_notice(zone_name, "DNSSEC, ignoring key %5d, "
			                "file '%s' (incompatible algorithm)",
			                params.keytag, entry->d_name);
			knot_free_key_params(&params);
			free(key);
			continue;
		}

		if (knot_get_zone_key(keys, params.keytag) != NULL) {
			log_zone_notice(zone_name, "DNSSEC, ignoring key %5d, "
					"file '%s' (duplicate keytag)",
					params.keytag, entry->d_name);
			knot_free_key_params(&params);
			free(key);
			continue;
		}

		ret = knot_dnssec_key_from_params(&params, &key->dnssec_key);
		if (ret != KNOT_EOK) {
			log_zone_error(zone_name, "DNSSEC, failed to process "
				       "key %5d, file '%s' (%s)",
				       params.keytag, entry->d_name,
			               knot_strerror(ret));
			knot_free_key_params(&params);
			free(key);
			continue;
		}

		log_zone_info(zone_name, "DNSSEC, loaded key %5d, file '%s', %s, %s, %s",
		              params.keytag, entry->d_name,
		              key->is_ksk ? "KSK" : "ZSK",
		              key->is_active ? "active" : "inactive",
		              key->is_public ? "public" : "not-public");

		knot_free_key_params(&params);

		add_tail(&keys->list, &key->node);
	}

	closedir(keydir);

	if (result == KNOT_EOK) {
		result = check_keys_validity(keys);
	}

	if (result == KNOT_EOK) {
		result = init_sign_contexts(keys);
	}

	if (result != KNOT_EOK) {
		knot_free_zone_keys(keys);
	}

	return result;
}

void knot_init_zone_keys(knot_zone_keys_t *keys)
{
	if (!keys) {
		return;
	}

	memset(keys, 0, sizeof(*keys));
	init_list(&keys->list);
}

/*!
 * \brief Free structure with zone keys and associated DNSSEC contexts.
 */
void knot_free_zone_keys(knot_zone_keys_t *keys)
{
	if (!keys) {
		return;
	}

	node_t *node = NULL;
	node_t *next = NULL;
	WALK_LIST_DELSAFE(node, next, keys->list) {
		knot_zone_key_t *key = (knot_zone_key_t *)node;
		knot_dnssec_sign_free(key->context);
		knot_dnssec_key_free(&key->dnssec_key);
		free(key);
	}

	init_list(&keys->list);
}

/*!
 * \brief Get timestamp of next key event.
 */
uint32_t knot_get_next_zone_key_event(const knot_zone_keys_t *keys)
{
	uint32_t result = UINT32_MAX;

	node_t *node = NULL;
	WALK_LIST(node, keys->list) {
		knot_zone_key_t *key = (knot_zone_key_t *)node;
		result = MIN(result, key->next_event);
	}

	return result;
}
