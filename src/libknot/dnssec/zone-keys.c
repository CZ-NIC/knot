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
#include "common/errcode.h"
#include "libknot/dname.h"
#include "libknot/dnssec/algorithm.h"
#include "libknot/dnssec/nsec3.h"
#include "libknot/dnssec/sign.h"
#include "libknot/dnssec/zone-keys.h"
#include "libknot/util/debug.h"

/*!
 * \brief Free DNSSEC signing context for each key.
 */
static void free_sign_contexts(knot_zone_keys_t *keys)
{
	assert(keys);

	for (int i = 0; i < keys->count; i++) {
		knot_dnssec_sign_free(keys->contexts[i]);
		keys->contexts[i] = NULL;
	}
}


/*!
 * \brief Initialize DNSSEC signing context for each key.
 */
static int init_sign_contexts(knot_zone_keys_t *keys)
{
	assert(keys);

	for (int i = 0; i < keys->count; i++) {
		keys->contexts[i] = knot_dnssec_sign_init(&keys->keys[i]);
		if (keys->contexts[i] == NULL) {
			free_sign_contexts(keys);
			return KNOT_ENOMEM;
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Check if the key is in active period.
 */
static bool is_current_key(const knot_key_params_t *key)
{
	assert(key);

	time_t now = time(NULL);

	if (now < key->time_activate) {
		return false;
	}

	if (key->time_inactive && now > key->time_inactive) {
		return false;
	}

	return true;
}

/*!
 * \brief Get zone key by a keytag.
 */
const knot_dnssec_key_t *get_zone_key(const knot_zone_keys_t *keys,
                                      uint16_t keytag)
{
	if (!keys) {
		return NULL;
	}

	const knot_dnssec_key_t *result = NULL;

	for (int i = 0; i < keys->count; i++) {
		if (keys->keys[i].keytag == keytag) {
			result = &keys->keys[i];
			break;
		}
	}

	return result;
}

/*!
 * \brief Load zone keys from a key directory.
 *
 * \todo Maybe use dynamic list instead of fixed size array.
 */
int load_zone_keys(const char *keydir_name, const knot_dname_t *zone_name,
		   bool nsec3_enabled, knot_zone_keys_t *keys)
{
	if (!keydir_name || !zone_name || !keys) {
		return KNOT_EINVAL;
	}

	DIR *keydir = opendir(keydir_name);
	if (!keydir) {
		return KNOT_DNSSEC_EINVALID_KEY;
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
			dbg_dnssec_detail("failed to allocate key path\n");
			continue;
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
			dbg_dnssec_detail("failed to load key parameters (%s)\n",
			                  knot_strerror(result));
			knot_free_key_params(&params);
			continue;
		}

		if (!knot_dname_is_equal(zone_name, params.name)) {
			dbg_dnssec_detail("skipping key, different zone name\n");
			knot_free_key_params(&params);
			continue;
		}

		if (!is_current_key(&params)) {
			dbg_dnssec_detail("skipping key, inactive period\n");
			knot_free_key_params(&params);
			continue;
		}

		if (knot_get_key_type(&params) != KNOT_KEY_DNSSEC) {
			dbg_dnssec_detail("skipping key, different purpose\n");
			knot_free_key_params(&params);
			continue;
		}

		if (!knot_dnssec_algorithm_is_zonesign(params.algorithm,
		                                       nsec3_enabled)
		) {
			dbg_dnssec_detail("skipping key, incompatible algorithm\n");
			knot_free_key_params(&params);
			continue;
		}

		if (get_zone_key(keys, params.keytag) != NULL) {
			dbg_dnssec_detail("skipping key, duplicate keytag\n");
			knot_free_key_params(&params);
			continue;
		}

		result = knot_dnssec_key_from_params(&params,
		                                     &keys->keys[keys->count]);
		if (result != KNOT_EOK) {
			dbg_dnssec_detail("cannot create DNSSEC key (%s)\n",
			                  knot_strerror(result));
			knot_free_key_params(&params);
			continue;
		}

		dbg_dnssec_detail("key is valid, tag %d, %s\n", params.keytag,
		                  (params.flags & 1 ? "KSK" : "ZSK"));

		keys->is_ksk[keys->count] = params.flags & 1;
		keys->count += 1;

		knot_free_key_params(&params);
	}

	closedir(keydir);

	if (keys->count == 0) {
		return KNOT_DNSSEC_EINVALID_KEY;
	}

	int result = init_sign_contexts(keys);
	if (result != KNOT_EOK) {
		dbg_dnssec_detail("init_sign_contexts() failed (%s)\n",
		                  knot_strerror(result));
		free_zone_keys(keys);
		return result;
	}

	return KNOT_EOK;
}

void free_zone_keys(knot_zone_keys_t *keys)
{
	if (!keys) {
		return;
	}

	free_sign_contexts(keys);

	for (int i = 0; i < keys->count; i++) {
		knot_dnssec_key_free(&keys->keys[i]);
	}
}
