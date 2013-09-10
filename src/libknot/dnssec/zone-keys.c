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
#include <stdio.h> // TMP
#include "common/errcode.h"
#include "libknot/dname.h"
#include "libknot/dnssec/sign.h"
#include "libknot/dnssec/zone-keys.h"

static void free_sign_contexts(knot_zone_keys_t *keys)
{
	for (int i = 0; i < keys->count; i++) {
		knot_dnssec_sign_free(keys->contexts[i]);
		keys->contexts[i] = NULL;
	}
}


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
	time_t now = time(NULL);

	if (now < key->time_activate)
		return false;

	if (key->time_inactive && now > key->time_inactive)
		return false;

	return true;
}

/*!
 * \brief Load zone keys from a key directory.
 *
 * \todo Remove fprintf()
 * \todo Check for duplicate key tags
 * \todo Maybe use dynamic list instead of fixed size array.
 */
int load_zone_keys(const char *keydir_name, const knot_dname_t *zone_name,
		   knot_zone_keys_t *keys)
{
	assert(keydir_name);
	assert(zone_name);
	assert(keys);

	DIR *keydir = opendir(keydir_name);
	if (!keydir)
		return KNOT_DNSSEC_EINVALID_KEY;

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

		size_t path_len = strlen(keydir_name) + 1
		                + strlen(entry->d_name) + 1;
		char *path = malloc(path_len * sizeof(char));
		if (!path) {
			fprintf(stderr, "failed to alloc key path\n");
			continue;
		}

		snprintf(path, path_len, "%s/%s", keydir_name, entry->d_name);
		fprintf(stderr, "reading key '%s'\n", path);

		knot_key_params_t params = { 0 };
		int result = knot_load_key_params(path, &params);
		free(path);

		if (result != KNOT_EOK) {
			fprintf(stderr, "failed to load key params\n");
			knot_free_key_params(&params);
			continue;
		}

		if (!knot_dname_is_equal(zone_name, params.name)) {
			fprintf(stderr, "key for other zone\n");
			knot_free_key_params(&params);
			continue;
		}

		if (!is_current_key(&params)) {
			fprintf(stderr, "key is not active\n");
			knot_free_key_params(&params);
			continue;
		}

		if (knot_get_key_type(&params) != KNOT_KEY_DNSSEC) {
			fprintf(stderr, "not a DNSSEC key\n");
			knot_free_key_params(&params);
			continue;
		}

		result = knot_dnssec_key_from_params(&params,
		                                     &keys->keys[keys->count]);
		if (result != KNOT_EOK) {
			fprintf(stderr, "cannot create the dnssec key\n");
			knot_free_key_params(&params);
			continue;
		}

		fprintf(stderr, "key is valid\n");
		fprintf(stderr, "key is %s\n", params.flags & 1 ? "ksk" : "zsk");

		keys->is_ksk[keys->count] = params.flags & 1;
		keys->count += 1;

		// Cleanup key parameters
		knot_free_key_params(&params);
	}

	closedir(keydir);

	if (keys->count == 0) {
		return KNOT_DNSSEC_EINVALID_KEY;
	}

	int result = init_sign_contexts(keys);
	if (result != KNOT_EOK) {
		fprintf(stderr, "init_sign_contexts() failed\n");
		free_zone_keys(keys);
		return result;
	}

	return KNOT_EOK;
}

void free_zone_keys(knot_zone_keys_t *keys)
{
	free_sign_contexts(keys);

	for (int i = 0; i < keys->count; i++) {
		knot_dnssec_key_free(&keys->keys[i]);
	}
}
