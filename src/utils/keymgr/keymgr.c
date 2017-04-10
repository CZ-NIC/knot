/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <dnssec/crypto.h>
#include <dnssec/error.h>
#include <dnssec/kasp.h>
#include <dnssec/keystore.h>
#include <dnssec/tsig.h>
#include <dnssec/key.h>
#include <dnssec/keystate.h>

#include "cmdparse/command.h"
#include "cmdparse/parameter.h"
#include "cmdparse/value.h"
#include "contrib/strtonum.h"
#include "legacy/key.h"
#include "options.h"
#include "shared/dname.h"
#include "shared/print.h"
#include "shared/shared.h"
#include "shared/wire.h"

#define PROGRAM_NAME "keymgr"

#define DEFAULT_POLICY "default"
#define DEFAULT_KEYSTORE "default"

#define MANUAL_POLICY "default_manual"

static const uint16_t DNSKEY_FLAGS_KSK = 257;
static const uint16_t DNSKEY_FLAGS_ZSK = 256;

/* -- global options ------------------------------------------------------- */

static options_t options = { 0 };

/* -- internal ------------------------------------------------------------- */

static void cleanup_kasp(dnssec_kasp_t **kasp_ptr)
{
	dnssec_kasp_deinit(*kasp_ptr);
}

static void cleanup_kasp_keystore(dnssec_kasp_keystore_t **keystore_ptr)
{
	dnssec_kasp_keystore_free(*keystore_ptr);
}

static void cleanup_keystore(dnssec_keystore_t **keystore_ptr)
{
	dnssec_keystore_deinit(*keystore_ptr);
}

static void cleanup_kasp_zone(dnssec_kasp_zone_t **zone_ptr)
{
	dnssec_kasp_zone_free(*zone_ptr);
}

static void cleanup_kasp_policy(dnssec_kasp_policy_t **policy_ptr)
{
	dnssec_kasp_policy_free(*policy_ptr);
}

static void cleanup_list(dnssec_list_t **list_ptr)
{
	dnssec_list_free_full(*list_ptr, NULL, NULL);
}

#define _cleanup_kasp_ _cleanup_(cleanup_kasp)
#define _cleanup_kasp_keystore_ _cleanup_(cleanup_kasp_keystore)
#define _cleanup_keystore_ _cleanup_(cleanup_keystore)
#define _cleanup_zone_ _cleanup_(cleanup_kasp_zone)
#define _cleanup_policy_ _cleanup_(cleanup_kasp_policy)
#define _cleanup_list_ _cleanup_(cleanup_list)

/* -- frequent operations -------------------------------------------------- */

static dnssec_kasp_t *get_zone_kasp(const char *zone_name)
{
	int r = options_zone_kasp_path(&options, zone_name);
	if (r != DNSSEC_EOK) {
		return NULL;
	}

	dnssec_kasp_t *kasp = NULL;

	r = options_zone_kasp_init(&options, zone_name, &kasp);
	if (r != DNSSEC_EOK) {
		return NULL;
	}

	r = dnssec_kasp_open(kasp, options.kasp_dir);
	if (r != DNSSEC_EOK) {
		error("Cannot open KASP directory (%s).", dnssec_strerror(r));
		dnssec_kasp_deinit(kasp);
		return NULL;
	}

	return kasp;
}

static dnssec_kasp_t *get_kasp(void)
{
	return get_zone_kasp(NULL);
}

static dnssec_kasp_zone_t *get_zone(dnssec_kasp_t *kasp, const char *name)
{
	dnssec_kasp_zone_t *zone = NULL;
	int r = dnssec_kasp_zone_load(kasp, name, &zone);
	if (r != DNSSEC_EOK) {
		error("Cannot retrieve zone from KASP (%s).", dnssec_strerror(r));
		return NULL;
	}

	return zone;
}

static dnssec_kasp_policy_t *get_policy(dnssec_kasp_t *kasp, const char *name)
{
	dnssec_kasp_policy_t *policy = NULL;
	int r = dnssec_kasp_policy_load(kasp, name, &policy);
	if (r != DNSSEC_EOK) {
		error("Cannot retrieve policy from KASP (%s).", dnssec_strerror(r));
		return NULL;
	}

	return policy;
}

static dnssec_keystore_t *get_keystore(dnssec_kasp_t *kasp, const char *name)
{
	_cleanup_kasp_keystore_ dnssec_kasp_keystore_t *config = NULL;
	int r = dnssec_kasp_keystore_load(kasp, name, &config);
	if (r != DNSSEC_EOK) {
		error("Cannot load key store '%s' configuration. (%s)",
		      name, dnssec_strerror(r));
		return NULL;
	}

	dnssec_keystore_t *store = NULL;
	r = dnssec_kasp_keystore_open(kasp, config->backend, config->config, &store);
	if (r != DNSSEC_EOK) {
		error("Cannot open private key store '%s' (%s).", name, dnssec_strerror(r));
		return NULL;
	}

	return store;
}

static bool zone_add_dnskey(dnssec_kasp_zone_t *zone, const char *id,
			    dnssec_key_t *dnskey,
			    const dnssec_kasp_key_timing_t *timing)
{
	dnssec_kasp_key_t *key = calloc(1, sizeof(*key));
	if (!key) {
		error("Failed to create a zone key (out of memory).");
		return false;
	}

	key->id = strdup(id);
	key->key = dnskey;
	key->timing = *timing;

	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(zone);
	dnssec_list_append(keys, key);

	return true;
}

/* -- list item matching and printing -------------------------------------- */

/*!
 * Check if a string item contains a substring (case insensitive).
 */
static bool item_match_substring(const void *_item, const char *filter)
{
	assert(_item);
	const char *item = _item;

	return strcasestr(item, filter) != NULL;
}

/*!
 * Check if a string contains a prefix (case insensitive).
 */
static bool str_prefix_match(const char *str, const char *prefix)
{
	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	return prefix_len <= str_len &&
	       strncasecmp(str, prefix, prefix_len) == 0;
}

/*!
 * Check if a string content is matching a key tag.
 */
static bool keytag_match(uint16_t keytag, const char *filter)
{
	uint16_t converted = 0;

	return str_to_u16(filter, &converted) == KNOT_EOK &&
	       keytag == converted;
}

/*!
 * Check if a \dnssec_kasp_key_t item matches a filter.
 *
 * The filter can be a key ID prefix or match the key tag.
 */
static bool item_match_key(const void *_item, const char *filter)
{
	assert(_item);
	const dnssec_kasp_key_t *item = _item;

	return str_prefix_match(item->id, filter) ||
	       keytag_match(dnssec_key_get_keytag(item->key), filter);
}

/*!
 * Print key item.
 */
static void item_print_key(const void *item)
{
	assert(item);
	const dnssec_kasp_key_t *key = item;

	printf("- %s %5d\n", key->id, dnssec_key_get_keytag(key->key));
}

/*!
 * Print key string.
 */
static void item_print_string(const void *item)
{
	assert(item);
	const char *str = item;
	printf("- %s\n", str);
}

static bool empty_filter(const char *filter)
{
	return (filter == NULL || filter[0] == '\0');
}

typedef bool (*list_match_cb)(const void *item, const char *filter);
typedef void (*list_print_cb)(const void *item);

key_state_t str_to_keystate(const char *filter) {
	if (!filter) {
		return DNSSEC_KEY_STATE_INVALID;
	}

	if (strcmp(filter, "+removed") == 0) {
		return DNSSEC_KEY_STATE_REMOVED;
	}

	if (strcmp(filter, "+retired") == 0) {
		return DNSSEC_KEY_STATE_RETIRED;
	}

	if (strcmp(filter, "+active") == 0) {
		return DNSSEC_KEY_STATE_ACTIVE;
	}

	if (strcmp(filter, "+published") == 0) {
		return DNSSEC_KEY_STATE_PUBLISHED;
	}

	return DNSSEC_KEY_STATE_INVALID;
}

/*!
 * Iterate over a list and print each matching item.
 *
 * \param list    List to walk through.
 * \param filter  Filter value passed to match callback (can be NULL).
 * \param match   Item match callback (can be NULL in case filter is NULL).
 * \param print   Item print callback.
 *
 * \return Number of printed items.
 */
static int print_list(dnssec_list_t *list, const char *filter,
		      list_match_cb match, list_print_cb print)
{
	assert(list);

	int found = 0;

	dnssec_list_foreach(item, list) {
		const void *value = dnssec_item_get(item);
		if (empty_filter(filter) || match(value, filter)) {
			found += 1;
			print(value);
		}
	}

	return found;
}

/*!
 * Iterate over a list and print each matching item.
 *
 * \param list    List to walk through.
 * \param filter  Limits printed keys to given state.
 * \param print   Item print callback.
 *
 * \return Number of printed items.
 */
static int print_list_filtered(dnssec_list_t *list, const char *filter1,
                               const char *filter2, list_print_cb print)
{
	assert(list);
	uint16_t flag = 0;
	bool first_valid = true;

	key_state_t state = str_to_keystate(filter1);
	if (state == DNSSEC_KEY_STATE_INVALID) {
		first_valid = false;
		state = str_to_keystate(filter2);
		if (filter2 && state == DNSSEC_KEY_STATE_INVALID) {
			error("Invalid filters.");
			return DNSSEC_ERROR;
		}
	}

	const char *flag_def = (first_valid ? filter2 : filter1);

	if (flag_def && !strcmp(flag_def, "+ksk")) {
		flag = DNSKEY_FLAGS_KSK;
	} else if (flag_def && !strcmp(flag_def, "+zsk")) {
		flag = DNSKEY_FLAGS_ZSK;
	}

	if ((!first_valid || filter2) && !flag) {
		error("Invalid filters.");
		return DNSSEC_ERROR;
	}

	int found = 0;
	time_t current = time(NULL);
	dnssec_list_foreach(item, list) {
		dnssec_kasp_key_t *key = dnssec_item_get(item);
		const void *value = dnssec_item_get(item);
		uint16_t flags = dnssec_key_get_flags(key->key);
		if ((state == DNSSEC_KEY_STATE_INVALID ||
		     dnssec_get_key_state(key, current) == state) &&
			(flags == flag || flag == 0)) {
			print(value);
			found+=1;
		}
	}
	return found;
}

/* -- key matching --------------------------------------------------------- */

/*!
 * Key match callback function prototype.
 */
typedef int (*key_match_cb)(dnssec_kasp_key_t *key, void *data);

/*!
 * Convert search string to keytag value.
 *
 * \return Keytag or -1 if the search string is not a keytag value.
 */
static int search_str_to_keytag(const char *search)
{
	assert(search);

	uint16_t keytag = 0;
	int r = str_to_u16(search, &keytag);

	return (r == KNOT_EOK ? keytag : -1);
}

/*!
 * Check if key matches search string or search keytag.
 *
 * \param key     KASP key to test.
 * \param keytag  Key tag to match (ignored if negative).
 * \param search  Key ID to match (prefix based match).
 *
 * \return DNSSEC key matches key tag or key ID.
 */
static bool key_match(const dnssec_kasp_key_t *key, int keytag, const char *keyid)
{
	assert(key);
	assert(keyid);

	// key tag

	if (keytag >= 0 && dnssec_key_get_keytag(key->key) == keytag) {
		return true;
	}

	// key ID

	size_t id_len = strlen(key->id);
	size_t keyid_len = strlen(keyid);
	return (keyid_len <= id_len && strncasecmp(key->id, keyid, keyid_len) == 0);
}

/*!
 * Call a function for each key matching the search string.
 *
 * \param list    List of \ref dnssec_kasp_key_t keys.
 * \param search  Search string, can be key tag or key ID prefix.
 * \param match   Callback function.
 * \param data    Custom data passed to callback function.
 *
 * \return Error code propagated from callback function.
 */
static int search_key(dnssec_list_t *list, const char *search,
		      key_match_cb match, void *data)
{
	assert(list);
	assert(search);
	assert(match);

	int keytag = search_str_to_keytag(search);

	dnssec_list_foreach(item, list) {
		dnssec_kasp_key_t *key = dnssec_item_get(item);
		if (key_match(key, keytag, search)) {
			int r = match(key, data);
			if (r != DNSSEC_EOK) {
				return r;
			}
		}
	}

	return DNSSEC_EOK;
}

/*!
 * Callback for \ref search_key assuring the found key is unique.
 */
static int assure_unique(dnssec_kasp_key_t *key, void *data)
{
	assert(key);
	assert(data);

	dnssec_kasp_key_t **unique_ptr = data;
	if (*unique_ptr) {
		return DNSSEC_ERROR;
	}

	*unique_ptr = key;
	return DNSSEC_EOK;
}

/*!
 * Search for a unique key.
 *
 * \param[in]  list     List of \ref dnssec_kasp_key_t keys.
 * \param[in]  search   Search string, can be key tag or key ID prefix.
 * \param[out] key_ptr  Found key.
 *
 * \return Error code.
 */
static int search_unique_key(dnssec_list_t *list, const char *search,
			     dnssec_kasp_key_t **key_ptr)
{
	assert(list);
	assert(search);
	assert(key_ptr);

	dnssec_kasp_key_t *match = NULL;
	int r = search_key(list, search, assure_unique, &match);
	if (r == DNSSEC_ERROR) {
		error("Multiple matching keys found.");
		return DNSSEC_ERROR;
	}

	if (match == NULL) {
		error("No matching key found.");
		return DNSSEC_ERROR;
	}

	*key_ptr = match;
	return DNSSEC_EOK;
}

/* -- actions implementation ----------------------------------------------- */

static bool init_kasp(dnssec_kasp_t **kasp_ptr)
{
	dnssec_kasp_t *kasp = NULL;
	dnssec_kasp_init_dir(&kasp);

	int r = dnssec_kasp_init(kasp, options.kasp_dir);
	if (r != DNSSEC_EOK) {
		error("Cannot initialize KASP directory (%s).", dnssec_strerror(r));
		free(kasp);
		return false;
	}

	r = dnssec_kasp_open(kasp, options.kasp_dir);
	if (r != DNSSEC_EOK) {
		error("Cannot open KASP directory (%s).", dnssec_strerror(r));
		free(kasp);
		return false;
	}

	*kasp_ptr = kasp;
	return true;
}

static int create_default_keystore(dnssec_kasp_t *kasp)
{
	int r = dnssec_kasp_keystore_exists(kasp, DEFAULT_KEYSTORE);
	if (r == DNSSEC_EOK || r != DNSSEC_NOT_FOUND) {
		return r;
	}

	dnssec_kasp_keystore_t config = {
		.name = DEFAULT_KEYSTORE,
		.backend = DNSSEC_KASP_KEYSTORE_PKCS8,
		.config = "keys",
	};

	_cleanup_keystore_ dnssec_keystore_t *keystore = NULL;
	r = dnssec_kasp_keystore_init(kasp, config.backend, config.config, &keystore);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = dnssec_kasp_keystore_save(kasp, &config);
	if (r != DNSSEC_EOK) {
		return r;
	}

	return DNSSEC_EOK;
}

static int create_policy(dnssec_kasp_t *kasp, const dnssec_kasp_policy_t *policy)
{
	int r = dnssec_kasp_policy_exists(kasp, policy->name);
	if (r == DNSSEC_EOK || r != DNSSEC_NOT_FOUND) {
		return r;
	}

	return dnssec_kasp_policy_save(kasp, policy);
}

static int create_default_policy(dnssec_kasp_t *kasp)
{
	dnssec_kasp_policy_t config = { 0 };
	dnssec_kasp_policy_defaults(&config);
	config.name = DEFAULT_POLICY;
	config.keystore = DEFAULT_KEYSTORE;

	return create_policy(kasp, &config);
}

static int create_manual_policy(dnssec_kasp_t *kasp)
{
	dnssec_kasp_policy_t config = { 0 };
	dnssec_kasp_policy_defaults(&config);
	config.name = MANUAL_POLICY;
	config.keystore = DEFAULT_KEYSTORE;
	config.manual = true;

	return create_policy(kasp, &config);
}

static int create_manual_policy_lazy(dnssec_kasp_t *kasp, bool *created)
{
	if (*created) {
		return DNSSEC_EOK;
	}

	*created = true;
	return create_manual_policy(kasp);
}

/*!
 * Walk through existing policies, (a) add reference to default key store
 * if missing, and (b) add default policy if missing.
 */
static bool update_policies(dnssec_kasp_t *kasp)
{
	_cleanup_list_ dnssec_list_t *policies = NULL;
	int r = dnssec_kasp_policy_list(kasp, &policies);
	if (r != DNSSEC_EOK) {
		error("Failed to get list of existing policies (%s).", dnssec_strerror(r));
		return false;
	}

	bool has_default = false;

	dnssec_list_foreach(i, policies) {
		const char *name = dnssec_item_get(i);
		if (strcmp(name, DEFAULT_POLICY) == 0) {
			has_default = true;
		}

		_cleanup_policy_ dnssec_kasp_policy_t *policy = NULL;
		r = dnssec_kasp_policy_load(kasp, name, &policy);
		if (r != DNSSEC_EOK) {
			error("Failed to load policy '%s' (%s).", name, dnssec_strerror(r));
			return false;
		}

		if (policy->keystore == NULL) {
			policy->keystore = strdup(DEFAULT_KEYSTORE);
		}

		r = dnssec_kasp_policy_save(kasp, policy);
		if (r != DNSSEC_EOK) {
			error("Failed to update policy '%s' (%s).", name, dnssec_strerror(r));
			return false;
		}
	}

	if (!has_default) {
		r = create_default_policy(kasp);
		if (r != DNSSEC_EOK) {
			error("Failed to add default policy (%s).", dnssec_strerror(r));
			return false;
		}
	}

	return true;
}

/*!
 * Walk through existing zones and adds a default policy with manual signing
 * enabled, if there is a zone with unassigned policy.
 */
static bool update_zones(dnssec_kasp_t *kasp)
{
	_cleanup_list_ dnssec_list_t *zones = NULL;
	int r = dnssec_kasp_zone_list(kasp, &zones);
	if (r != DNSSEC_EOK) {
		error("Failed to get list of existing zones (%s).", dnssec_strerror(r));
		return false;
	}

	bool manual_ready = false;

	dnssec_list_foreach(i, zones) {
		const char *name = dnssec_item_get(i);

		_cleanup_zone_ dnssec_kasp_zone_t *zone = NULL;
		int r = dnssec_kasp_zone_load(kasp, name, &zone);
		if (r != DNSSEC_EOK) {
			error("Failed to load zone '%s' (%s).", name, dnssec_strerror(r));
			return false;
		}

		if (dnssec_kasp_zone_get_policy(zone) == NULL) {
			r = create_manual_policy_lazy(kasp, &manual_ready);
			if (r != DNSSEC_EOK) {
				error("Failed to create policy for manual signing (%s)", MANUAL_POLICY);
				return false;
			}

			r = dnssec_kasp_zone_set_policy(zone, MANUAL_POLICY);
			if (r != DNSSEC_EOK) {
				error("Failed to assign policy '%s' to zone '%s' (%s).",
				      name, MANUAL_POLICY, dnssec_strerror(r));
				return false;
			}
		}

		r = dnssec_kasp_zone_save(kasp, zone);
		if (r != DNSSEC_EOK) {
			error("Failed to save zone '%s' (%s).", name, dnssec_strerror(r));
			return false;
		}
	}

	return true;
}

/*
 * keymgr init
 */
static int cmd_init(int argc, char *argv[])
{
	if (argc != 0) {
		error("Extra parameters supplied.");
		return 1;
	}

	_cleanup_kasp_ dnssec_kasp_t *kasp = NULL;
	if (!init_kasp(&kasp)) {
		return 1;
	}

	int r = create_default_keystore(kasp);
	if (r != DNSSEC_EOK) {
		error("Failed to initialize default key store (%s).", dnssec_strerror(r));
		return 1;
	}

	if (!update_policies(kasp)) {
		return 1;
	}

	if (!update_zones(kasp)) {
		return 1;
	}

	return 0;
}

/*
 * keymgr zone add <name> [policy <policy>]
 */
static int cmd_zone_add(int argc, char *argv[])
{
	if (argc < 1) {
		error("Missing zone name.");
		return 1;
	}

	const char *zone_name = argv[0];
	const char *policy = DEFAULT_POLICY;

	static const parameter_t params[] = {
		{ "policy", value_static_string },
		{ NULL }
	};

	if (parse_parameters(params, argc - 1, argv + 1, &policy) != 0) {
		return 1;
	}

	// create zone

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_zone_kasp(zone_name);
	if (!kasp) {
		return 1;
	}

	int r = dnssec_kasp_zone_exists(kasp, zone_name);
	if (r == DNSSEC_EOK) {
		error("Zone with given name already exists.");
		return 1;
	} else if (r != DNSSEC_NOT_FOUND) {
		error("Failed to check if given zone exists (%s).", dnssec_strerror(r));
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = dnssec_kasp_zone_new(zone_name);
	if (!zone) {
		error("Failed to create new zone.");
		return 1;
	}

	r = dnssec_kasp_zone_set_policy(zone, policy);
	if (r != DNSSEC_EOK) {
		error("Unable to set zone policy.");
		return 1;
	}

	r = dnssec_kasp_zone_save(kasp, zone);
	if (r != DNSSEC_EOK) {
		error("Failed to save new zone (%s).", dnssec_strerror(r));
		return 1;
	}

	return 0;
}

/*
 * keymgr zone list [substring-match]
 */
static int cmd_zone_list(int argc, char *argv[])
{
	const char *match;
	if (argc == 0) {
		match = NULL;
	} else if (argc == 1) {
		match = argv[0];
	} else {
		error("Extra parameter specified.");
		return 1;
	}

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_zone_kasp(match);
	if (!kasp) {
		return 1;
	}

	_cleanup_list_ dnssec_list_t *zones = NULL;
	int r = dnssec_kasp_zone_list(kasp, &zones);
	if (r != DNSSEC_EOK) {
		error("Failed to get list of zones (%s).", dnssec_strerror(r));
		return 1;
	}

	int found = print_list(zones, match, item_match_substring, item_print_string);
	if (found == 0) {
		error("No matching zone found.");
		return 1;
	}

	return 0;
}

static int cmd_zone_show(int argc, char *argv[])
{
	if (argc != 1) {
		error("Name of one zone has to be specified.");
		return 1;
	}

	char *zone_name = argv[0];

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_zone_kasp(zone_name);
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, zone_name);
	if (!zone) {
		return 1;
	}

	printf("zone: %s\n", zone_name);
	const char *policy = dnssec_kasp_zone_get_policy(zone);
	printf("policy: %s\n", policy ? policy : "(not set)");
	printf("keys: %zu\n", dnssec_list_size(dnssec_kasp_zone_get_keys(zone)));

	return 0;
}

static bool is_zone_used(dnssec_kasp_zone_t *zone)
{
	time_t now = time(NULL);
	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(zone);
	dnssec_list_foreach(item, keys) {
		dnssec_kasp_key_t *key = dnssec_item_get(item);
		if (dnssec_kasp_key_is_used(&key->timing, now)) {
			return true;
		}
	}

	return false;
}

/*
 * keymgr zone remove <name> [force]
 */
static int cmd_zone_remove(int argc, char *argv[])
{
	if (argc < 1) {
		error("Name of one zone has to be specified.");
		return 1;
	}

	char *zone_name = argv[0];
	bool force = false;

	static const parameter_t params[] = {
		{ "force", value_flag, .req_full_match = true },
		{ NULL }
	};

	if (parse_parameters(params, argc - 1, argv + 1, &force) != 0) {
		return 1;
	}

	// delete zone

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_zone_kasp(zone_name);
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, zone_name);
	if (!zone) {
		return 1;
	}

	if (!force && is_zone_used(zone)) {
		error("Some keys are being used. Cannot remove the zone "
		      "unless 'force' parameter is given.");
		return 1;
	}

	int r = dnssec_kasp_zone_remove(kasp, zone_name);
	if (r != DNSSEC_EOK) {
		error("Cannot remove the zone (%s).", dnssec_strerror(r));
		return 1;
	}

	return 0;
}

/*
 * keymgr zone key list <zone> [<filter>]
 */
static int cmd_zone_key_list(int argc, char *argv[])
{
	if (argc < 1 || argc > 3) {
		error("Zone name and optional filter has to be specified.");
		return 1;
	}

	const char *zone_name = argv[0];
	const char *filter1 = (argc >= 2 ? argv[1] : NULL);
	const char *filter2 = (argc == 3 ? argv[2] : NULL);

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_zone_kasp(zone_name);
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, zone_name);
	if (!zone) {
		return 1;
	}

	dnssec_list_t *zone_keys = dnssec_kasp_zone_get_keys(zone);
	int count = 0;
	/* No filter */
	if ((!filter1 || filter1[0] != '+') && !filter2) {
		count = print_list(zone_keys, filter1, item_match_key, item_print_key);
	/* with filters */
	} else if (filter1 && filter1[0] == '+' && (!filter2 || filter2[0] == '+')) {
		count = print_list_filtered(zone_keys, filter1, filter2, item_print_key);
	} else {
		error("Invalid argument combination");
		return 1;
	}

	if (count == 0) {
		error("No matching zone key found.");
		return 1;
	}

	return 0;
}

/*
 * keymgr zone key show <zone> <key-spec>
 */
static int cmd_zone_key_show(int argc, char *argv[])
{
	if (argc != 2) {
		error("Name of zone and key have to be specified.");
		return 1;
	}

	char *zone_name = argv[0];
	char *search = argv[1];

	// list the keys

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_zone_kasp(zone_name);
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, zone_name);
	if (!zone) {
		return 1;
	}

	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(zone);

	dnssec_kasp_key_t *key = NULL;
	int r = search_unique_key(keys, search, &key);
	if (r != DNSSEC_EOK) {
		return 1;
	}

	printf("id %s\n",        key->id);
	printf("keytag %d\n",    dnssec_key_get_keytag(key->key));
	printf("algorithm %d\n", dnssec_key_get_algorithm(key->key));
	printf("size %u\n",      dnssec_key_get_size(key->key));
	printf("flags %d\n",     dnssec_key_get_flags(key->key));
	printf("publish %lld\n", (long long)key->timing.publish);
	printf("active %lld\n",  (long long)key->timing.active);
	printf("retire %lld\n",  (long long)key->timing.retire);
	printf("remove %lld\n",  (long long)key->timing.remove);

	return 0;
}

/*!
 * Print DS record in presentation format to standard output.
 *
 * \see RFC 4034, Section 5.1 (DS RDATA Wire Format)
 * \see RFC 4034, Section 5.3 (The DS RR Presentation Format)
 */
static int print_ds(const uint8_t *dname, const dnssec_binary_t *rdata)
{
	wire_ctx_t ctx = wire_init_binary(rdata);
	if (wire_available(&ctx) < 4) {
		return DNSSEC_MALFORMED_DATA;
	}

	_cleanup_free_ char *name = dname_to_ascii(dname);
	if (!name) {
		return DNSSEC_ENOMEM;
	}

	dnssec_binary_t digest = { 0 };

	uint16_t keytag   = wire_read_u16(&ctx);
	uint8_t algorithm = wire_read_u8(&ctx);
	uint8_t digest_type = wire_read_u8(&ctx);
	wire_available_binary(&ctx, &digest);

	printf("%s. DS %d %d %d ", name, keytag, algorithm, digest_type);
	for (size_t i = 0; i < digest.size; i++) {
		printf("%02x", digest.data[i]);
	}
	printf("\n");

	return DNSSEC_EOK;
}

static int create_and_print_ds(const dnssec_key_t *key, dnssec_key_digest_t digest)
{
	_cleanup_binary_ dnssec_binary_t rdata = { 0 };
	int r = dnssec_key_create_ds(key, digest, &rdata);
	if (r != DNSSEC_EOK) {
		return r;
	}

	return print_ds(dnssec_key_get_dname(key), &rdata);
}

/*
 * keymgr zone key ds <zone> <key-spec>
 */
static int cmd_zone_key_ds(int argc, char *argv[])
{
	if (argc != 2) {
		error("Name of zone and key have to be specified");
		return 1;
	}

	const char *zone_name = argv[0];
	const char *key_name = argv[1];

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_zone_kasp(zone_name);
	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, zone_name);
	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(zone);

	static const dnssec_key_digest_t digests[] = {
		DNSSEC_KEY_DIGEST_SHA1,
		DNSSEC_KEY_DIGEST_SHA256,
		DNSSEC_KEY_DIGEST_SHA384,
		0
	};

	dnssec_kasp_key_t *key = NULL;

	key_state_t state = str_to_keystate(key_name);
	if (state == DNSSEC_KEY_STATE_INVALID) {
		if (key_name[0] == '+') {
			error("Wrong filter");
			return 1;
		}

		int r = search_unique_key(keys, key_name, &key);
		if (r != DNSSEC_EOK) {
			return 1;
		}

		for (const dnssec_key_digest_t *d = digests; *d != 0; d++) {
			create_and_print_ds(key->key, *d);
		}
	} else if (state == DNSSEC_KEY_STATE_ACTIVE || state == DNSSEC_KEY_STATE_PUBLISHED) {
		int found = 0;
		time_t current = time(NULL);

		dnssec_list_foreach(item, keys) {
			key = dnssec_item_get(item);
			uint16_t flags = dnssec_key_get_flags(key->key);
			const void *value = dnssec_item_get(item);
			if (dnssec_get_key_state(key, current) == state && flags == DNSKEY_FLAGS_KSK) {
				found++;
				item_print_key(value);
				for (const dnssec_key_digest_t *d = digests; *d != 0; d++) {
					create_and_print_ds(key->key, *d);
				}
			}
		}

		if (found == 0) {
			error ("No key matching filter.");
			return 1;
		}
	} else { // if onther state than active or published
		error("Wrong filter.");
		return 1;
	}

	return 0;
}

static void assure_key_size(uint16_t *size, dnssec_key_algorithm_t algorithm)
{
	assert(size);

	if (*size == 0) {
		*size = dnssec_algorithm_key_size_default(algorithm);
	}
}

/*
 * keymgr zone key generate <zone> algorithm <algorithm> size <size> [ksk]
 *                                 [publish <publish>] [active <active>]
 *                                 [retire <retire>] [remove <remove>]
 */
static int cmd_zone_key_generate(int argc, char *argv[])
{
	if (argc < 1) {
		error("Name of the zone has to be specified.");
		return 1;
	}

	struct config {
		char *name;
		dnssec_key_algorithm_t algorithm;
		uint16_t size;
		bool is_ksk;
		dnssec_kasp_key_timing_t timing;
	};

	static const parameter_t params[] = {
		#define o(member) offsetof(struct config, member)
		{ "algorithm", value_algorithm, .offset = o(algorithm) },
		{ "size",      value_key_size,  .offset = o(size) },
		{ "ksk",       value_flag,      .offset = o(is_ksk) },
		{ "publish",   value_time,      .offset = o(timing.publish) },
		{ "active",    value_time,      .offset = o(timing.active) },
		{ "retire",    value_time,      .offset = o(timing.retire) },
		{ "remove",    value_time,      .offset = o(timing.remove) },
		{ NULL }
		#undef o
	};

	struct config config = {
		.name = argv[0]
	};

	if (parse_parameters(params, argc - 1, argv + 1, &config) != 0) {
		return 1;
	}

	if (config.algorithm == 0) {
		error("Algorithm has to be specified.");
		return 1;
	}

	assure_key_size(&config.size, config.algorithm);

	if (!dnssec_algorithm_key_size_check(config.algorithm, config.size)) {
		error("Key size is invalid for given algorithm.");
		return 1;
	}

	// open KASP and key store

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_zone_kasp(config.name);
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, config.name);
	if (!zone) {
		return 1;
	}

	_cleanup_policy_ dnssec_kasp_policy_t *policy = NULL;
	policy = get_policy(kasp, dnssec_kasp_zone_get_policy(zone));
	if (!policy) {
		return 1;
	}

	_cleanup_keystore_ dnssec_keystore_t *store = get_keystore(kasp, policy->keystore);
	if (!store) {
		return 1;
	}

	// generate private key and construct DNSKEY

	_cleanup_free_ char *keyid = NULL;
	int r = dnssec_keystore_generate_key(store, config.algorithm, config.size, &keyid);
	if (r != DNSSEC_EOK) {
		error("Failed to generate a private key (%s).", dnssec_strerror(r));
		return 1;
	}

	uint16_t flags = config.is_ksk ? DNSKEY_FLAGS_KSK : DNSKEY_FLAGS_ZSK;

	dnssec_key_t *dnskey = NULL;
	dnssec_key_new(&dnskey);
	dnssec_key_set_algorithm(dnskey, config.algorithm);
	dnssec_key_set_flags(dnskey, flags);

	r = dnssec_key_import_keystore(dnskey, store, keyid);
	if (r != DNSSEC_EOK) {
		dnssec_key_free(dnskey);
		error("Failed to create a DNSKEY record (%s).", dnssec_strerror(r));
		return 1;
	}

	// add DNSKEY into zone keys

	config.timing.created = time(NULL);
	if (!zone_add_dnskey(zone, keyid, dnskey, &config.timing)) {
		dnssec_key_free(dnskey);
		return 1;
	}

	r = dnssec_kasp_zone_save(kasp, zone);
	if (r != DNSSEC_EOK) {
		error("Failed to save updated zone (%s).", dnssec_strerror(r));
		dnssec_keystore_remove_key(store, keyid);
		return 1;
	}

	printf("%s\n", keyid);

	return 0;
}

/*
 * keymgr zone key set <zone> <key-spec>  [publish <publish>] [active <active>]
 *					  [retire <retire>] [remove <remove>]
 */
static int cmd_zone_key_set(int argc, char *argv[])
{
	if (argc < 2) {
		error("Name of the zone and key have to be specified.");
		return 1;
	}

	char *zone_name = argv[0];
	char *search = argv[1];

	static const parameter_t params[] = {
		#define o(member) offsetof(dnssec_kasp_key_timing_t, member)
		{ "publish", value_time, .offset = o(publish) },
		{ "active",  value_time, .offset = o(active) },
		{ "retire",  value_time, .offset = o(retire) },
		{ "remove",  value_time, .offset = o(remove) },
		{ NULL }
		#undef o
	};

	dnssec_kasp_key_timing_t new_timing = { -1, -1, -1, -1 };

	if (parse_parameters(params, argc - 2, argv + 2, &new_timing) != 0) {
		return 1;
	}

	// update the key

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_zone_kasp(zone_name);
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, zone_name);
	if (!zone) {
		return 1;
	}

	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(zone);
	dnssec_kasp_key_t *match = NULL;
	int r = search_unique_key(keys, search, &match);
	if (r != DNSSEC_EOK) {
		return 1;
	}

	if (new_timing.publish >= 0) { match->timing.publish = new_timing.publish; }
	if (new_timing.active >= 0) { match->timing.active = new_timing.active; }
	if (new_timing.retire >= 0) { match->timing.retire = new_timing.retire; }
	if (new_timing.remove >= 0) { match->timing.remove = new_timing.remove; }

	r = dnssec_kasp_zone_save(kasp, zone);
	if (r != DNSSEC_EOK) {
		error("Failed to save updated zone (%s).", dnssec_strerror(r));
		return 1;
	}

	return 0;
}

/*
 * keymgr zone key import <zone> <bind-keyfile>
 */
static int cmd_zone_key_import(int argc, char *argv[])
{
	if (argc != 2) {
		error("Zone name and input file required.");
		return 1;
	}

	char *zone_name = argv[0];
	char *input_file = argv[1];

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_zone_kasp(zone_name);
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, zone_name);
	if (!zone) {
		return 1;
	}

	_cleanup_policy_ dnssec_kasp_policy_t *policy = NULL;
	policy = get_policy(kasp, dnssec_kasp_zone_get_policy(zone));
	if (!policy) {
		return 1;
	}

	_cleanup_keystore_ dnssec_keystore_t *store = get_keystore(kasp, policy->keystore);
	if (!store) {
		return 1;
	}

	// parse the key

	dnssec_key_t *key = NULL;
	_cleanup_binary_ dnssec_binary_t pem = { 0 };
	dnssec_kasp_key_timing_t timing = { 0 };

	int r = legacy_key_parse(input_file, &key, &pem, &timing);
	if (r != DNSSEC_EOK) {
		error("Failed to parse the input key (%s).", dnssec_strerror(r));
		return 1;
	}

	// store private key

	_cleanup_free_ char *keyid = NULL;
	r = dnssec_keystore_import(store, &pem, &keyid);
	if (r != DNSSEC_EOK) {
		error("Failed to import private key (%s).", dnssec_strerror(r));
		dnssec_key_free(key);
		return 1;
	}

	timing.created = time(NULL);
	if (!zone_add_dnskey(zone, keyid, key, &timing)) {
		dnssec_keystore_remove_key(store, keyid);
		dnssec_key_free(key);
		return 1;
	}

	r = dnssec_kasp_zone_save(kasp, zone);
	if (r != DNSSEC_EOK) {
		error("Failed to save updated zone (%s).", dnssec_strerror(r));
		dnssec_keystore_remove_key(store, keyid);
		dnssec_key_free(key);
		return 1;
	}

	printf("%s\n", keyid);

	return 0;
}

static int cmd_zone_key(int argc, char *argv[])
{
	static const command_t commands[] = {
		{ "list",     cmd_zone_key_list },
		{ "show",     cmd_zone_key_show },
		{ "ds",       cmd_zone_key_ds },
		{ "generate", cmd_zone_key_generate },
		{ "set",      cmd_zone_key_set },
		{ "import",   cmd_zone_key_import },
		{ NULL }
	};

	return subcommand(commands, options.legacy, argc, argv);
}

static int cmd_zone_set(int argc, char *argv[])
{
	if (argc < 1) {
		error("Name of the zone has to be specified.");
		return 1;
	}

	char *zone_name = argv[0];

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_zone_kasp(zone_name);
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, zone_name);
	if (!zone) {
		return 1;
	}

	const char *policy = dnssec_kasp_zone_get_policy(zone);

	static const parameter_t params[] = {
		{ "policy", value_static_string },
		{ NULL }
	};

	if (parse_parameters(params, argc - 1, argv + 1, &policy) != 0) {
		return 1;
	}

	int r = dnssec_kasp_zone_set_policy(zone, policy);
	if (r != DNSSEC_EOK) {
		error("Failed to set new policy (%s).", dnssec_strerror(r));
		return 1;
	}

	r = dnssec_kasp_zone_save(kasp, zone);
	if (r != DNSSEC_EOK) {
		error("Failed to save updated zone (%s).", dnssec_strerror(r));
		return 1;
	}

	return 0;
}

static int cmd_zone(int argc, char *argv[])
{
	static command_t commands[] = {
		{ "key",    cmd_zone_key },
		{ "add",    cmd_zone_add,    LEGACY },
		{ "list",   cmd_zone_list,   LEGACY },
		{ "remove", cmd_zone_remove, LEGACY },
		{ "show",   cmd_zone_show,   LEGACY },
		{ "set",    cmd_zone_set,    LEGACY },
		{ NULL }
	};

	return subcommand(commands, options.legacy, argc, argv);
}

static int cmd_policy_list(int argc, char *argv[])
{
	const char *match;
	if (argc == 0) {
		match = NULL;
	} else if (argc == 1) {
		match = argv[0];
	} else {
		error("Extra parameter specified.");
		return 1;
	}

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	_cleanup_list_ dnssec_list_t *policies = NULL;
	int r = dnssec_kasp_policy_list(kasp, &policies);
	if (r != DNSSEC_EOK) {
		error("Failed to get list of policies (%s).", dnssec_strerror(r));
		return 1;
	}

	int found = print_list(policies, match, item_match_substring, item_print_string);
	if (found == 0) {
		error("No matching policy found.");
		return 1;
	}

	return 0;
}

static void print_policy(const dnssec_kasp_policy_t *policy)
{
	printf("manual control:      %s\n", policy->manual ? "true" : "false");
	printf("keystore:            %s\n", policy->keystore ? policy->keystore : "(not set)");
	printf("algorithm:           %d\n", policy->algorithm);
	printf("DNSKEY TTL:          %u\n", policy->dnskey_ttl);
	printf("KSK key size:        %u\n", policy->ksk_size);
	printf("ZSK key size:        %u\n", policy->zsk_size);
	printf("ZSK lifetime:        %u\n", policy->zsk_lifetime);
	printf("RRSIG lifetime:      %u\n", policy->rrsig_lifetime);
	printf("RRSIG refresh:       %u\n", policy->rrsig_refresh_before);
	printf("NSEC3 enabled:       %s\n", policy->nsec3_enabled ? "true" : "false");
	printf("NSEC3 iterations:    %u\n", policy->nsec3_iterations);
	printf("NSEC3 salt length:   %u\n", policy->nsec3_salt_length);
	printf("NSEC3 salt lifetime: %u\n", policy->nsec3_salt_lifetime);
	printf("SOA min TTL:         %u\n", policy->soa_minimal_ttl);
	printf("zone max TTL:        %u\n", policy->zone_maximal_ttl);
	printf("data propagation:    %u\n", policy->propagation_delay);
}

static int cmd_policy_show(int argc, char *argv[])
{
	if (argc != 1) {
		error("Policy name is required.");
		return 1;
	}

	char *name = argv[0];

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	_cleanup_policy_ dnssec_kasp_policy_t *policy = get_policy(kasp, name);
	if (!policy) {
		return 1;
	}

	print_policy(policy);

	return 0;
}

static const parameter_t POLICY_PARAMS[] = {
	#define o(member) offsetof(dnssec_kasp_policy_t, member)
	{ "algorithm",           value_algorithm, .offset = o(algorithm) },
	{ "manual",              value_bool,      .offset = o(manual) },
	{ "keystore",            value_string,    .offset = o(keystore) },
	{ "dnskey-ttl",          value_uint32,    .offset = o(dnskey_ttl) },
	{ "ksk-size",            value_key_size,  .offset = o(ksk_size) },
	{ "zsk-size",            value_key_size,  .offset = o(zsk_size) },
	{ "zsk-lifetime",        value_uint32,    .offset = o(zsk_lifetime) },
	{ "rrsig-lifetime",      value_uint32,    .offset = o(rrsig_lifetime) },
	{ "rrsig-refresh",       value_uint32,    .offset = o(rrsig_refresh_before) },
	{ "nsec3",               value_bool,      .offset = o(nsec3_enabled) },
	{ "nsec3-iterations",    value_uint16,    .offset = o(nsec3_iterations) },
	{ "nsec3-salt-length",   value_uint8,     .offset = o(nsec3_salt_length) },
	{ "nsec3-salt-lifetime", value_uint32,    .offset = o(nsec3_salt_lifetime) },
	{ "soa-min-ttl",         value_uint32,    .offset = o(soa_minimal_ttl) },
	{ "zone-max-ttl",        value_uint32,    .offset = o(zone_maximal_ttl) },
	{ "delay",               value_uint32,    .offset = o(propagation_delay) },
	{ NULL }
	#undef o
};

static int cmd_policy_add(int argc, char *argv[])
{
	if (argc < 1) {
		error("Name of the policy has to be specified.");
		return 1;
	}

	const char *policy_name = argv[0];

	_cleanup_policy_ dnssec_kasp_policy_t *policy = dnssec_kasp_policy_new(policy_name);
	if (!policy) {
		error("Failed to create new policy.");
		return 1;
	}

	dnssec_kasp_policy_defaults(policy);
	policy->keystore = strdup(DEFAULT_KEYSTORE);

	policy->ksk_size = 0;
	policy->zsk_size = 0;

	if (parse_parameters(POLICY_PARAMS, argc - 1, argv + 1, policy) != 0) {
		return 1;
	}

	assure_key_size(&policy->ksk_size, policy->algorithm);
	assure_key_size(&policy->zsk_size, policy->algorithm);

	int r = dnssec_kasp_policy_validate(policy);
	if (r != DNSSEC_EOK) {
		error("Policy configuration is invalid (%s).", dnssec_strerror(r));
		return 1;
	}

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	r = dnssec_kasp_policy_exists(kasp, policy_name);
	if (r == DNSSEC_EOK) {
		error("Policy with given name already exists.");
		return 1;
	} else if (r != DNSSEC_NOT_FOUND) {
		error("Failed to check if given policy exists (%s).", dnssec_strerror(r));
		return 1;
	}

	r = dnssec_kasp_policy_save(kasp, policy);
	if (r != DNSSEC_EOK) {
		error("Failed to save new policy (%s).", dnssec_strerror(r));
		return 1;
	}

	print_policy(policy);
	return 0;
}

static int cmd_policy_set(int argc, char *argv[])
{
	if (argc < 1) {
		error("Policy name is required.");
		return 1;
	}

	char *name = argv[0];

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	_cleanup_policy_ dnssec_kasp_policy_t *policy = get_policy(kasp, name);
	if (!policy) {
		return 1;
	}

	if (parse_parameters(POLICY_PARAMS, argc -1, argv + 1, policy) != 0) {
		return 1;
	}

	int r = dnssec_kasp_policy_validate(policy);
	if (r != DNSSEC_EOK) {
		error("Policy configuration is invalid (%s).", dnssec_strerror(r));
		return 1;
	}

	r = dnssec_kasp_policy_save(kasp, policy);
	if (r != DNSSEC_EOK) {
		error("Failed to save updated policy (%s).", dnssec_strerror(r));
		return 1;
	}

	print_policy(policy);

	return 0;
}

static int cmd_policy_remove(int argc, char *argv[])
{
	if (argc != 1) {
		error("Name of a policy has to be specified.");
		return 1;
	}

	const char *name = argv[0];

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	int r = dnssec_kasp_policy_remove(kasp, name);
	if (r != DNSSEC_EOK) {
		error("Failed to remove the policy (%s).", dnssec_strerror(r));
		return 1;
	}

	return 0;
}

static int cmd_policy(int argc, char *argv[])
{
	static const command_t commands[] = {
		{ "list",   cmd_policy_list,   LEGACY },
		{ "show",   cmd_policy_show,   LEGACY },
		{ "add",    cmd_policy_add,    LEGACY },
		{ "set",    cmd_policy_set,    LEGACY },
		{ "remove", cmd_policy_remove, LEGACY },
		{ NULL }
	};

	return subcommand(commands, options.legacy, argc, argv);
}

static int cmd_keystore_list(int argc, char *argv[])
{
	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	dnssec_list_t *names = NULL;
	dnssec_kasp_keystore_list(kasp, &names);
	dnssec_list_foreach(item, names) {
		const char *name = dnssec_item_get(item);
		printf("%s\n", name);
	}
	dnssec_list_free_full(names, NULL, NULL);

	return 0;
}

/*
 * keymgr keystore show <name>
 */
static int cmd_keystore_show(int argc, char *argv[])
{
	if (argc != 1) {
		error("Keystore name has to be specified.");
		return 1;
	}

	const char *name = argv[0];

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	_cleanup_kasp_keystore_ dnssec_kasp_keystore_t *kasp_store = NULL;
	int r = dnssec_kasp_keystore_load(kasp, name, &kasp_store);
	if (r != DNSSEC_EOK) {
		error("Failed to load keystore configuration.");
		return 1;
	}

	printf("name:    %s\n", kasp_store->name);
	printf("backend: %s\n", kasp_store->backend);
	printf("config:  %s\n", kasp_store->config);

	_cleanup_keystore_ dnssec_keystore_t *store = get_keystore(kasp, argv[0]);
	if (!store) {
		return 1;
	}

	dnssec_list_t *keys = NULL;
	dnssec_keystore_list_keys(store, &keys);
	printf("keys:    %zu\n", dnssec_list_size(keys));
	dnssec_list_foreach(item, keys) {
		const char *key_id = dnssec_item_get(item);
		printf("- %s\n", key_id);
	}
	dnssec_list_free_full(keys, NULL, NULL);

	return 0;
}

/*
 * keymgr keystore add <name> [backend <files>] [config <config>]
 */
static int cmd_keystore_add(int argc, char *argv[])
{
	if (argc < 1) {
		error("Keystore name has to be specified.");
		return 1;
	}

	dnssec_kasp_keystore_t config = {
		.name = argv[0],
		.backend = DNSSEC_KASP_KEYSTORE_PKCS8,
		.config = NULL,
	};

	static const parameter_t params[] = {
		#define off(member) offsetof(dnssec_kasp_keystore_t, member)
		{ "backend", value_static_string, .offset = off(backend) },
		{ "config",  value_static_string, .offset = off(config) },
		{ NULL },
		#undef off
	};

	if (parse_parameters(params, argc - 1, argv + 1, &config) != 0) {
		return 1;
	}

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	int r = dnssec_kasp_keystore_save(kasp, &config);
	if (r != DNSSEC_EOK) {
		error("Failed to save keystore (%s).", dnssec_strerror(r));
		return 1;
	}

	return 0;
}

/*!
 * Print TSIG key in client and server format.
 */
static void print_tsig(dnssec_tsig_algorithm_t mac, const char *name,
		       const dnssec_binary_t *secret)
{
	assert(name);
	assert(secret);

	const char *mac_name = dnssec_tsig_algorithm_to_name(mac);
	assert(mac_name);

	// client format (as a comment)
	printf("# %s:%s:%.*s\n", mac_name, name, (int)secret->size, secret->data);

	// server format
	printf("key:\n");
	printf("  - id: %s\n", name);
	printf("    algorithm: %s\n", mac_name);
	printf("    secret: %.*s\n", (int)secret->size, secret->data);
}

/*
 * keymgr tsig generate <name> [algorithm <algorithm>] [size <size>]
 */
static int cmd_tsig_generate(int argc, char *argv[])
{
	if (argc < 1) {
		error("TSIG key name has to be specified.");
		return 1;
	}

	struct config {
		dnssec_tsig_algorithm_t algorithm;
		unsigned size;
	};

	static const parameter_t params[] = {
		#define o(member) offsetof(struct config, member)
		{ "algorithm", value_tsig_algorithm, .offset = o(algorithm) },
		{ "size",      value_key_size,       .offset = o(size) },
		{ NULL }
		#undef o
	};

	struct config config = {
		.algorithm = DNSSEC_TSIG_HMAC_SHA256
	};

	_cleanup_free_ char *name = dname_ascii_normalize_copy(argv[0]);
	if (!name) {
		error("Invalid TSIG key name.");
		return 1;
	}

	if (parse_parameters(params, argc - 1, argv + 1, &config) != 0) {
		return 1;
	}

	// round up bits to bytes
	config.size = (config.size + CHAR_BIT - 1) / CHAR_BIT * CHAR_BIT;

	int optimal_size = dnssec_tsig_optimal_key_size(config.algorithm);
	assert(optimal_size > 0);

	if (config.size == 0) {
		config.size = optimal_size;
	}

	if (config.size != optimal_size) {
		error("Notice: Optimal key size for %s is %d bits.",
		      dnssec_tsig_algorithm_to_name(config.algorithm),
		      optimal_size);
	}

	assert(config.size % CHAR_BIT == 0);

	_cleanup_binary_ dnssec_binary_t key = { 0 };
	int r = dnssec_binary_alloc(&key, config.size / CHAR_BIT);
	if (r != DNSSEC_EOK) {
		error("Failed to allocate memory.");
		return 1;
	}

	r = gnutls_rnd(GNUTLS_RND_KEY, key.data, key.size);
	if (r != 0) {
		error("Failed to generate secret the key.");
		return 1;
	}

	_cleanup_binary_ dnssec_binary_t key_b64 = { 0 };
	r = dnssec_binary_to_base64(&key, &key_b64);
	if (r != DNSSEC_EOK) {
		error("Failed to convert the key to Base64.");
		return 1;
	}

	print_tsig(config.algorithm, name, &key_b64);

	return 0;
}

static int cmd_keystore(int argc, char *argv[])
{
	static const command_t commands[] = {
		{ "list", cmd_keystore_list, LEGACY },
		{ "show", cmd_keystore_show, LEGACY },
		{ "add",  cmd_keystore_add,  LEGACY },
		{ NULL }
	};

	return subcommand(commands, options.legacy, argc, argv);
}

static int cmd_tsig(int argc, char *argv[])
{
	static const command_t commands[] = {
		{ "generate", cmd_tsig_generate },
		{ NULL }
	};

	return subcommand(commands, options.legacy, argc, argv);
}

static void print_help(void)
{
	printf("Please, see %s(8) manual page.\n", PROGRAM_NAME);
}

static void print_version(void)
{
	printf("%s (Knot DNS), version %s\n", PROGRAM_NAME, PACKAGE_VERSION);
}

int main(int argc, char *argv[])
{
	int exit_code = 1;

	// global options

	static const struct option opts[] = {
		{ "config",  required_argument, NULL, 'c' },
		{ "confdb",  required_argument, NULL, 'C' },
		{ "dir",     required_argument, NULL, 'd' },
		{ "help",    no_argument,       NULL, 'h' },
		{ "legacy",  no_argument,       NULL, 'l' },
		{ "version", no_argument,       NULL, 'V' },
		{ NULL }
	};

	int c = 0;
	while (c = getopt_long(argc, argv, "+c:C:d:hlV", opts, NULL), c != -1) {
		switch (c) {
		case 'c':
			options.config = optarg;
			break;
		case 'C':
			options.confdb = optarg;
			break;
		case 'd':
			free(options.kasp_dir);
			options.kasp_dir = strdup(optarg);
			break;
		case 'h':
			print_help();
			exit_code = 0;
			goto failed;
		case 'l':
			options.legacy = true;
			break;
		case 'V':
			print_version();
			exit_code = 0;
			goto failed;
		default:
			goto failed;
		}
	}

	// global configuration

	int r = options_init(&options);
	if (r != DNSSEC_EOK) {
		goto failed;
	}

	// subcommands

	static command_t commands[] = {
		{ "tsig",     cmd_tsig },
		{ "zone",     cmd_zone },
		{ "init",     cmd_init,     LEGACY },
		{ "policy",   cmd_policy,   LEGACY },
		{ "keystore", cmd_keystore, LEGACY },
		{ NULL }
	};

	dnssec_crypto_init();
	exit_code = subcommand(commands, options.legacy, argc - optind, argv + optind);
	dnssec_crypto_cleanup();

failed:
	options_cleanup(&options);

	return exit_code;
}
