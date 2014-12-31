/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dnssec/crypto.h>
#include <dnssec/error.h>
#include <dnssec/kasp.h>
#include <dnssec/keystore.h>

#include "cmdparse/command.h"
#include "cmdparse/parameter.h"
#include "cmdparse/value.h"
#include "legacy/key.h"
#include "print.h"
#include "shared.h"

/* -- global options ------------------------------------------------------- */

struct options {
	char *kasp_dir;
	char *keystore_dir;
};

typedef struct options options_t;

static options_t global = { 0 };

/* -- internal ------------------------------------------------------------- */

static void cleanup_kasp(dnssec_kasp_t **kasp_ptr)
{
	dnssec_kasp_deinit(*kasp_ptr);
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

#define _cleanup_kasp_ _cleanup_(cleanup_kasp)
#define _cleanup_keystore_ _cleanup_(cleanup_keystore)
#define _cleanup_zone_ _cleanup_(cleanup_kasp_zone)
#define _cleanup_policy_ _cleanup_(cleanup_kasp_policy)

/* -- frequent operations -------------------------------------------------- */

static dnssec_kasp_t *get_kasp(void)
{
	dnssec_kasp_t *kasp = NULL;

	dnssec_kasp_init_dir(&kasp);
	int r = dnssec_kasp_open(kasp, global.kasp_dir);
	if (r != DNSSEC_EOK) {
		error("Cannot open KASP directory (%s).", dnssec_strerror(r));
		dnssec_kasp_deinit(kasp);
		return NULL;
	}

	return kasp;
}

static dnssec_keystore_t *get_keystore(void)
{
	dnssec_keystore_t *store = NULL;

	dnssec_keystore_init_pkcs8_dir(&store);
	int r = dnssec_keystore_open(store, global.keystore_dir);
	if (r != DNSSEC_EOK) {
		error("Cannot open private key store (%s).", dnssec_strerror(r));
		dnssec_keystore_deinit(store);
		return NULL;
	}

	return store;
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

static bool zone_add_dnskey(dnssec_kasp_zone_t *zone, dnssec_key_t *dnskey,
			    const dnssec_kasp_key_timing_t *timing)
{
	dnssec_kasp_key_t *key = calloc(1, sizeof(*key));
	if (!key) {
		error("Failed to create a zone key (out of memory).");
		return false;
	}

	key->key = dnskey;
	if (timing) {
		key->timing = *timing;
	}

	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(zone);
	dnssec_list_append(keys, key);

	return true;
}

static void print_key(const dnssec_key_t *key)
{
	printf("id %s keytag %d\n", dnssec_key_get_id(key), dnssec_key_get_keytag(key));
}


/* -- actions implementation ----------------------------------------------- */

/*
 * keymgr init
 */
static int cmd_init(int argc, char *argv[])
{
	if (argc != 0) {
		error("Extra parameters supplied.");
		return 1;
	}

	// KASP

	_cleanup_kasp_ dnssec_kasp_t *kasp = NULL;
	dnssec_kasp_init_dir(&kasp);

	int r = dnssec_kasp_init(kasp, global.kasp_dir);
	if (r != DNSSEC_EOK) {
		error("Cannot initialize KASP directory (%s).", dnssec_strerror(r));
		return 1;
	}

	// keystore

	_cleanup_keystore_ dnssec_keystore_t *store = NULL;
	dnssec_keystore_init_pkcs8_dir(&store);

	r = dnssec_keystore_init(store, global.keystore_dir);
	if (r != DNSSEC_EOK) {
		error("Cannot initialize default keystore (%s).", dnssec_strerror(r));
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

	char *zone_name = argv[0];
	char *policy = NULL;

	parameter_t params[] = {
		{ "policy", value_string },
		{ NULL }
	};

	if (parse_parameters(params, argc - 1, argv + 1, &policy) != 0) {
		return 1;
	}

	// create zone

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = NULL;
	int r = dnssec_kasp_zone_load(kasp, zone_name, &zone);
	if (r == DNSSEC_EOK || zone != NULL) {
		error("Zone with given name alredy exists.");
		return 1;
	}

	zone = dnssec_kasp_zone_new(zone_name);
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

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	dnssec_list_t *zones = NULL;
	int r = dnssec_kasp_zone_list(kasp, &zones);
	if (r != DNSSEC_EOK) {
		error("Failed to get list of zones (%s).", dnssec_strerror(r));
	}

	bool found_match = false;

	dnssec_list_foreach(item, zones) {
		const char *name = dnssec_item_get(item);
		if (match == NULL || strcasestr(name, match) != NULL) {
			found_match = true;
			printf("%s\n", name);
		}
	}

	dnssec_list_free_full(zones, NULL, NULL);

	if (!found_match) {
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

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
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

	parameter_t params[] = {
		{ "force", value_flag, .req_full_match = true },
		{ NULL }
	};

	if (parse_parameters(params, argc - 1, argv + 1, &force) != 0) {
		return 1;
	}

	// delete zone

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
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
 * keymgr zone key list <zone>
 */
static int cmd_zone_key_list(int argc, char *argv[])
{
	if (argc != 1) {
		error("Name of one zone has to be specified.");
		return 1;
	}

	char *zone_name = argv[0];

	// list the keys

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, zone_name);
	if (!zone) {
		return 1;
	}

	dnssec_list_t *zone_keys = dnssec_kasp_zone_get_keys(zone);
	dnssec_list_foreach(item, zone_keys) {
		const dnssec_kasp_key_t *key = dnssec_item_get(item);
		print_key(key->key);
	}

	return 0;
}

/*!
 * Match key by keytag or key ID prefix.
 */
static bool key_match(const dnssec_key_t *key, const char *search)
{
	// keytag exact match

	char keytag[10] = { 0 };
	snprintf(keytag, sizeof(keytag), "%d", dnssec_key_get_keytag(key));

	if (strcmp(search, keytag) == 0) {
		return true;
	}

	// key ID prefix match

	const char *keyid = dnssec_key_get_id(key);

	size_t keyid_len = strlen(keyid);
	size_t search_len = strlen(search);

	return (search_len <= keyid_len && strncasecmp(search, keyid, search_len) == 0);
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

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, zone_name);
	if (zone) {
		return 1;
	}

	bool found = false;

	dnssec_list_t *zone_keys = dnssec_kasp_zone_get_keys(zone);
	dnssec_list_foreach(item, zone_keys) {
		const dnssec_kasp_key_t *key = dnssec_item_get(item);
		if (!key_match(key->key, search)) {
			continue;
		}

		if (found) {
			printf("\n");
		}

		printf("id %s\n", dnssec_key_get_id(key->key));
		printf("keytag %d\n", dnssec_key_get_keytag(key->key));
		printf("algorithm %d\n", dnssec_key_get_algorithm(key->key));
		printf("size %u\n", dnssec_key_get_size(key->key));
		printf("flags %d\n", dnssec_key_get_flags(key->key));
		printf("publish %ld\n", key->timing.publish);
		printf("active %ld\n", key->timing.active);
		printf("retire %ld\n", key->timing.retire);
		printf("remove %ld\n", key->timing.remove);

		found = true;
	}

	if (!found) {
		error("No matching key found.");
		return 1;
	}

	return 0;
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
		unsigned size;
		bool is_ksk;
		dnssec_kasp_key_timing_t timing;
	};

	parameter_t params[] =   {
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

	if (config.size == 0) {
		error("Key size has to be specified.");
		return 1;
	}

	if (!dnssec_algorithm_key_size_check(config.algorithm, config.size)) {
		error("Key size is invalid for given algorithm.");
		return 1;
	}

	// open KASP and key store

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, config.name);
	if (!zone) {
		return 1;
	}

	_cleanup_keystore_ dnssec_keystore_t *store = get_keystore();
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

	dnssec_key_t *dnskey = NULL;
	dnssec_key_new(&dnskey);
	r = dnssec_key_import_keystore(dnskey, store, keyid, config.algorithm);
	if (r != DNSSEC_EOK) {
		dnssec_key_free(dnskey);
		error("Failed to create a DNSKEY record (%s).", dnssec_strerror(r));
		return 1;
	}

	uint16_t flags = config.is_ksk ? 257 : 256;
	dnssec_key_set_flags(dnskey, flags);

	// add DNSKEY into zone keys

	if (!zone_add_dnskey(zone, dnskey, &config.timing)) {
		free(dnskey);
		return 1;
	}

	r = dnssec_kasp_zone_save(kasp, zone);
	if (r != DNSSEC_EOK) {
		error("Failed to save updated zone (%s).", dnssec_strerror(r));
		dnssec_keystore_remove_key(store, keyid);
		return 1;
	}

	print_key(dnskey);

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

	parameter_t params[] = {
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

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, zone_name);
	if (!zone) {
		return 1;
	}

	dnssec_kasp_key_t *match = NULL;

	dnssec_list_t *zone_keys = dnssec_kasp_zone_get_keys(zone);
	dnssec_list_foreach(item, zone_keys) {
		dnssec_kasp_key_t *key = dnssec_item_get(item);
		if (key_match(key->key, search)) {
			if (match) {
				error("Multiple matching keys found.");
				return 1;
			}
			match = key;
		}
	}

	if (!match) {
		error("No matching key found.");
		return 1;
	}

	if (new_timing.publish >= 0) { match->timing.publish = new_timing.publish; }
	if (new_timing.active >= 0) { match->timing.active = new_timing.active; }
	if (new_timing.retire >= 0) { match->timing.retire = new_timing.retire; }
	if (new_timing.remove >= 0) { match->timing.remove = new_timing.remove; }

	int r = dnssec_kasp_zone_save(kasp, zone);
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

	_cleanup_kasp_ dnssec_kasp_t *kasp = get_kasp();
	if (!kasp) {
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = get_zone(kasp, zone_name);
	if (!zone) {
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

	_cleanup_keystore_ dnssec_keystore_t *store = get_keystore();
	if (!store) {
		dnssec_key_free(key);
		return 1;
	}

	_cleanup_free_ char *keyid = NULL;
	r = dnssec_keystore_import(store, &pem, &keyid);
	if (r != DNSSEC_EOK) {
		error("Failed to import private key (%s).", dnssec_strerror(r));
		dnssec_key_free(key);
		return 1;
	}

	if (!zone_add_dnskey(zone, key, &timing)) {
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

	print_key(key);

	return 0;
}

static int cmd_zone_key(int argc, char *argv[])
{
	static const command_t commands[] = {
		{ "list",     cmd_zone_key_list },
		{ "show",     cmd_zone_key_show },
		{ "generate", cmd_zone_key_generate },
		{ "set",      cmd_zone_key_set },
		{ "import",   cmd_zone_key_import },
		{ NULL }
	};

	return subcommand(commands, argc, argv);
}

static int cmd_zone(int argc, char *argv[])
{
	static const command_t commands[] = {
		{ "add",    cmd_zone_add },
		{ "list",   cmd_zone_list },
		{ "remove", cmd_zone_remove },
		{ "show",   cmd_zone_show },
		{ "key",    cmd_zone_key },
		{ NULL }
	};

	return subcommand(commands, argc, argv);
}

static int cmd_policy_list(int argc, char *argv[])
{
	error("Not implemented.");
	return 1;
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

	printf("algorithm:        %d\n", policy->algorithm);
	printf("KSK key size:     %u\n", policy->ksk_size);
	printf("ZSK key size:     %u\n", policy->zsk_size);
	printf("DNSKEY TTL:       %u\n", policy->dnskey_ttl);
	printf("RRSIG lifetime:   %u\n", policy->rrsig_lifetime);
	printf("SOA minimum:      %u\n", policy->soa_minimal_ttl);
	printf("maximal zone TTL: %u\n", policy->zone_maximal_ttl);
	printf("data propagation: %u\n", policy->propagation_delay);

	return 0;
}

static int cmd_policy_add(int argc, char *argv[])
{
	error("Not implemented.");
	return 1;
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

	int r = dnssec_kasp_policy_save(kasp, policy);
	if (r != DNSSEC_EOK) {
		error("Failed to save updated policy (%s).", dnssec_strerror(r));
		return 1;
	}

	return 0;
}

static int cmd_policy_remove(int argc, char *argv[])
{
	error("Not implemented");

	return 1;
}

static int cmd_policy(int argc, char *argv[])
{
	static const command_t commands[] = {
		{ "list",   cmd_policy_list   },
		{ "show",   cmd_policy_show   },
		{ "add",    cmd_policy_add    },
		{ "set",    cmd_policy_set    },
		{ "remove", cmd_policy_remove },
		{ NULL }
	};

	return subcommand(commands, argc, argv);
}

static int cmd_keystore_list(int argc, char *argv[])
{
	_cleanup_keystore_ dnssec_keystore_t *store = get_keystore();
	if (!store) {
		return 1;
	}

	dnssec_list_t *keys = NULL;
	dnssec_keystore_list_keys(store, &keys);
	dnssec_list_foreach(item, keys) {
		const char *key_id = dnssec_item_get(item);
		printf("%s\n", key_id);
	}
	dnssec_list_free_full(keys, NULL, NULL);

	return 0;
}

static int cmd_keystore(int argc, char *argv[])
{
	static const command_t commands[] = {
		{ "list",   cmd_keystore_list },
		{ NULL }
	};

	return subcommand(commands, argc, argv);
}

static void print_help(void)
{
	printf("TBD.\n");
}

static void print_version(void)
{
	printf("keymgr, version %s\n", PACKAGE_VERSION);
}

int main(int argc, char *argv[])
{
	int exit_code = 1;

	// global configuration

	global.kasp_dir = getcwd(NULL, 0);
	assert(global.kasp_dir);

	// global options

	static const struct option opts[] = {
		{ "dir",     required_argument, NULL, 'd' },
		{ "help",    no_argument,       NULL, 'h' },
		{ "version", no_argument,       NULL, 'V' },
		{ NULL }
	};

	int c = 0;
	while (c = getopt_long(argc, argv, "+", opts, NULL), c != -1) {
		switch (c) {
		case 'd':
			free(global.kasp_dir);
			global.kasp_dir = strdup(optarg);
			break;
		case 'h':
			print_help();
			exit_code = 0;
			goto failed;
		case 'V':
			print_version();
			exit_code = 0;
			goto failed;
		case '?':
			goto failed;
		default:
			assert(0);
		}
	}

	if (asprintf(&global.keystore_dir, "%s/keys", global.kasp_dir) == -1) {
		error("failed to allocate memory");
		global.keystore_dir = NULL;
		goto failed;
	}

	// subcommands

	static const command_t commands[] = {
		{ "init",     cmd_init },
		{ "zone",     cmd_zone },
		{ "policy",   cmd_policy },
		{ "keystore", cmd_keystore },
		{ NULL }
	};

	dnssec_crypto_init();

	exit_code = subcommand(commands, argc - optind, argv + optind);

failed:
	dnssec_crypto_cleanup();

	free(global.kasp_dir);
	free(global.keystore_dir);

	return exit_code;
}
