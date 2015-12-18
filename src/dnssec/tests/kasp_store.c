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

#include <stdbool.h>
#include <string.h>
#include <tap/basic.h>

#include "dnssec/error.h"
#include "dnssec/kasp.h"
#include "kasp/internal.h"
#include "kasp/zone.h"

bool streq(const char *a, const char *b)
{
	return a && b && strcmp(a, b) == 0;
}

static void *MOCK_CTX = (void *)0xaced7e57;

static bool mock_policy_open_ok = false;
static int mock_policy_policy_open(void **ctx_ptr, const char *config)
{
	mock_policy_open_ok = ctx_ptr && streq(config, "valid config");
	if (ctx_ptr) {
		*ctx_ptr = MOCK_CTX;
	}

	return DNSSEC_EOK;
}

static bool mock_policy_close_ok = false;
static void mock_policy_close(void *ctx)
{
	mock_policy_close_ok = ctx == MOCK_CTX;
}

static bool mock_zone_load_ok = false;
static int mock_zone_load(void *ctx, dnssec_kasp_zone_t *zone)
{
	mock_zone_load_ok = ctx == MOCK_CTX && zone &&
			    streq(zone->name, "some.zone") &&
			    streq((char *)zone->dname, "\x04some\x04zone\x00") &&
			    zone->policy == NULL &&
			    dnssec_list_is_empty(zone->keys);
	if (zone) {
		zone->policy = strdup("bleedingedge");
	}

	return DNSSEC_EOK;
}

static bool mock_zone_save_ok = false;
static int mock_zone_save(void *ctx, dnssec_kasp_zone_t *zone)
{
	mock_zone_save_ok = ctx == MOCK_CTX && zone &&
			    streq(zone->policy, "cuttingedge");

	return DNSSEC_EOK;
}

static bool mock_zone_remove_ok = false;
static int mock_zone_remove(void *ctx, const char *name)
{
	mock_zone_remove_ok = ctx == MOCK_CTX && streq(name, "zone.to.remove");

	return DNSSEC_EOK;
}

static bool mock_zone_list_ok = false;
static int mock_zone_list(void *ctx, dnssec_list_t *names)
{
	mock_zone_list_ok = ctx == MOCK_CTX && names && dnssec_list_size(names) == 0;
	if (names) {
		dnssec_list_append(names, strdup("coconut"));
	}

	return DNSSEC_EOK;
}

static bool mock_zone_exists_ok = false;
static int mock_zone_exists(void *ctx, const char *name)
{
	mock_zone_exists_ok = ctx == MOCK_CTX && streq(name, "cool.name");

	return DNSSEC_EOK;
}

static bool mock_policy_load_ok = false;
static int mock_policy_load(void *ctx, dnssec_kasp_policy_t *policy)
{
	mock_policy_load_ok = ctx == MOCK_CTX && policy && streq(policy->name, "happy");
	if (policy) {
		policy->rrsig_lifetime = 12345;
	}

	return DNSSEC_EOK;
}

static bool mock_policy_save_ok = false;
static int mock_policy_save(void *ctx, dnssec_kasp_policy_t *policy)
{
	mock_policy_save_ok = ctx == MOCK_CTX && policy &&
			      streq(policy->name, "happy") &&
			      policy->rrsig_lifetime == 54321;

	return DNSSEC_EOK;
}

static bool mock_policy_remove_ok = false;
static int mock_policy_remove(void *ctx, const char *name)
{
	mock_policy_remove_ok = ctx == MOCK_CTX && streq(name, "remove-me");

	return DNSSEC_EOK;
}

static bool mock_policy_list_ok = false;
static int mock_policy_list(void *ctx, dnssec_list_t *names)
{
	mock_policy_list_ok = ctx == MOCK_CTX && names && dnssec_list_size(names) == 0;
	if (names) {
		dnssec_list_append(names, strdup("banana"));
	}

	return DNSSEC_EOK;
}

static bool mock_policy_exists_ok = false;
static int mock_policy_exists(void *ctx, const char *name)
{
	mock_policy_exists_ok = ctx == MOCK_CTX && streq(name, "superstrict");

	return DNSSEC_EOK;
}

static bool mock_keystore_load_ok = false;
static int mock_keystore_load(void *ctx, dnssec_kasp_keystore_t *keystore)
{
	mock_keystore_load_ok = ctx == MOCK_CTX && keystore && streq(keystore->name, "foobar");
	if (keystore) {
		keystore->backend = strdup("mock");
		keystore->config  = strdup("abc=123");
	}

	return DNSSEC_EOK;
}

static bool mock_keystore_save_ok = false;
static int mock_keystore_save(void *ctx, dnssec_kasp_keystore_t *keystore)
{
	mock_keystore_save_ok = ctx == MOCK_CTX && keystore &&
			      streq(keystore->name, "foobar") &&
			      streq(keystore->config, "abc=456");

	return DNSSEC_EOK;
}

static bool mock_keystore_remove_ok = false;
static int mock_keystore_remove(void *ctx, const char *name)
{
	mock_keystore_remove_ok = ctx == MOCK_CTX && streq(name, "nomorefoo");

	return DNSSEC_EOK;
}

static bool mock_keystore_list_ok = false;
static int mock_keystore_list(void *ctx, dnssec_list_t *names)
{
	mock_keystore_list_ok = ctx == MOCK_CTX && names && dnssec_list_size(names) == 0;
	if (names) {
		dnssec_list_append(names, strdup("pineapple"));
	}

	return DNSSEC_EOK;
}

static bool mock_keystore_exists_ok = false;
static int mock_keystore_exists(void *ctx, const char *name)
{
	mock_keystore_exists_ok = ctx == MOCK_CTX && streq(name, "istherebar");

	return DNSSEC_EOK;
}

static const dnssec_kasp_store_functions_t MOCK = {
	.open            = mock_policy_policy_open,
	.close           = mock_policy_close,
	.zone_load       = mock_zone_load,
	.zone_save       = mock_zone_save,
	.zone_remove     = mock_zone_remove,
	.zone_list       = mock_zone_list,
	.zone_exists     = mock_zone_exists,
	.policy_load     = mock_policy_load,
	.policy_save     = mock_policy_save,
	.policy_remove   = mock_policy_remove,
	.policy_list     = mock_policy_list,
	.policy_exists   = mock_policy_exists,
	.keystore_load   = mock_keystore_load,
	.keystore_save   = mock_keystore_save,
	.keystore_remove = mock_keystore_remove,
	.keystore_list   = mock_keystore_list,
	.keystore_exists = mock_keystore_exists,
};

static void test_zone(dnssec_kasp_t *kasp)
{
	// load

	dnssec_kasp_zone_t *zone = NULL;
	int r = dnssec_kasp_zone_load(kasp, "some.ZONE..", &zone);
	ok(r == DNSSEC_EOK && zone, "zone load, call");
	ok(mock_zone_load_ok, "zone load, input");
	ok(zone && streq(zone->policy, "bleedingedge"), "zone load, output");

	// save

	free(zone->policy);
	zone->policy = strdup("cuttingedge");
	r = dnssec_kasp_zone_save(kasp, zone);
	ok(r == DNSSEC_EOK, "zone save, call");
	ok(mock_zone_save_ok, "zone save, input");

	dnssec_kasp_zone_free(zone);

	// remove

	r = dnssec_kasp_zone_remove(kasp, "ZONE.to.REMOVE");
	ok(r == DNSSEC_EOK, "zone remove, call");
	ok(mock_zone_remove_ok, "zone remove, input");

	// list

	dnssec_list_t *zones = NULL;
	r = dnssec_kasp_zone_list(kasp, &zones);
	ok(r == DNSSEC_EOK && zones, "zone list, call");
	ok(mock_zone_list_ok, "zone list, input");
	ok(dnssec_list_size(zones) == 1 &&
	   streq(dnssec_item_get(dnssec_list_tail(zones)), "coconut"),
	   "zone list, output");

	dnssec_list_free_full(zones, NULL, NULL);

	// exists

	r = dnssec_kasp_zone_exists(kasp, "cool.name");
	ok(r == DNSSEC_EOK, "zone exists, call");
	ok(mock_zone_exists_ok, "zone exists, input");
}

static void test_policy(dnssec_kasp_t *kasp)
{
	// load

	dnssec_kasp_policy_t *policy = NULL;
	int r = dnssec_kasp_policy_load(kasp, "happy", &policy);
	ok(r == DNSSEC_EOK && policy, "policy load: call");
	ok(mock_policy_load_ok, "policy load: input");
	ok(policy && streq(policy->name, "happy") &&
	   policy->rrsig_lifetime == 12345,
	   "policy load: output");

	// save

	if (policy) {
		policy->rrsig_lifetime = 54321;
	}
	r = dnssec_kasp_policy_save(kasp, policy);
	ok(r == DNSSEC_EOK, "policy save: call");
	ok(mock_policy_save_ok, "policy save: input");

	dnssec_kasp_policy_free(policy);

	// remove

	r = dnssec_kasp_policy_remove(kasp, "remove-me");
	ok(r == DNSSEC_EOK, "policy remove: call");
	ok(mock_policy_remove_ok, "policy remove: input");

	// list

	dnssec_list_t *names = NULL;
	r = dnssec_kasp_policy_list(kasp, &names);
	ok(r == DNSSEC_EOK && names, "policy list: call");
	ok(mock_policy_list_ok, "policy list: input");
	ok(dnssec_list_size(names) == 1 &&
	   streq("banana", dnssec_item_get(dnssec_list_tail(names))),
	   "policy list: output");

	dnssec_list_free_full(names, NULL, NULL);

	// exists

	r = dnssec_kasp_policy_exists(kasp, "superstrict");
	ok(r == DNSSEC_EOK, "policy exists, call");
	ok(mock_policy_exists_ok, "policy exists, input");
}

static void test_keystore(dnssec_kasp_t *kasp)
{
	// load

	dnssec_kasp_keystore_t *keystore = NULL;
	int r = dnssec_kasp_keystore_load(kasp, "foobar", &keystore);
	ok(r == DNSSEC_EOK && keystore, "keystore load: call");
	ok(mock_keystore_load_ok, "keystore load: input");
	ok(keystore &&
	   streq(keystore->name, "foobar") &&
	   streq(keystore->backend, "mock") &&
	   streq(keystore->config, "abc=123"),
	   "keystore load: output");

	// save

	if (keystore) {
		free(keystore->config);
		keystore->config = strdup("abc=456");
	}
	r = dnssec_kasp_keystore_save(kasp, keystore);
	ok(r == DNSSEC_EOK, "keystore save: call");
	ok(mock_keystore_save_ok, "keystore save: input");

	dnssec_kasp_keystore_free(keystore);

	// remove

	r = dnssec_kasp_keystore_remove(kasp, "nomorefoo");
	ok(r == DNSSEC_EOK, "keystore remove: call");
	ok(mock_keystore_remove_ok, "keystore remove: input");

	// list

	dnssec_list_t *names = NULL;
	r = dnssec_kasp_keystore_list(kasp, &names);
	ok(r == DNSSEC_EOK && names, "keystore list: call");
	ok(mock_keystore_list_ok, "keystore list: input");
	ok(dnssec_list_size(names) == 1 &&
	   streq("pineapple", dnssec_item_get(dnssec_list_tail(names))),
	   "keystore list: output");

	dnssec_list_free_full(names, NULL, NULL);

	// exists

	r = dnssec_kasp_keystore_exists(kasp, "istherebar");
	ok(r == DNSSEC_EOK, "keystore exists, call");
	ok(mock_keystore_exists_ok, "keystore exists, input");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	dnssec_kasp_t *kasp = NULL;
	int r = dnssec_kasp_create(&kasp, &MOCK);
	ok(r == DNSSEC_EOK && kasp, "create mock KASP");

	r = dnssec_kasp_open(kasp, "valid config");
	ok(r == DNSSEC_EOK && mock_policy_open_ok, "open mock KASP");

	test_zone(kasp);
	test_policy(kasp);
	test_keystore(kasp);

	dnssec_kasp_deinit(kasp);
	ok(mock_policy_close_ok, "close mock KASP");

	return 0;
}
