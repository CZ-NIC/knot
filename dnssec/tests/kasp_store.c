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

bool streq(const char *a, const char *b)
{
	return a && b && strcmp(a, b) == 0;
}

static void *mock_ctx = (void *)0xaced7e57;

static bool mock_policy_open_ok = false;
static int mock_policy_policy_open(void **ctx_ptr, const char *config)
{
	mock_policy_open_ok = ctx_ptr && streq(config, "valid config");
	if (ctx_ptr) {
		*ctx_ptr = mock_ctx;
	}

	return DNSSEC_EOK;
}

static bool mock_policy_close_ok = false;
static void mock_policy_close(void *ctx)
{
	mock_policy_close_ok = ctx == mock_ctx;
}

static bool mock_policy_load_ok = false;
static int mock_policy_load(void *ctx, dnssec_kasp_policy_t *policy)
{
	mock_policy_load_ok = ctx == mock_ctx && policy && streq(policy->name, "happy");
	if (policy) {
		policy->rrsig_lifetime = 12345;
	}

	return DNSSEC_EOK;
}

static bool mock_policy_save_ok = false;
static int mock_policy_save(void *ctx, dnssec_kasp_policy_t *policy)
{
	mock_policy_save_ok = ctx == mock_ctx && policy &&
			      streq(policy->name, "happy") &&
			      policy->rrsig_lifetime == 54321;

	return DNSSEC_EOK;
}

static bool mock_policy_remove_ok = false;
static int mock_policy_remove(void *ctx, const char *name)
{
	mock_policy_remove_ok = ctx == mock_ctx && streq(name, "remove-me");

	return DNSSEC_EOK;
}

static bool mock_policy_list_ok = false;
static int mock_policy_list(void *ctx, dnssec_list_t *names)
{
	mock_policy_list_ok = ctx == mock_ctx && names && dnssec_list_size(names) == 0;
	if (names) {
		dnssec_list_append(names, strdup("banana"));
	}

	return DNSSEC_EOK;
}

static const dnssec_kasp_store_functions_t MOCK = {
	.open          = mock_policy_policy_open,
	.close         = mock_policy_close,
	.policy_load   = mock_policy_load,
	.policy_save   = mock_policy_save,
	.policy_remove = mock_policy_remove,
	.policy_list   = mock_policy_list
};

static void test_policy(dnssec_kasp_t *kasp)
{
	// load

	dnssec_kasp_policy_t *policy = NULL;
	int r = dnssec_kasp_policy_load(kasp, "happy", &policy);
	ok(r == DNSSEC_EOK && policy && mock_policy_load_ok &&
	   streq(policy->name, "happy") && policy->rrsig_lifetime == 12345,
	   "policy: load");

	// save

	if (policy) {
		policy->rrsig_lifetime = 54321;
	}
	r = dnssec_kasp_policy_save(kasp, policy);
	ok(r == DNSSEC_EOK && mock_policy_save_ok, "policy: save");

	dnssec_kasp_policy_free(policy);

	// remove

	r = dnssec_kasp_policy_remove(kasp, "remove-me");
	ok(r == DNSSEC_EOK && mock_policy_remove_ok, "policy: remove");

	// list

	dnssec_list_t *names = NULL;
	r = dnssec_kasp_policy_list(kasp, &names);
	ok(r == DNSSEC_EOK && names && mock_policy_list_ok &&
	   dnssec_list_size(names) == 1 &&
	   streq("banana", dnssec_item_get(dnssec_list_tail(names))),
	   "policy: list");

	dnssec_list_free_full(names, NULL, NULL);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	dnssec_kasp_t *kasp = NULL;
	int r = dnssec_kasp_create(&kasp, &MOCK);
	ok(r == DNSSEC_EOK && kasp, "create mock KASP");

	r = dnssec_kasp_open(kasp, "valid config");
	ok(r == DNSSEC_EOK && mock_policy_open_ok, "open mock KASP");

	test_policy(kasp);

	dnssec_kasp_deinit(kasp);
	ok(mock_policy_close_ok, "close mock KASP");

	return 0;
}
