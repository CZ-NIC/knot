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

#include <tap/basic.h>
#include <string.h>

#include "dnssec/error.h"
#include "dnssec/kasp.h"
#include "event/action.h"
#include "shared.h"

static const event_action_functions_t *api(void)
{
	return &event_action_nsec3_resalt;
}

static void test_responds_to(void)
{
	diag("responds_to");
	ok(api()->responds_to(DNSSEC_EVENT_NSEC3_RESALT), "valid");
	ok(!api()->responds_to(DNSSEC_EVENT_GENERATE_INITIAL_KEY), "invalid");
}

static void test_plan(void)
{
	diag("plan");

	dnssec_kasp_zone_t zone = { 0 };

	dnssec_kasp_policy_t policy = {
		.nsec3_enabled = false,
		.nsec3_salt_lifetime = 1000,
		.nsec3_iterations = 10,
		.nsec3_salt_length = 16,
	};

	dnssec_event_ctx_t ctx = {
		.zone = &zone,
		.policy = &policy,
		.now = 42000,
	};

	dnssec_event_t event = { 0 };

	int r = api()->plan(&ctx, &event);
	ok(r == DNSSEC_EOK && event.type == DNSSEC_EVENT_NONE,
	   "NSEC3 disabled");

	policy.nsec3_enabled = true;
	clear_struct(&event);
	r = api()->plan(&ctx, &event);
	ok(r == DNSSEC_EOK && event.type == DNSSEC_EVENT_NSEC3_RESALT &&
	   event.time == 42000, "salt not generated");

	dnssec_binary_alloc(&zone.nsec3_salt, 16);
	zone.nsec3_salt_created = 43000;
	clear_struct(&event);
	r = api()->plan(&ctx, &event);
	ok(r == DNSSEC_EINVAL, "salt from future");

	zone.nsec3_salt_created = 40000;
	clear_struct(&event);
	r = api()->plan(&ctx, &event);
	ok(r == DNSSEC_EOK && event.type == DNSSEC_EVENT_NSEC3_RESALT &&
	   event.time == 42000, "salt overdue");

	zone.nsec3_salt_created = 41500;
	clear_struct(&event);
	r = api()->plan(&ctx, &event);
	ok(r == DNSSEC_EOK && event.type == DNSSEC_EVENT_NSEC3_RESALT &&
	   event.time == 42500, "fresh salt");

	policy.nsec3_salt_length = 20;
	clear_struct(&event);
	r = api()->plan(&ctx, &event);
	ok(r == DNSSEC_EOK && event.type == DNSSEC_EVENT_NSEC3_RESALT &&
	   event.time == 42000, "salt size incorrect");

	policy.nsec3_salt_length = 0;
	clear_struct(&event);
	r = api()->plan(&ctx, &event);
	ok(r == DNSSEC_EOK && event.type == DNSSEC_EVENT_NONE,
	   "nothing to resalt");

	dnssec_binary_free(&zone.nsec3_salt);

}

static int mock_zone_save(void *ctx, const dnssec_kasp_zone_t *zone)
{
	return DNSSEC_EOK;
}

static const dnssec_kasp_store_functions_t mock_kasp = {
	.zone_save = mock_zone_save,
};

static void test_exec(void)
{
	diag("exec");

	dnssec_kasp_t *kasp = NULL;
	dnssec_kasp_init_custom(&kasp, &mock_kasp);

	dnssec_kasp_zone_t zone = { .name = ".", .dname = (uint8_t *)"" };
	dnssec_binary_alloc(&zone.nsec3_salt, 10);

	dnssec_kasp_policy_t policy = {
		.nsec3_enabled = true,
		.nsec3_salt_lifetime = 1000,
		.nsec3_iterations = 10,
		.nsec3_salt_length = 16,
	};

	dnssec_event_ctx_t ctx = {
		.kasp = kasp,
		.zone = &zone,
		.policy = &policy,
		.now = 7000,
	};

	dnssec_event_t event = {
		.type = DNSSEC_EVENT_NSEC3_RESALT,
		.time = 7000,
	};

	int r = api()->exec(&ctx, &event);
	ok(r == DNSSEC_EOK &&
	   zone.nsec3_salt.size == 16 && zone.nsec3_salt_created == 7000,
	   "generate salt");

	policy.nsec3_salt_length = 0;
	ctx.now = 8000;
	r = api()->exec(&ctx, &event);
	ok(r == DNSSEC_EOK &&
	   zone.nsec3_salt.size == 0 && zone.nsec3_salt_created == 8000,
	   "generate salt of zero length");

	dnssec_binary_free(&zone.nsec3_salt);
	dnssec_kasp_deinit(kasp);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	test_responds_to();
	test_plan();
	test_exec();

	return 0;
}
