/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "dnssec/binary.h"
#include "dnssec/error.h"
#include "dnssec/random.h"
#include "event/action.h"
#include "event/utils.h"

static bool responds_to(dnssec_event_type_t event)
{
	return event == DNSSEC_EVENT_NSEC3_RESALT;
}

static bool params_match(const dnssec_binary_t *salt,
			 const dnssec_kasp_policy_t *policy)
{
	return salt->size == policy->nsec3_salt_length;
}

static int plan(dnssec_event_ctx_t *ctx, dnssec_event_t *event)
{
	assert(ctx);
	assert(event);

	if (!ctx->policy->nsec3_enabled || ctx->policy->nsec3_salt_length == 0) {
		return DNSSEC_EOK;
	}

	time_t next = 0;

	if (!params_match(&ctx->zone->nsec3_salt, ctx->policy)) {
		next = ctx->now;
	} else {
		if (ctx->now < ctx->zone->nsec3_salt_created) {
			return DNSSEC_EINVAL;
		}

		time_t age = ctx->now - ctx->zone->nsec3_salt_created;

		if (age >= ctx->policy->nsec3_salt_lifetime) {
			next = ctx->now;
		} else {
			next = ctx->now + (ctx->policy->nsec3_salt_lifetime - age);
		}
	}

	event->type = DNSSEC_EVENT_NSEC3_RESALT;
	event->time = next;

	return DNSSEC_EOK;
}

static int generate_salt(dnssec_binary_t *salt, uint16_t length)
{
	assert(salt);
	dnssec_binary_t new_salt = { 0 };

	if (length > 0) {
		int r = dnssec_binary_alloc(&new_salt, length);
		if (r != DNSSEC_EOK) {
			return r;
		}

		r = dnssec_random_binary(&new_salt);
		if (r != DNSSEC_EOK) {
			dnssec_binary_free(&new_salt);
			return r;
		}
	}

	dnssec_binary_free(salt);
	*salt = new_salt;

	return DNSSEC_EOK;
}

static int exec(dnssec_event_ctx_t *ctx, const dnssec_event_t *event)
{
	assert(ctx);
	assert(event);
	assert(event->type == DNSSEC_EVENT_NSEC3_RESALT);

	int r = generate_salt(&ctx->zone->nsec3_salt, ctx->policy->nsec3_salt_length);
	if (r != DNSSEC_EOK) {
		return r;
	}

	ctx->zone->nsec3_salt_created = ctx->now;

	return dnssec_kasp_zone_save(ctx->kasp, ctx->zone);
}

/*! Event API. */
const event_action_functions_t event_action_nsec3_resalt = {
	.responds_to = responds_to,
	.plan        = plan,
	.exec        = exec,
};
