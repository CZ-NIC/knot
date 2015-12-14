/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdbool.h>

#include "dnssec/error.h"
#include "dnssec/event.h"
#include "event/action.h"
#include "shared.h"

_public_
const char *dnssec_event_name(dnssec_event_type_t event)
{
	switch (event) {
	case DNSSEC_EVENT_NONE:
		return "no event";
	case DNSSEC_EVENT_GENERATE_INITIAL_KEY:
		return "generate initial keys";
	case DNSSEC_EVENT_ZSK_ROLL_PUBLISH_NEW_KEY:
		return "ZSK rollover, publish new key";
	case DNSSEC_EVENT_ZSK_ROLL_REPLACE_SIGNATURES:
		return "ZSK rollover, replace signatures";
	case DNSSEC_EVENT_ZSK_ROLL_REMOVE_OLD_KEY:
		return "ZSK rollover, remove old key";
	default:
		return "unknown event";
	}
}

_public_
int dnssec_event_get_next(dnssec_event_ctx_t *ctx, dnssec_event_t *event)
{
	if (!ctx || !event || !ctx->policy) {
		return DNSSEC_EINVAL;
	}

	dnssec_event_t first = { 0 };

	if (ctx->policy->manual) {
		goto done;
	}

	const event_action_functions_t * const *action;
	for (action = EVENT_ACTION_HANDLERS; *action; action++) {
		dnssec_event_t search = { 0 };
		int r = (*action)->plan(ctx, &search);
		if (r != DNSSEC_EOK) {
			return r;
		}

		if (search.type == DNSSEC_EVENT_NONE) {
			continue;
		}

		if (first.time == 0 || search.time < first.time) {
			first = search;
			if (first.time <= ctx->now) {
				break;
			}
		}
	}

done:
	*event = first;

	return DNSSEC_EOK;
}

_public_
int dnssec_event_execute(dnssec_event_ctx_t *ctx, dnssec_event_t *event)
{
	if (!ctx || !event) {
		return DNSSEC_EINVAL;
	}

	const event_action_functions_t * const *action;
	for (action = EVENT_ACTION_HANDLERS; *action; action++) {
		if ((*action)->responds_to(event->type)) {
			return (*action)->exec(ctx, event);
		}
	}

	return DNSSEC_EINVAL;
}
