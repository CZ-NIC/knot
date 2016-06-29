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

#pragma once

#include <stdbool.h>

#include "dnssec/event.h"

struct event_action_functions {
	bool (*responds_to)(dnssec_event_type_t event);
	int (*plan)(dnssec_event_ctx_t *ctx, dnssec_event_t *event);
	int (*exec)(dnssec_event_ctx_t *ctx, const dnssec_event_t *event);
};

typedef struct event_action_functions event_action_functions_t;

extern const event_action_functions_t event_action_initial_key;
extern const event_action_functions_t event_action_zsk_rollover;
extern const event_action_functions_t event_action_nsec3_resalt;

/*!
 * List of event implementations sorted by priority.
 */
static const event_action_functions_t * const EVENT_ACTION_HANDLERS[] = {
	&event_action_initial_key,
	&event_action_zsk_rollover,
	&event_action_nsec3_resalt,
	NULL,
};
