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

#include <time.h>

#include <dnssec/kasp.h>
#include <dnssec/keystore.h>

enum dnssec_event_type {
	DNSSEC_EVENT_NONE = 0,
	DNSSEC_EVENT_GENERATE_INITIAL_KEY,
	DNSSEC_EVENT_ZSK_ROLL_PUBLISH_NEW_KEY,
	DNSSEC_EVENT_ZSK_ROLL_REPLACE_SIGNATURES,
	DNSSEC_EVENT_ZSK_ROLL_REMOVE_OLD_KEY,
	DNSSEC_EVENT_NSEC3_RESALT,
};

typedef enum dnssec_event_type dnssec_event_type_t;

/*!
 * Get user-readable name of DNSSEC event.
 */
const char *dnssec_event_name(dnssec_event_type_t event);

// TODO: disclose
struct dnssec_event {
	time_t time;
	dnssec_event_type_t type;
};

typedef struct dnssec_event dnssec_event_t;

struct dnssec_event_ctx {
	time_t now;
	dnssec_kasp_t *kasp;
	dnssec_kasp_zone_t *zone;
	dnssec_kasp_policy_t *policy;
	dnssec_keystore_t *keystore;
};

typedef struct dnssec_event_ctx dnssec_event_ctx_t;

/*!
 * Get next DNSSEC event to be executed.
 */
int dnssec_event_get_next(dnssec_event_ctx_t *ctx, dnssec_event_t *event);

/*!
 * Execute given DNSSEC event.
 */
int dnssec_event_execute(dnssec_event_ctx_t *ctx, dnssec_event_t *event);
