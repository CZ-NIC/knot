/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "contrib/time.h"
#include "knot/dnssec/kasp/policy.h"

typedef enum {
	DNSSEC_KEY_STATE_INVALID = 0,
	DNSSEC_KEY_STATE_PRE_ACTIVE,
	DNSSEC_KEY_STATE_PUBLISHED,
	DNSSEC_KEY_STATE_READY,
	DNSSEC_KEY_STATE_ACTIVE,
	DNSSEC_KEY_STATE_RETIRE_ACTIVE,
	DNSSEC_KEY_STATE_RETIRED,
	DNSSEC_KEY_STATE_POST_ACTIVE,
	DNSSEC_KEY_STATE_REVOKED,
	DNSSEC_KEY_STATE_REMOVED,
} key_state_t;

key_state_t get_key_state(const knot_kasp_key_t *key, knot_time_t moment);
