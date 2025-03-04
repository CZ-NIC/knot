/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "libknot/packet/pkt.h"

struct kdig_dnssec_ctx;

typedef enum {
	KDIG_VALIDATION_LOG_NONE,
	KDIG_VALIDATION_LOG_OUTCOME,
	KDIG_VALIDATION_LOG_ERRORS,
	KDIG_VALIDATION_LOG_INFOS,
	KDIG_VALIDATION_LOG_REASONING,
} kdig_validation_log_level_t;

int kdig_dnssec_validate(knot_pkt_t *pkt, struct kdig_dnssec_ctx **dv_ctx,
                         kdig_validation_log_level_t level,
                         knot_dname_t **zone_name, uint16_t *type_needed);
