/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/dnssec/context.h"
#include "knot/zone/contents.h"

/*!
 * \brief Update policy parameters depending on zone content.
 */
void update_policy_from_zone(conf_t *conf,
                             knot_kasp_policy_t *policy,
                             const zone_contents_t *zone);
