/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/zone/semantic-check.h"
#include "libknot/libknot.h"

int zone_check(const char *zone_file, const knot_dname_t *zone_name, bool zonemd,
               uint32_t dflt_ttl, semcheck_optional_t optional, time_t time, bool print);
