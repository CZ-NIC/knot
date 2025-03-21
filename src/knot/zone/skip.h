/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/libknot.h"
#include "knot/conf/conf.h"

struct zone_contents; // elsewhere

knot_dynarray_declare(rrtype, uint16_t, DYNARRAY_VISIBILITY_NORMAL, 64)
typedef rrtype_dynarray_t zone_skip_t;

/*!
 * \brief Add single type (or "dnssec") to given list of skip types.
 */
int zone_skip_add(zone_skip_t *skip, const char *type_str);

/*!
 * \brief Add DNSSEC types relevant for zone diff computation to skip.
 *
 * \note This inclused RRSIGs and NSECs due to zone being signed, but DNSKEYs
 *       might be partially managed from outside in the case of incremental policy.
 */
int zone_skip_add_dnssec_diff(zone_skip_t *skip);

/*!
 * \brief Fill in zone_skip structure according to a configuration option.
 */
int zone_skip_from_conf(zone_skip_t *skip, conf_val_t *val);

/*!
 * \brief Should we skip loading/dumping this type according to zone_skip structure?
 */
inline static bool zone_skip_type(zone_skip_t *skip, uint16_t type)
{
	return skip != NULL && rrtype_dynarray_bsearch(skip, &type) != NULL;
}

/*!
 * \brief Free any potentially allocated memory by zone_skip structure.
 */
inline static void zone_skip_free(zone_skip_t *skip)
{
	rrtype_dynarray_free(skip);
}

/*!
 * \brief Read from conf what should be skipped and write zone file to given path.
 */
int zonefile_write_skip(const char *path, struct zone_contents *zone, conf_t *conf);
