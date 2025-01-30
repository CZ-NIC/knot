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

#include "libknot/libknot.h"
#include "knot/conf/conf.h"

struct zone_contents; // elsewhere

knot_dynarray_declare(rrtype, uint16_t, DYNARRAY_VISIBILITY_NORMAL, 64)
typedef rrtype_dynarray_t zone_skip_t;

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
