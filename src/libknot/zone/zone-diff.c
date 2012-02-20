/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/util/error.h"
#include "libknot/util/debug.h"
#include "zone-diff.h"

static int knot_zone_diff_load_soas(const knot_zone_contents_t *zone1,
                                    const knot_zone_contents_t *zone2,
                                    knot_changeset_t *changeset)
{
	if (zone1 == NULL || zone2 == NULL || changeset == NULL) {
		return KNOT_EBADARG;
	}

	const knot_node_t *apex1 = knot_zone_contents_apex(zone1);
	const knot_node_t *apex2 = knot_zone_contents_apex(zone2);
	if (apex1 == NULL || apex2 == NULL) {
		dbg_zonediff_verb("zone_diff: "
		                  "both zones must have apex nodes.\n");
		return KNOT_EBADARG;
	}

	const knot_rrset_t soa_rrset1 = knot_node_rrset(apex1, KNOT_RRTYPE_SOA);
	const knot_rrset_t soa_rrset2 = knot_node_rrset(apex2, KNOT_RRTYPE_SOA);
	if (soa_rrset1 == NULL || soa_rrset2 == NULL) {
		dbg_zonediff_verb("zone_diff: "
		                  "both zones must have apex nodes.\n");
		return KNOT_EBADARG;
	}

	if (knot_rrset_rdata(soa_rrset1) == NULL ||
	    knot_rrset_rdata(soa_rrset2) == NULL) {
		dbg_zonediff_verb("zone_diff: "
		                  "both zones must have apex nodes with SOA "
		                  "RRs.\n");
		return KNOT_EBADARG;
	}

	int64_t soa_serial1 =
		knot_rdata_soa_serial(knot_rrset_rdata(soa_rrset1));

	int64_t soa_serial2 =
		knot_rdata_soa_serial(knot_rrset_rdata(soa_rrset2));

	if (soa_serial1 >= soa_serial2) {
		dbg_zonediff("zone_diff: "
		             "second zone must have higher serial than the "
		             "first one.\n");
		return KNOT_EBADARG;
	}

	assert(changeset);

	changeset->soa_from = soa_rrset1;
	changeset->soa_to = soa_rrset2;

	return KNOT_EOK;
}

static int knot_zone_diff_rdata...

static int knot_zone_diff_rrset...

static void knot_zone_diff_node...

knot_changeset_t *knot_zone_diff(const knot_zone_contents_t *zone1,
                                 const knot_zone_contents_t *zone2)
{
	if (zone1 == NULL || zone2 == NULL) {
		dbg_zonediff_verb("zone_diff: NULL argument(s).\n");
		return KNOT_EBADARG;
	}

	/* Create changeset structure. */
	knot_changeset_t *changeset = malloc(sizeof(knot_changeset_t));
	if (changeset == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Settle SOAs first. */
	int ret = knot_zone_diff_load_soas(zone1, zone2, changeset);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: loas_SOAs failed with error: %s\n",
		             knot_strerror(ret));
		return ret;
	}

	/* Traverse one tree, compare every node, each rrset with its rdata. */
	knot_zone_contents...

	/* Do the same for NSEC3 nodes. */
	knot_zone_contents...

	return KNOT_EOK;
}

