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

#include "libknot/zone/zone.h"
#include "knot/zone/zone-load.h"
#include "knot/common.h"
#include "libknot/rrset.h"
#include "libknot/util/descriptor.h"
#include "zcompile/zcompile.h"

#ifdef TEST_WITH_LDNS
#include "ldns/ldns.h"
#endif

static int zoneparser_tests_count(int argc, char *argv[]);
static int zoneparser_tests_run(int argc, char *argv[]);

/*
 * Unit API.
 */
unit_api zoneparser_tests_api = {
	"Zoneparser",
	&zoneparser_tests_count,
	&zoneparser_tests_run
};

#ifdef TEST_WITH_LDNS
/*
 *  Unit implementation.
 */static int compare_wires_simple_zp(uint8_t *wire1,
				      uint8_t *wire2, uint count)
{
	int i = 0;
	while (i < count &&
	       wire1[i] == wire2[i]) {
		i++;
	}
	return (!(count == i));
}

/* compares only one rdata */
static int compare_rr_rdata_silent(knot_rdata_t *rdata, ldns_rr *rr,
				   uint16_t type)
{
	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(type);
	for (int i = 0; i < rdata->count; i++) {
		/* TODO check for ldns "descriptors" as well */
		if (desc->wireformat[i] == KNOT_RDATA_WF_COMPRESSED_DNAME ||
		    desc->wireformat[i] == KNOT_RDATA_WF_LITERAL_DNAME ||
		    desc->wireformat[i] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME) {
			assert(ldns_rr_rdf(rr, i));
			if (rdata->items[i].dname->size !=
			    ldns_rdf_size(ldns_rr_rdf(rr, i))) {
				return 1;
			}
			if (compare_wires_simple_zp(rdata->items[i].dname->name,
				ldns_rdf_data(ldns_rr_rdf(rr, i)),
				rdata->items[i].dname->size) != 0) {
				return 1;
			}
		} else {
			if (ldns_rr_rdf(rr, i) == NULL &&
			    rdata->items[i].raw_data[0] != 0) {
				return 1;
			} else {
				continue;
			}
			if (rdata->items[i].raw_data[0] !=
			    ldns_rdf_size(ldns_rr_rdf(rr, i))) {

				/* ldns stores the size including the
				 * length, dnslib does not */
				if (abs(rdata->items[i].raw_data[0] -
				    ldns_rdf_size(ldns_rr_rdf(rr, i))) != 1) {
					return 1;
				}
			}
			if (compare_wires_simple_zp((uint8_t *)
				(rdata->items[i].raw_data + 1),
				ldns_rdf_data(ldns_rr_rdf(rr, i)),
				rdata->items[i].raw_data[0]) != 0) {
				return 1;
			}
		}
	}
	return 0;
}

static int compare_rrset_w_ldns_rrset(const knot_rrset_t *rrset,
				      ldns_rr_list *rrs,
				      char check_rdata, char verbose)
{
	/* We should have only one rrset from ldns, although it is
	 * represented as rr_list ... */

	/* TODO errors */

	assert(rrs);
	assert(rrset);

	ldns_rr_list_sort(rrs);

	/* compare headers */

	ldns_rr *rr = ldns_rr_list_rr(rrs, 0);

	if (rrset->owner->size != ldns_rdf_size(ldns_rr_owner(rr))) {
		diag("RRSet owner names differ in length");
		if (!verbose) {
			return 1;
		}
		diag("ldns: %d, dnslib: %d", ldns_rdf_size(ldns_rr_owner(rr)),
		     rrset->owner->size);
		diag("%s", knot_dname_to_str(rrset->owner));
		diag("%s", ldns_rdf_data(ldns_rr_owner(rr)));
		return 1;
	}

	if (compare_wires_simple_zp(rrset->owner->name,
				   ldns_rdf_data(ldns_rr_owner(rr)),
				   rrset->owner->size) != 0) {
		diag("RRSet owner wireformats differ");
		return 1;
	}

	if (rrset->type != ldns_rr_get_type(rr)) {
		diag("RRset types differ");
		if (!verbose) {
			return 1;
		}
		diag("Dnslib type: %d Ldns type: %d", rrset->type,
		     ldns_rr_get_type(rr));
		return 1;
	}

	if (rrset->rclass != ldns_rr_get_class(rr)) {
		diag("RRset classes differ");
		return 1;
	}

	if (rrset->ttl != ldns_rr_ttl(rr)) {
		diag("RRset TTLs differ");
		if (!verbose) {
			return 1;
		}
		diag("dnslib: %d ldns: %d", rrset->ttl, ldns_rr_ttl(rr));
		return 1;
	}

	if (!check_rdata) {
		return 0;
	}

	/* compare rdatas */

	/* sort dnslib rdata */

	knot_rdata_t *tmp_rdata = rrset->rdata;

	rr = ldns_rr_list_pop_rr(rrs);

	char found;

	while (rr != NULL) {
		found = 0;
		tmp_rdata = rrset->rdata;
		while (!found &&
		       tmp_rdata->next != rrset->rdata) {
			if (compare_rr_rdata_silent(tmp_rdata, rr,
						    rrset->type) == 0) {
				found = 1;
			}
			tmp_rdata = tmp_rdata->next;
		}

		if (!found &&
		    compare_rr_rdata_silent(tmp_rdata, rr, rrset->type) == 0) {
			found = 1;
		}

		/* remove the found rdata from list */
		if (!found) {
			diag("RRsets rdata differ");
			return 1;
		}
		ldns_rr_free(rr);

		rr = ldns_rr_list_pop_rr(rrs);
	}

	return 0;
}

int compare_zones(knot_zone_contents_t *zone,
                  ldns_rr_list *ldns_list, char verbose)
{
	/* TODO currently test fail when encountering first error -
	 * it should finish going through the zone */
	knot_rrset_t *tmp_rrset = NULL;

	knot_dname_t *tmp_dname = NULL;

	knot_node_t *node = NULL;

	ldns_rr_list *ldns_rrset = ldns_rr_list_pop_rrset(ldns_list);

	if (ldns_rrset == NULL) {
		diag("Error: empty node");
		return 1;
	}

	ldns_rr *rr = NULL;

	/*
	 * Following cycle works like this: First, we get RR from ldns rrset,
	 * then we search for the node containing the rrset, then we get the
	 * rrset, which is then compared with whole ldns rrset.
	 */

	/* ldns_rr_list_pop_rrset should pop the first rrset */
	while (ldns_rrset != NULL) {
		rr = ldns_rr_list_rr(ldns_rrset, 0);
		tmp_dname =
		knot_dname_new_from_wire(ldns_rdf_data(ldns_rr_owner(rr)),
					   ldns_rdf_size(ldns_rr_owner(rr)),
					   NULL);

		node = knot_zone_contents_get_node(zone, tmp_dname);

		if (node == NULL) {
			node = knot_zone_contents_get_nsec3_node(zone,
			                                         tmp_dname);
		}

		if (node == NULL) {
			diag("Could not find node");
			diag("%s", knot_dname_to_str(tmp_dname));
			return 1;
		}

		knot_dname_free(&tmp_dname);

		tmp_rrset = knot_node_get_rrset(node,
				ldns_rr_get_type(ldns_rr_list_rr(ldns_rrset,
								 0)));

		if (tmp_rrset == NULL &&
		    (uint)(ldns_rr_get_type(ldns_rr_list_rr(ldns_rrset, 0))) !=
		    (uint)KNOT_RRTYPE_RRSIG) {
			diag("Could not find rrset");
			if (!verbose) {
				return 1;
			}
			ldns_rr_list_print(stdout, ldns_rrset);
			diag("%s", knot_dname_to_str(node->owner));
			return 1;
		} else if ((uint)(ldns_rr_get_type(ldns_rr_list_rr(ldns_rrset,
		                                                  0))) ==
			   (uint)KNOT_RRTYPE_RRSIG) {
			knot_rrset_t *rrsigs = NULL;
			/* read type covered from ldns rrset */
			for (int i = 0; i < ldns_rrset->_rr_count; i++) {
				uint16_t type_covered =
				ldns_rdf_data(ldns_rr_rdf(
					ldns_rr_list_rr(ldns_rrset, i), 0))[1];

				/*
				 * Dnslib stores RRSIGs separately -
				 * we have to find get it from its "parent"
				 * rrset.
				 */

				tmp_rrset = knot_node_get_rrset(node,
								  type_covered);

				if (tmp_rrset == NULL) {
					if (!verbose) {
						return 1;
					}
					diag("following rrset "
					     "could not be found");
					ldns_rr_list_print(stdout, ldns_rrset);
					return 1;
				}

				if (rrsigs == NULL) {
					rrsigs = tmp_rrset->rrsigs;
				} else {
					knot_rrset_merge((void *)&rrsigs,
					(void *)&(tmp_rrset->rrsigs));
				}
			}
			tmp_rrset = rrsigs;
		}

/*		diag("dnslib type: %d", tmp_rrset->type);
		diag("dnslib dname: %s", tmp_rrset->owner->name);

		diag("ldns type: %d",
		     ldns_rr_get_type(ldns_rr_list_rr(ldns_rrset, 0)));
		diag("ldns dname : %s", ldns_rdf_data(ldns_rr_owner(
				ldns_rr_list_rr(ldns_rrset, 0)))); */

//		knot_rrset_dump(tmp_rrset, 1);

		if (compare_rrset_w_ldns_rrset(tmp_rrset, ldns_rrset,
					       1, 0) != 0) {
			diag("RRSets did not match");
//			knot_rrset_dump(tmp_rrset, 1);
			return 1;
		}

		ldns_rr_list_deep_free(ldns_rrset);

		ldns_rrset = ldns_rr_list_pop_rrset(ldns_list);

		if (ldns_rrset == NULL) {
			ldns_rrset = ldns_rr_list_pop_rrset(ldns_list);
		}
	}

	return 0;
}

#endif

static int test_zoneparser_zone_read(const char *origin, const char *filename,
				     const char *outfile)
{
#ifndef TEST_WITH_LDNS
	diag("Zoneparser tests without usage of ldns are not implemented");
	return 0;
#endif

#ifdef TEST_WITH_LDNS
	/* Calls zcompile. */
	parser = zparser_create();
	int ret = zone_read(origin, filename, outfile, 0);
	if (ret != 0) {
		diag("Could not load zone from file: %s", filename);
		return 0;
	}

	knot_zone_t *dnsl_zone = NULL;
	zloader_t *loader = NULL;
	if (knot_zload_open(&loader, outfile) != 0) {
		diag("Could not create zone loader.\n");
		return 0;
	}
	dnsl_zone = knot_zload_load(loader);
	remove(outfile);
	if (!dnsl_zone) {
		diag("Could not load dumped zone.\n");
		return 0;
	}

	ldns_zone *ldns_zone = NULL;
	FILE *f = fopen(filename, "r");
	if (ldns_zone_new_frm_fp(&ldns_zone, f, NULL,
				  0, LDNS_RR_CLASS_IN) != LDNS_STATUS_OK) {
		diag("Could not load zone from file: %s (ldns)", filename);
		return 0;
	}

//	ldns_zone_sort(ldns_zone);

	/*
	 * LDNS stores SOA record independently - create a list with all
	 * records in it.
	 */

	ldns_rr_list *ldns_list = ldns_zone_rrs(ldns_zone);

	ldns_rr_list_push_rr(ldns_list, ldns_zone_soa(ldns_zone));

	if (compare_zones(dnsl_zone->contents, ldns_list, 0) != 0) {
		return 0;
	}

	knot_zone_deep_free(&dnsl_zone, 0);
	ldns_zone_free(ldns_zone);
	fclose(f);
	return 1;
#endif
}

static const int ZONEPARSER_TEST_COUNT = 1;

/*! API: return number of tests. */
static int zoneparser_tests_count(int argc, char *argv[])
{
	return ZONEPARSER_TEST_COUNT;
}

/*! API: run tests. */
static int zoneparser_tests_run(int argc, char *argv[])
{
	if (argc == 3) {
		ok(test_zoneparser_zone_read(argv[1], argv[2],
					     "foo_test_zone"),
					     "zoneparser: read (%s)",
		   argv[2]);
	} else {
		diag("Wrong parameters\n usage: "
		     "knot-zcompile-unittests origin zonefile");
		return 0;
	}
	return 1;
}
