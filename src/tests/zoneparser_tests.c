#include "tap_unit.h"
#ifdef TEST_WITH_LDNS
#include "ldns/ldns.h"
#endif

#include "zone.h"
#include "zone-load.h"
#include "rrset.h"
#include "zoneparser.h"

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

/*
 *  Unit implementation.
 */

static int status = 0;

static int compare_rrset_w_ldns_rrset(const dnslib_rrset_t *rrset,
				      ldns_rr_list *rrs,
				      char check_rdata)
{
	/* We should have only one rrset from ldns, although it is
	 * represented as rr_list ... */

	/* TODO errors */

	assert(rrs);
	assert(rrset);

	/* compare headers */

	ldns_rr *rr = ldns_rr_list_rr(rrs, 0);

	if (rrset->owner->size != ldns_rdf_size(ldns_rr_owner(rr))) {
		diag("RRSet owner names differ in length");
		diag("ldns: %d, dnslib: %d", ldns_rdf_size(ldns_rr_owner(rr)),
		     rrset->owner->size);
		diag("%s", dnslib_dname_to_str(rrset->owner));
		diag("%s", ldns_rdf_data(ldns_rr_owner(rr)));
		return 1;
	}

	if (compare_wires_simple(rrset->owner->name,
				 ldns_rdf_data(ldns_rr_owner(rr)),
				 rrset->owner->size) != 0) {
		diag("RRSet owner wireformats differ");
		return 1;
	}

	if (rrset->type != ldns_rr_get_type(rr)) {
		diag("RRset types differ");
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
		diag("dnslib: %d ldns: %d", rrset->ttl, ldns_rr_ttl(rr));
		return 1;
	}

	/* compare rdatas */

//	dnslib_rdata_t *tmp_rdata = rrset->rdata;

//	int i = 0;

//	while (tmp_rdata->next != rrset->rdata) {
//		rr = ldns_rr_list_rr(rr_set, i);
//		/* TODO use this in the other cases as
//		 * well, it's better than pop */
//		if (rr == NULL) {
//			diag("ldns rrset has more rdata entries"
//			     "than the one from dnslib");
//			return 1;
//		}

//		if (compare_rr_rdata(tmp_rdata, rr, rrset->type) != 0) {
//			diag("Rdata differ");
//			return 1;
//		}

//		tmp_rdata = tmp_rdata->next;
//		i++;
//	}

//	/* TODO double check the indexing */
//	rr = ldns_rr_list_rr(rr_set, i);
//	if (rr == NULL) {
//		diag("ldns rrset has more rdata entries"
//		     "than the one from dnslib");
//		return 1;
//	}

//	if (compare_rr_rdata(tmp_rdata, rr, rrset->type) != 0) {
//		diag("Rdata differ");
//		return 1;
//	}

	if (check_rdata) {
		if (compare_rr_rdata(rrset->rdata, rr, rrset->type) != 0) {
			diag("Rdata differ");
			return 1;
		}
	}

	return 0;
}

void compare_zones(dnslib_node_t *node, void *data)
{
	/* maybe put status > 0 check here */
	ldns_rr_list *ldns_list = (ldns_rr_list *)data;


	dnslib_rrset_t *tmp_rrset = NULL;

	const skip_node_t *skip_node = skip_first(node->rrsets);

	if (skip_node == NULL) {
		diag("Error: empty node -> owner: %s",
		     dnslib_dname_to_str(node->owner));
		return;
	}

	ldns_rr_list *ldns_rrset = ldns_rr_list_pop_rrset(ldns_list);

	if (ldns_rrset == NULL) {
		diag("Error: empty node");
		return;
	}

	/* \note ldns_rr_list_pop_rrset should pop the first rrset */
	while (skip_node != NULL) {

		if (ldns_rrset == NULL) {
			diag("Nodes contain different count of rrsets");
			status++;
			return;
		}

//		tmp_rrset = (dnslib_rrset_t *)skip_node->value;
		tmp_rrset = dnslib_node_get_rrset(node,
				ldns_rr_get_type(ldns_rr_list_rr(ldns_rrset,
								 0)));

		if (tmp_rrset == NULL) {
			status++;
			return;
		}

/*		diag("dnslib type: %d", tmp_rrset->type);
		diag("dnslib dname: %s", tmp_rrset->owner->name);

		diag("ldns type: %d",
		     ldns_rr_get_type(ldns_rr_list_rr(ldns_rrset, 0)));
		diag("ldns dname : %s", ldns_rdf_data(ldns_rr_owner(
				ldns_rr_list_rr(ldns_rrset, 0)))); */

		if (compare_rrset_w_ldns_rrset(tmp_rrset, ldns_rrset, 1) != 0) {
			diag("RRSets did not match");
			status++;
			diag("dnslib: %s", tmp_rrset->owner->name);
			diag("ldns: %s", ldns_rdf_data(ldns_rr_owner(
				ldns_rr_list_rr(ldns_rrset, 0))));
		} else {
			diag("I'll be damned, it was ok");
		}

		skip_node = skip_next(skip_node);
		if (skip_node != NULL) {
			ldns_rrset = ldns_rr_list_pop_rrset(ldns_list);
		}
	}
}

static int compare_dnslib_zone_ldns_zone(dnslib_zone_t *dnsl_zone,
					 ldns_zone *ldns_zone)
{
	ldns_rr_list *ldns_list = ldns_zone_rrs(ldns_zone);

	ldns_rr_list_push_rr(ldns_list, ldns_zone_soa(ldns_zone));

	ldns_rr_list_sort(ldns_list);

	dnslib_zone_tree_apply_inorder_reverse(dnsl_zone, compare_zones,
				       (void *)ldns_list);

	return status;
}

static int test_zoneparser_zone_read(const char *origin, const char *filename,
				     const char *outfile)
{
#ifndef TEST_WITH_LDNS
	diag("Zoneparser tests without usage of ldns are not implemented");
	return 1;
#endif

#ifdef TEST_WITH_LDNS
	parser = zparser_create();
	int ret = zone_read(origin, filename, outfile);
	if (ret != 0) {
		diag("Could not load zone from file: %s", filename);
		return 0;
	}

	dnslib_zone_t *dnsl_zone = dnslib_zload_load(outfile);

	if (dnsl_zone == NULL) {
		diag("Could not load parsed zone");
		return 0;
	}

	dnslib_zone_dump(dnsl_zone);

	getchar();

	FILE *f = fopen(filename, "r");

	ldns_zone *ldns_zone = NULL;

	if (ldns_zone_new_frm_fp(&ldns_zone, f, NULL,
				  0, LDNS_RR_CLASS_IN) != LDNS_STATUS_OK) {
		diag("Could not load zone from file: %s (ldns)", filename);
		return 0;
	}

	ldns_zone_sort(ldns_zone);

	if (compare_dnslib_zone_ldns_zone(dnsl_zone, ldns_zone) != 0) {
		return 0;
	}

	dnslib_zone_deep_free(&dnsl_zone);

	ldns_zone_deep_free(ldns_zone);

	fclose(f);
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
	ok(test_zoneparser_zone_read("example.com.", "/home/jan/work/cutedns/samples/"
				     "example.com.zone",
				     "foo_zone"));
        return 1;
}
