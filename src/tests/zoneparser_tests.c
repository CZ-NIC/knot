#include "tap_unit.h"
#ifdef TEST_WITH_LDNS
#include "ldns/ldns.h"
#endif

#include "zone.h"
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

void compare_zones(dnslib_node_t *node, void *data)
{
	ldns_rr_list *ldns_list = (ldns_rr_list *)data;

	skip_list_t *list = node->rrsets;

	if (list == NULL) {
		status = 0;
		return;
	}

	/* \note ldns_rr_list_pop_rrset should pop the first rrset */
}

static int compare_dnslib_zone_ldns_zone(dnslib_zone_t *dnsl_zone,
					 ldns_zone *ldns_zone)
{
	ldns_zone_sort(ldns_zone);

	ldns_rr_list *ldns_list = ldns_zone_rrs(ldns_zone);

	dnslib_zone_tree_apply_inorder(dnsl_zone, compare_zones,
				       (void *)ldns_list);
}

static int test_zoneparser_zone_read(const char *origin, const char *filename,
				     const char *outfile)
{
#ifndef TEST_WITH_LDNS
	diag("Zoneparser tests without usage of ldns are not implemented");
	return 1;
#endif

#ifdef TEST_WITH_LDNS
	dnslib_zone_t *dnsl_zone = zone_read(origin, filename, outfile);
	if (dnsl_zone == NULL) {
		diag("Could not load zone from file: %s", filename);
		return 0;
	}

	FILE *f = fopen(filename, "r");

	ldns_zone *ldns_zone = NULL;

	if (ldns_zone_new_from_fp(&ldns_zone, f, NULL,
				  0, LDNS_RR_CLASS_IN) != LDNS_STATUS_OK) {
		diag("Could not load zone from file: %s (ldns)", filename);
		return 0;
	}

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

        return 1;
}
