#include <string.h>
#include <assert.h>

#include "tap_unit.h"

#include "common.h"
#include "dname.h"
#include "node.h"

static int dnslib_dname_tests_count(int argc, char *argv[]);
static int dnslib_dname_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dnslib_dname_tests_api = {
	"DNS library - dname",        //! Unit name
	&dnslib_dname_tests_count,  //! Count scheduled tests
	&dnslib_dname_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

// C will not accept const int in other const definition
enum { TEST_DOMAINS_OK = 7 };

enum { TEST_DOMAINS_BAD = 3 };

enum { TEST_DOMAINS_NON_FQDN = 6 };

static dnslib_node_t *NODE_ADDRESS = (dnslib_node_t *)0xDEADBEEF;

struct test_domain {
	char *str;
	char *wire;
	uint size;
	char *labels;
	short label_count;
};

/*! \warning Do not change the order in those, if you want to test some other
 *           feature with new dname, add it at the end of these arrays.
 */
static const struct test_domain
		test_domains_ok[TEST_DOMAINS_OK] = {
	{ "abc.test.domain.com.", "\3abc\4test\6domain\3com", 21,
	  "\x0\x4\x9\x10", 4 },
	{ "some.test.domain.com.", "\4some\4test\6domain\3com", 22,
	  "\x0\x5\xA\x11", 4 },
	{ "xyz.test.domain.com.", "\3xyz\4test\6domain\3com", 21,
	  "\x0\x4\x9\x10", 4 },
	{ "some.test.domain.com.", "\4some\4test\6domain\3com", 22,
	  "\x0\x5\xA\x11", 4 },
	{ "test.domain.com.", "\4test\6domain\3com", 17,
	  "\x0\x5\xC", 3 },
	{ ".", "\0", 1, "", 0 },
	{ "www.example.com.", "\3www\7example\3com", 17, "\x0\x4\xC", 3}
};

static const struct test_domain // sizes are strlen()s here
	test_domains_non_fqdn[TEST_DOMAINS_NON_FQDN] = {
		{ "www", "\3www", 4, "\x0", 1 },
		{ "example", "\7example", 8, "\x0", 1 },
		{ "com", "\3com", 4, "\x0", 1 },
		{ "www.example.com", "\3www\7example\3com", 16, "\x0\x4\xC",
		  3 },
		{ "some", "\4some", 5, "\x0", 1 },
		{ "example.com", "\7example\3com", 12, "\x0\x8", 2 }
	};

static const struct test_domain
		test_domains_bad[TEST_DOMAINS_BAD] = {
	{ NULL, "\x2ex\x3com", 0, "", 0 },
	{ "ex.com.", NULL, 0, "", 0 },
	{ "ex.com.\x5", "\x3ex\x3com\x0\x5", 10, "", 0 }
};


/*!
 * \brief Tests dnslib_dname_new().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_dname_create()
{
	dnslib_dname_t *dname = dnslib_dname_new();
	if (dname == NULL
	    || dnslib_dname_name(dname) != NULL
	    || dnslib_dname_size(dname) != 0
	    || dnslib_dname_node(dname) != NULL) {
		diag("New domain name not initialized properly!");
		return 0;
	}
	dnslib_dname_free(&dname);
	if (dname != NULL) {
		diag("Pointer to the structure not set to"
		     "NULL when deallocating!");
		return 0;
	}
	return 1;
}

/*!
 * \brief Tests dnslib_dname_free().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_dname_delete()
{
	// how to test this??
	return 0;
}

static int check_domain_name(const dnslib_dname_t *dname,
                             const struct test_domain *test_domains, int i,
                             int check_node)
{
	int errors = 0;

	if (dname == NULL) {
		diag("Domain name #%d not created!", i);
		return 1;
	}

	// check size
	if (dnslib_dname_size(dname) != test_domains[i].size) {
		diag("Bad size of the created domain name: %u (should be %u).",
		     dnslib_dname_size(dname), test_domains[i].size);
		++errors;
	}
	// check wire format
	uint size = dnslib_dname_size(dname);
	if (strncmp((char *)dnslib_dname_name(dname), 
		    test_domains[i].wire, size) != 0) {
		diag("The wire format of the created domain name is wrong:"
		     " '%.*s' (should be '%.*s').", 
		     size, dnslib_dname_name(dname),
		     size, test_domains[i].wire);
		++errors;
	}
	// check labels
	if (test_domains[i].label_count != dname->label_count) {
		diag("Label count of the created domain name is wrong:"
		     " %d (should be %d)\n", dname->label_count,
		     test_domains[i].label_count);
		++errors;
	}
	if (strncmp((char *)dname->labels, test_domains[i].labels,
		    test_domains[i].label_count) != 0) {
		diag("Label offsets of the created domain name are wrong.\n");
		++errors;
	} else {
		note("Labels OK");
	}

	if (check_node) {
		if (dnslib_dname_node(dname) != NODE_ADDRESS) {
			diag("Node pointer in the created domain name is wrong:"
			     "%p (should be %p)",
			     dnslib_dname_node(dname), NODE_ADDRESS);
			++errors;
		}
	}

	return errors;
}

/*!
 * \brief Tests dnslib_dname_new_from_str().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_dname_create_from_str()
{
	int errors = 0;
	dnslib_dname_t *dname = NULL;

	for (int i = 0; i < TEST_DOMAINS_OK && errors == 0; ++i) {
		//note("testing domain: %s", test_domains_ok[i].str);
		dname = dnslib_dname_new_from_str(test_domains_ok[i].str,
		          strlen(test_domains_ok[i].str), NODE_ADDRESS);
		errors += check_domain_name(dname, test_domains_ok, i, 1);
		dnslib_dname_free(&dname);
	}

	return (errors == 0);
}

static int test_dname_create_from_str_non_fqdn()
{
	int errors = 0;
	dnslib_dname_t *dname = NULL;

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; ++i) {
		//note("testing domain: %s", test_domains_non_fqdn[i].str);
		dname = dnslib_dname_new_from_str(test_domains_non_fqdn[i].str,
		          strlen(test_domains_non_fqdn[i].str), NULL);
		errors += check_domain_name(dname, test_domains_non_fqdn, i, 0);
		dnslib_dname_free(&dname);
	}

	return (errors == 0);
}

static int test_dname_cat()
{
	int errors = 0;

	dnslib_dname_t *d1, *d2, *d3;

	d1 = dnslib_dname_new_from_str(test_domains_non_fqdn[0].str,
	                            strlen(test_domains_non_fqdn[0].str), NULL);
	d2 = dnslib_dname_new_from_str(test_domains_non_fqdn[1].str,
	                            strlen(test_domains_non_fqdn[1].str), NULL);
	d3 = dnslib_dname_new_from_str(test_domains_non_fqdn[2].str,
	                            strlen(test_domains_non_fqdn[2].str), NULL);

	dnslib_dname_cat(d1, d2);
	dnslib_dname_cat(d1, d3);

	errors += check_domain_name(d1, test_domains_non_fqdn, 3, 0);

	dnslib_dname_free(&d1);
	dnslib_dname_free(&d2);
	dnslib_dname_free(&d3);

	d1 = dnslib_dname_new_from_str(test_domains_non_fqdn[4].str,
	                               strlen(test_domains_non_fqdn[4].str),
	                               NODE_ADDRESS);

	d2 = dnslib_dname_new_from_str(test_domains_ok[4].str,
	                               strlen(test_domains_ok[4].str),
	                               NODE_ADDRESS);

	dnslib_dname_cat(d1, d2);

	errors += check_domain_name(d1, test_domains_ok, 1, 1);

	dnslib_dname_free(&d1);
	dnslib_dname_free(&d2);

	// concatenating with root label
	d1 = dnslib_dname_new_from_str(test_domains_non_fqdn[3].str,
				       strlen(test_domains_non_fqdn[3].str),
				       NODE_ADDRESS);

	d2 = dnslib_dname_new_from_str(test_domains_ok[5].str,
				       strlen(test_domains_ok[5].str),
				       NODE_ADDRESS);

	dnslib_dname_cat(d1, d2);

	errors += check_domain_name(d1, test_domains_ok, 6, 6);

	dnslib_dname_free(&d1);
	dnslib_dname_free(&d2);

	return (errors == 0);
}

static int test_dname_left_chop()
{
	int errors = 0;

	dnslib_dname_t *d1;

	d1 = dnslib_dname_new_from_str(test_domains_ok[1].str,
	                               strlen(test_domains_ok[1].str),
	                               NODE_ADDRESS);

	dnslib_dname_t *chopped;

	chopped = dnslib_dname_left_chop(d1);

	errors += check_domain_name(chopped, test_domains_ok, 4, 0);

	dnslib_dname_free(&d1);
	dnslib_dname_free(&chopped);

	d1 = dnslib_dname_new_from_str(test_domains_non_fqdn[3].str,
	                               strlen(test_domains_non_fqdn[3].str),
	                               NODE_ADDRESS);

	chopped = dnslib_dname_left_chop(d1);

	errors += check_domain_name(chopped, test_domains_non_fqdn, 5, 0);

	dnslib_dname_free(&d1);
	dnslib_dname_free(&chopped);

	return (errors == 0);
}

/*!
 * \brief Tests dnslib_dname_new_from_wire().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_dname_create_from_wire()
{
	int errors = 0;
	dnslib_dname_t *dname = NULL;

	for (int i = 0; i < TEST_DOMAINS_OK && errors == 0; ++i) {
		assert(strlen(test_domains_ok[i].wire) + 1 == 
		       test_domains_ok[i].size);
		dname = dnslib_dname_new_from_wire(
		            (uint8_t *)test_domains_ok[i].wire,
		            test_domains_ok[i].size, NODE_ADDRESS);
		errors += check_domain_name(dname, test_domains_ok, i, 1);
		dnslib_dname_free(&dname);
	}

	return (errors == 0);
}

/*!
 * \brief Tests dnslib_dname_to_str().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_dname_to_str()
{
	int errors = 0;
	dnslib_dname_t *dname = NULL;

	for (int i = 0; i < TEST_DOMAINS_OK && errors == 0; ++i) {
		dname = dnslib_dname_new_from_wire(
		            (uint8_t *)test_domains_ok[i].wire,
		            test_domains_ok[i].size, NODE_ADDRESS);
		char *name_str = dnslib_dname_to_str(dname);
		if (strcmp(name_str, test_domains_ok[i].str) != 0) {
			diag("Presentation format of domain name wrong:"
			     " %s (should be %s)",
			     name_str, test_domains_ok[i].str);
			++errors;
		}
		free(name_str);
		dnslib_dname_free(&dname);
	}

	return (errors == 0);
}

/* called by lives_ok */
static int test_faulty_data()
{
	dnslib_dname_t *dname = NULL;

	for (int i = 0; i < TEST_DOMAINS_BAD; i++) {

		if (test_domains_bad[i].str != NULL) {
			dname = dnslib_dname_new_from_str(
			            test_domains_bad[i].str,
			            strlen(test_domains_bad[i].str),
			            NODE_ADDRESS);
		} else {
			dname = dnslib_dname_new_from_str(
			    test_domains_bad[i].str, 0, NODE_ADDRESS);
		}

		dnslib_dname_free(&dname);

		dname = dnslib_dname_new_from_wire(
		            (uint8_t *)test_domains_bad[i].wire,
		            test_domains_bad[i].size, NODE_ADDRESS);

		dnslib_dname_free(&dname);
	}
	return 1; //did it get here? success
}

static int test_dname_compare()
{
	dnslib_dname_t *dnames[TEST_DOMAINS_OK];

	for (int i = 0; i < TEST_DOMAINS_OK; ++i) {
		dnames[i] = dnslib_dname_new_from_wire(
		                (uint8_t *)test_domains_ok[i].wire,
		                test_domains_ok[i].size, NODE_ADDRESS);
	}

	int errors = 0;
	/* abc < some */
	if (dnslib_dname_compare(dnames[0], dnames[1]) != -1) {
		diag("Dname comparison error");
		errors++;
	}
	/* some == some */
	if (dnslib_dname_compare(dnames[1], dnames[3]) != 0) {
		diag("Dname comparison error");
		errors++;
	}
	/*xyz > some */
	if (dnslib_dname_compare(dnames[2], dnames[1]) != 1) {
		diag("Dname comparison error");
		errors++;
	}

	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
		dnslib_dname_free(&dnames[i]);
	}

	return (errors == 0);
}

static int test_dname_is_fqdn()
{
	int errors = 0;

	dnslib_dname_t *dname;

	for (int i = 0; i < TEST_DOMAINS_OK && !errors; ++i) {
		dname = dnslib_dname_new_from_wire(
		                (uint8_t *)test_domains_ok[i].wire,
		                test_domains_ok[i].size, NODE_ADDRESS);
		errors += !dnslib_dname_is_fqdn(dname);
		dnslib_dname_free(&dname);
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN && !errors; ++i) {
		dname = dnslib_dname_new_from_str(test_domains_non_fqdn[i].str,
		          strlen(test_domains_non_fqdn[i].str), NULL);
		errors += dnslib_dname_is_fqdn(dname);
		dnslib_dname_free(&dname);
	}

	return (errors == 0);
}

static int test_dname_is_subdomain()
{
	int errors = 0;

	dnslib_dname_t *dnames_fqdn[TEST_DOMAINS_OK];
	dnslib_dname_t *dnames_non_fqdn[TEST_DOMAINS_NON_FQDN];

	for (int i = 0; i < TEST_DOMAINS_OK; ++i) {
		dnames_fqdn[i] = dnslib_dname_new_from_wire(
		                (uint8_t *)test_domains_ok[i].wire,
		                test_domains_ok[i].size, NULL);
		assert(dnames_fqdn[i] != NULL);
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; ++i) {
		dnames_non_fqdn[i] = dnslib_dname_new_from_wire(
		                (uint8_t *)test_domains_non_fqdn[i].wire,
		                test_domains_non_fqdn[i].size, NULL);
		assert(dnames_non_fqdn[i] != NULL);
	}

	// fqdn names 0 - 3 should be subdomains of name 4
	dnslib_dname_t *parent = dnames_fqdn[4];
	for (int i = 0; i < 3; ++i) {
		if (!dnslib_dname_is_subdomain(dnames_fqdn[i], parent)) {
			diag("(fqdn 1-%d) "
			     "Name %s was not considered subdomain of %s", i,
			     dnslib_dname_name(dnames_fqdn[i]),
			     dnslib_dname_name(parent));
			++errors;
		}
	}

	// fqdn names 0 - 4 should be subdomains of name 5 (root)
	parent = dnames_fqdn[5];
	for (int i = 0; i < 4; ++i) {
		if (!dnslib_dname_is_subdomain(dnames_fqdn[i], parent)) {
			diag("(fqdn 2-%d) "
			     "Name %s was not considered subdomain of %s", i,
			     dnslib_dname_name(dnames_fqdn[i]),
			     dnslib_dname_name(parent));
			++errors;
		}
	}

	// non-fqdn names 3 and 5 should be subdomains of non-fqdn name 2
	parent = dnames_non_fqdn[2];
	if (!dnslib_dname_is_subdomain(dnames_non_fqdn[3], parent)) {
		diag("(non-fqdn 1) "
		     "Name %.*s was not considered subdomain of %.*s",
		     dnslib_dname_size(dnames_non_fqdn[3]),
		     dnslib_dname_name(dnames_non_fqdn[3]),
		     dnslib_dname_size(parent),
		     dnslib_dname_name(parent));
		++errors;
	}
	if (!dnslib_dname_is_subdomain(dnames_non_fqdn[5], parent)) {
		diag("(non-fqdn 2) "
		     "Name %.*s was not considered subdomain of %.*s",
		     dnslib_dname_size(dnames_non_fqdn[5]),
		     dnslib_dname_name(dnames_non_fqdn[5]),
		     dnslib_dname_size(parent),
		     dnslib_dname_name(parent));
		++errors;
	}

	// non-fqdn name 3 should be subdomain of non-fqdn name 5
	parent = dnames_non_fqdn[5];
	if (!dnslib_dname_is_subdomain(dnames_non_fqdn[3], parent)) {
		diag("(non-fqdn 3) "
		     "Name %.*s was not considered subdomain of %.*s",
		     dnslib_dname_size(dnames_non_fqdn[3]),
		     dnslib_dname_name(dnames_non_fqdn[3]),
		     dnslib_dname_size(parent),
		     dnslib_dname_name(parent));
		++errors;
	}

	// identical names should not be considered subdomains
	if (dnslib_dname_is_subdomain(dnames_fqdn[0], dnames_fqdn[0])) {
		diag("(identical names) "
		     "Name %s was considered subdomain of itself",
		     dnslib_dname_name(dnames_fqdn[0]));
		++errors;
	}
	if (dnslib_dname_is_subdomain(dnames_fqdn[1], dnames_fqdn[3])) {
		diag("(identical names) "
		     "Name %s was considered subdomain of %s",
		     dnslib_dname_name(dnames_fqdn[1]),
		     dnslib_dname_name(dnames_fqdn[3]));
		++errors;
	}

	// fqdn name should not be considered subdomain of non-fqdn name
	if (dnslib_dname_is_subdomain(dnames_fqdn[1], dnames_non_fqdn[2])) {
		diag("(fqdn subdomain of non-fqdn) "
		     "Name %s was considered subdomain of %.*s",
		     dnslib_dname_name(dnames_fqdn[1]),
		     dnslib_dname_size(dnames_non_fqdn[2]),
		     dnslib_dname_name(dnames_non_fqdn[2]));
		++errors;
	}

	// non-fqdn name should not be considered subdomain of fqdn name
	if (dnslib_dname_is_subdomain(dnames_fqdn[1], dnames_non_fqdn[2])) {
		diag("(non-fqdn subdomain of fqdn) "
		     "Name %s was considered subdomain of %.*s",
		     dnslib_dname_name(dnames_fqdn[1]),
		     dnslib_dname_size(dnames_non_fqdn[2]),
		     dnslib_dname_name(dnames_non_fqdn[2]));
		++errors;
	}

	// parent name should not be considered subdomain of its subdomain
	if (dnslib_dname_is_subdomain(dnames_fqdn[4], dnames_fqdn[0])) {
		diag("(ancestor subdomain of name) "
		     "Name %s was considered subdomain of %s",
		     dnslib_dname_name(dnames_fqdn[4]),
		     dnslib_dname_name(dnames_fqdn[0]));
		++errors;
	}

	for (int i = 0; i < TEST_DOMAINS_OK; ++i) {
		dnslib_dname_free(&dnames_fqdn[i]);
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; ++i) {
		dnslib_dname_free(&dnames_non_fqdn[i]);
	}

	return (errors == 0);
}

static int check_wires(const uint8_t *wire1, uint size1,
                         uint8_t *wire2, uint size2)
{
	if (size1 != size2) {
		return 0;
	}

	int i;

	for (i = 0; (i < size1); i++) {
		if (wire1[i] != wire2[i]) {
			return 0;
		}
	}

	return 1;
}

/* \note not to be run separately */
static int test_dname_name(dnslib_dname_t **dnames_fqdn,
                           dnslib_dname_t **dnames_non_fqdn)
{
	assert(dnames_fqdn);
	assert(dnames_non_fqdn);

	int errors = 0;

	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
		const uint8_t *tmp_name;
		tmp_name = dnslib_dname_name(dnames_fqdn[i]);
		if (!check_wires(tmp_name, dnames_fqdn[i]->size,
			        (uint8_t *)test_domains_ok[i].wire,
				test_domains_ok[i].size)) {
			diag("Got bad name value from structure: "
			     "%s, should be: %s",
			     tmp_name, test_domains_ok[i].wire);
			errors++;
		}
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
		const uint8_t *tmp_name;
		tmp_name = dnslib_dname_name(dnames_non_fqdn[i]);
		if (!check_wires(tmp_name, dnames_non_fqdn[i]->size,
			        (uint8_t *)test_domains_non_fqdn[i].wire,
				test_domains_non_fqdn[i].size)) {
			diag("Got bad name value from structure: "
			     "%s, should be: %s",
			     tmp_name, test_domains_non_fqdn[i].wire);
			errors++;
		}
	}

	return errors;
}

/* \note not to be run separately */
static int test_dname_size(dnslib_dname_t **dnames_fqdn,
                           dnslib_dname_t **dnames_non_fqdn)
{
	assert(dnames_fqdn);
	assert(dnames_non_fqdn);

	int errors = 0;

	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
		uint8_t tmp_size;
		if ((tmp_size = dnslib_dname_size(dnames_fqdn[i])) !=
		    test_domains_ok[i].size) {
			diag("Got bad size value from structure: "
			     "%u, should be: %u",
			     tmp_size, test_domains_ok[i].size);
			errors++;
		}
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
		uint8_t tmp_size;
		if ((tmp_size = dnslib_dname_size(dnames_non_fqdn[i])) !=
		    test_domains_non_fqdn[i].size) {
			diag("Got bad size value from structure: "
			     "%u, should be: %u",
			     tmp_size, test_domains_non_fqdn[i].size);
			errors++;
		}
	}

	return errors;
}

/* \note not to be run separately */
static int test_dname_node(dnslib_dname_t **dnames_fqdn,
                           dnslib_dname_t **dnames_non_fqdn)
{
	assert(dnames_fqdn);
	assert(dnames_non_fqdn);

	int errors = 0;

	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
		const dnslib_node_t *tmp_node;
		if ((tmp_node = dnslib_dname_node(dnames_fqdn[i])) !=
		    NODE_ADDRESS) {
			diag("Got bad node value from structure: "
			     "%p, should be: %p",
			     tmp_node, NODE_ADDRESS);
			errors++;
		}
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
		const dnslib_node_t *tmp_node;
		if ((tmp_node = dnslib_dname_node(dnames_non_fqdn[i])) !=
		    NODE_ADDRESS) {
			diag("Got bad node value from structure: "
			     "%s, should be: %s",
			     tmp_node, NODE_ADDRESS);
			errors++;
		}
	}

	return errors;
}

static int test_dname_getters(uint type)
{
	int errors = 0;

	dnslib_dname_t *dnames_fqdn[TEST_DOMAINS_OK];
	dnslib_dname_t *dnames_non_fqdn[TEST_DOMAINS_NON_FQDN];

	for (int i = 0; i < TEST_DOMAINS_OK; i++) {
		dnames_fqdn[i] = dnslib_dname_new_from_wire(
		                (uint8_t *)test_domains_ok[i].wire,
		                test_domains_ok[i].size, NODE_ADDRESS);
		assert(dnames_fqdn[i] != NULL);
	}

	for (int i = 0; i < TEST_DOMAINS_NON_FQDN; i++) {
		dnames_non_fqdn[i] = dnslib_dname_new_from_wire(
		                (uint8_t *)test_domains_non_fqdn[i].wire,
		                test_domains_non_fqdn[i].size, NODE_ADDRESS);
		assert(dnames_non_fqdn[i] != NULL);
	}

	switch (type) {
		case 0: {
			errors += test_dname_name(dnames_fqdn, dnames_non_fqdn);
			break;
		}

		case 1: {
			errors += test_dname_size(dnames_fqdn, dnames_non_fqdn);
			break;
		}

		case 2: {
			errors += test_dname_node(dnames_fqdn, dnames_non_fqdn);
			break;
		}
	} /* switch */
	
	return (errors == 0);
}

static const int DNSLIB_DNAME_TEST_COUNT = 15;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_dname_tests_count(int argc, char *argv[])
{
	return DNSLIB_DNAME_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_dname_tests_run(int argc, char *argv[])
{
	int res = 0,
	    res_str = 0,
	    res_wire = 0,
	    res_str_non_fqdn = 0,
	    res_final = 1;

	res = test_dname_create();
	ok(res, "dname: create empty");
	res_final *= res;

	skip(!res, 12);

	todo();

	ok((res = test_dname_delete()), "dname: delete");
	//res_final *= res;

	endtodo;

	ok((res_str = test_dname_create_from_str()), "dname: create from str");
	ok((res_wire = test_dname_create_from_wire()),
	   "dname: create from wire");
	ok((res_str_non_fqdn = test_dname_create_from_str_non_fqdn()),
	   "dname: create from str non fqdn");
	res_final *= res_str;
	res_final *= res_wire;
	res_final *= res_str_non_fqdn;

	res = test_dname_getters(0);
	ok(res, "dname: name");

	res = test_dname_getters(1);
	ok(res, "dname: size");

	res = test_dname_getters(2);
	ok(res, "dname: node");

	skip(!res_str || !res_wire || !res_str_non_fqdn, 2);

	ok((res = test_dname_to_str()), "dname: convert to str");
	res_final *= res;

	lives_ok(test_faulty_data(); , "dname: faulty data test");

	endskip;  /* !res_str || !res_wire */

	ok((res = test_dname_compare()), "dname: compare");
	res_final *= res;

	ok((res = test_dname_cat()), "dname: cat");
	res_final *= res;

	ok((res = test_dname_is_fqdn()), "dname: fqdn");
	res_final *= res;

	ok((res = test_dname_left_chop()), "dname: left chop");
	res_final *= res;

	ok((res = test_dname_is_subdomain()), "dname: is subdomain");
	res_final *= res;

	endskip;  /* create failed */

	return res_final;
}
