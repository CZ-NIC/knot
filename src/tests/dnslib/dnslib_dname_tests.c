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
enum { TEST_DOMAINS_OK = 6 };

enum { TEST_DOMAINS_BAD = 2 };

enum { TEST_LABELS = 6 };

static dnslib_node_t *NODE_ADDRESS = (dnslib_node_t *)0xDEADBEEF;

struct test_domain {
	char *str;
	char *wire;
	uint size;
};

/* \warning Do not change the order in those, if you want to test 
    some other feature with new dname, add it at the end of these arrays. */
static const struct test_domain
		test_domains_ok[TEST_DOMAINS_OK] = {
	{ "abc.test.domain.com.", "\3abc\4test\6domain\3com", 21 },
	{ "some.test.domain.com.", "\4some\4test\6domain\3com", 22 },
	{ "xyz.test.domain.com.", "\3xyz\4test\6domain\3com", 21 },
	{ "some.test.domain.com.", "\4some\4test\6domain\3com", 22 },
	{ "test.domain.com.", "\4test\6domain\3com", 17 },
	{ ".", "\0", 1 }
};

static const struct test_domain // non fqdn, these are not labels per se
		test_labels[TEST_LABELS] = { // sizes are strlen()s here
			{"www", NULL, 3},
			{"example", NULL, 7},
			{"com", NULL, 3},
			{"www.example.com", NULL, 15},
			{"some", NULL, 4},
			{"example.com", NULL, 11}
		};

static const struct test_domain
		test_domains_bad[TEST_DOMAINS_BAD] = {
	{ NULL, "\2ex\3com", 8 },
	{ "ex.com.", NULL, 0 },
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

static int check_domain_name(const dnslib_dname_t *dname, int i)
{
	int errors = 0;

	if (dname == NULL) {
		diag("Domain name not created!");
		return 1;
	}

	// check size
	if (dnslib_dname_size(dname) != test_domains_ok[i].size) {
		diag("Bad size of the created domain name: %u (should be %u).",
		     dnslib_dname_size(dname), test_domains_ok[i].size);
		++errors;
	}
	// check wire format
	uint size = dnslib_dname_size(dname);
	if (strncmp((char *)dnslib_dname_name(dname), 
		    test_domains_ok[i].wire, size) != 0) {
		diag("The wire format of the created domain name is wrong:"
		     " '%.*s' (should be '%.*s').", 
		     size, dnslib_dname_name(dname),
		     size, test_domains_ok[i].wire);
		++errors;
	}
	// check node
	if (dnslib_dname_node(dname) != NODE_ADDRESS) {
		diag("Node pointer in the created domain name is wrong: %p"
		     " (should be %p)",
		     dnslib_dname_node(dname), NODE_ADDRESS);
		++errors;
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
		dname = dnslib_dname_new_from_str(test_domains_ok[i].str,
		          strlen(test_domains_ok[i].str), NODE_ADDRESS);
		errors += check_domain_name(dname, i);
		dnslib_dname_free(&dname);
	}

	return (errors == 0);
}

static int check_label(dnslib_dname_t *dname, int i)
{
	int errors = 0;
	if (dname->size != test_labels[i].size + 1) {
		diag("size of created label is wrong: should be %d is %d",
		     test_labels[i].size + 1 , dname->size);
		errors++;
	}

	char *tmp = dnslib_dname_to_str(dname);

	if (strcmp(test_labels[i].str, tmp) != 0) {
		diag("created label is wrong: should be: %s is %s",
		     test_labels[i].str, tmp);
		errors++;
	}

	free(tmp);

	return errors;
}

/* \todo possibly rename */
static int test_dname_create_from_label()
{
	int errors = 0;
	dnslib_dname_t *dname = NULL;

	for (int i = 0; i < TEST_LABELS; ++i) {
		dname = dnslib_dname_new_from_str(test_labels[i].str,
		          strlen(test_labels[i].str), NULL);
		errors += check_label(dname, i);
		dnslib_dname_free(&dname);
	}

	return (errors == 0);
}

static int test_dname_cat()
{
	int errors = 0;

	dnslib_dname_t *d1, *d2, *d3;

	d1 = dnslib_dname_new_from_str(test_labels[0].str, 
	                               strlen(test_labels[0].str), NULL);
	d2 = dnslib_dname_new_from_str(test_labels[1].str, 
                        	       strlen(test_labels[1].str), NULL);
	d3 = dnslib_dname_new_from_str(test_labels[2].str, 
	                               strlen(test_labels[2].str), NULL);

	dnslib_dname_cat(d1, d2);
	dnslib_dname_cat(d1, d3);

	errors += check_label(d1, 3);

	dnslib_dname_free(&d1);
	dnslib_dname_free(&d2);
	dnslib_dname_free(&d3);

	d1 = dnslib_dname_new_from_str(test_labels[4].str, 
	                               strlen(test_labels[4].str),
				       NODE_ADDRESS);

	d2 = dnslib_dname_new_from_str(test_domains_ok[4].str,
	                               strlen(test_domains_ok[4].str),
				       NODE_ADDRESS);

	dnslib_dname_cat(d1, d2);

	errors += check_domain_name(d1, 1);

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

	errors += check_domain_name(chopped, 4);

	dnslib_dname_free(&d1);
	dnslib_dname_free(&chopped);

	d1 = dnslib_dname_new_from_str(test_labels[3].str,
	                               strlen(test_labels[3].str),
				       NODE_ADDRESS);

	chopped = dnslib_dname_left_chop(d1);

	errors += check_label(chopped, 5);

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
		errors += check_domain_name(dname, i);
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

	for (int i = 0; i < TEST_LABELS && !errors; ++i) {
		dname = dnslib_dname_new_from_str(test_labels[i].str,
		          strlen(test_labels[i].str), NULL);
		errors += dnslib_dname_is_fqdn(dname);
		dnslib_dname_free(&dname);
	}

	return (errors == 0);
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

static const int DNSLIB_DNAME_TEST_COUNT = 11;

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
	int res_create = 0,
	    res_str = 0,
	    res_wire = 0;


	res_create = test_dname_create();
	ok(res_create, "dname: create empty");

	skip(!res_create, 9);

	todo();

	ok(test_dname_delete(), "dname: delete");

	endtodo;

	ok((res_str = test_dname_create_from_str()),
	   "dname: create from str");
	ok((res_wire = test_dname_create_from_wire()),
	   "dname: create from wire");

	skip(!res_str || !res_wire, 1);

	ok(test_dname_to_str(), "dname: convert to str");

	lives_ok(test_faulty_data(); , "dname: faulty data test");

	endskip;	/* !res_str || !res_wire */

	ok(test_dname_compare(), "dname: compare");

	ok(test_dname_create_from_label(), "dname: create label");

	ok(test_dname_cat(), "dname: cat");

	ok(test_dname_is_fqdn(), "dname: fqdn");

	ok(test_dname_left_chop(), "dname: left chop");

	endskip;	/* !res_create */

	return 0;
}
