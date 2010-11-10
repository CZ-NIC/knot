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
enum { TEST_DOMAINS = 1 };

static dnslib_node_t *NODE_ADDRESS = (dnslib_node_t *)0xDEADBEEF;

struct test_domain {
	char *str;
	char *wire;
	uint size;
};

static const struct test_domain
		test_domains[TEST_DOMAINS] = {
	{ "some.test.domain.com.", "\4some\4test\6domain\3com", 22 }
};

/*!
 * \brief Tests dnslib_dname_new().
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
		diag("Pointer to the structure not set to NULL when deallocating!");
		return 0;
	}
	return 1;
}

/*!
 * \brief Tests dnslib_dname_free().
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_dname_delete() {
	// how to test this??
	return 0;
}

static int check_domain_name( const dnslib_dname_t *dname, int i )
{
	int errors = 0;

	if (dname == NULL) {
		diag("Domain name not created!");
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
	if (strncmp((char *)dnslib_dname_name(dname), test_domains[i].wire, size)
		!= 0) {
		diag("The wire format of the created domain name is wrong: '%.*s'"
			 " (should be '%.*s').", size, dnslib_dname_name(dname),
			 size, test_domains[i].wire);
		++errors;
	}
	// check node
	if (dnslib_dname_node(dname) != NODE_ADDRESS) {
		diag("Node pointer in the created domain name is wrong: %p"
			 " (should be %p)", dnslib_dname_node(dname), NODE_ADDRESS);
		++errors;
	}

	return errors;
}

/*!
 * \brief Tests dnslib_dname_new_from_str().
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_dname_create_from_str()
{
	int errors = 0;
	dnslib_dname_t *dname = NULL;

	for (int i = 0; i < TEST_DOMAINS && errors == 0; ++i) {
		dname = dnslib_dname_new_from_str(test_domains[i].str,
									strlen(test_domains[i].str), NODE_ADDRESS);
		errors += check_domain_name(dname, i);
		dnslib_dname_free(&dname);
	}

	return (errors == 0);
}

/*!
 * \brief Tests dnslib_dname_new_from_wire().
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_dname_create_from_wire()
{
	int errors = 0;
	dnslib_dname_t *dname = NULL;

	for (int i = 0; i < TEST_DOMAINS && errors == 0; ++i) {
		assert(strlen(test_domains[i].wire) + 1 == test_domains[i].size);
		dname = dnslib_dname_new_from_wire(
				(uint8_t *)test_domains[i].wire, test_domains[i].size,
				NODE_ADDRESS);
		errors += check_domain_name(dname, i);
		dnslib_dname_free(&dname);
	}

	return (errors == 0);
}

/*!
 * \brief Tests dnslib_dname_to_str().
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_dname_to_str()
{
	int errors = 0;
	dnslib_dname_t *dname = NULL;

	for (int i = 0; i < TEST_DOMAINS && errors == 0; ++i) {
		dname = dnslib_dname_new_from_wire(
				(uint8_t *)test_domains[i].wire, test_domains[i].size,
				NODE_ADDRESS);
		char *name_str = dnslib_dname_to_str(dname);
		if (strcmp(name_str, test_domains[i].str) != 0) {
			diag("Presentation format of domain name wrong: %s (should be %s)",
				 name_str, test_domains[i].str);
			++errors;
		}
		free(name_str);
		dnslib_dname_free(&dname);
	}

	return (errors == 0);
}

static const int DNSLIB_DNAME_TEST_COUNT = 5;

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

	skip(!res_create, 4);

	todo();

	ok(test_dname_delete(), "dname: delete");

	endtodo;

	ok((res_str = test_dname_create_from_str()), "dname: create from str");
	ok((res_wire = test_dname_create_from_wire()),
	   "dname: create from wire");

	skip(!res_str || !res_wire, 1);

	ok(test_dname_to_str(), "dname: convert to str");

	endskip;	/* !res_str || !res_wire */

	endskip;	/* !res_create */

	return 0;
}
