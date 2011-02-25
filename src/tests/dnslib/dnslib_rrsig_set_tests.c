/*!
 * \file dnslib_rrsig_set_tests.c
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * Contains unit tests for RRSIG set (dnslib_rrsig_set_t) and its API.
 *
 * Contains tests for:
 * - RRSIG set API
 */

#include "dnslib/rrsig.h"
#include "dnslib/dname.h"
#include "dnslib/rdata.h"

static int dnslib_rrsig_set_tests_count(int argc, char *argv[]);
static int dnslib_rrsig_set_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dnslib_rrsig_set_tests_api = {
	"DNS library - rrsig_set",        //! Unit name
	&dnslib_rrsig_set_tests_count,  //! Count scheduled tests
	&dnslib_rrsig_set_tests_run     //! Run scheduled tests
};

/*----------------------------------------------------------------------------*/
/*
 *  Unit implementation.
 */

enum { TEST_RRSIG_SETS = 6 };

//void *RRSIG_ADDRESS = (void *)0xDEADBEEF;
//void *RRSIG_FIRST = RRSIG_ADDRESS + 10;

struct test_rrsig_set {
	char *owner;
	uint16_t type;
	uint16_t rclass;
	uint32_t  ttl;
	dnslib_rdata_t *rdata;
};

enum {
	RRS_DNAMES_COUNT = 3,
	RRS_ITEMS_COUNT = 3,
	RRS_RDATA_COUNT = 5,
};

static dnslib_dname_t RRS_DNAMES[RRS_DNAMES_COUNT] =
	{ {(uint8_t *)"\7example\3com", 13, NULL}, //0's at the end are added
          {(uint8_t *)"\2ns1\7example\3com", 17, NULL},
          {(uint8_t *)"\2ns2\7example\3com", 17, NULL} };

/*			   192.168.1.1 */
//static uint8_t adress[4] = {0xc0, 0xa8, 0x01, 0x01};

static dnslib_rdata_item_t RRS_ITEMS[RRS_ITEMS_COUNT] =
	{ {.dname = &RRS_DNAMES[1]},
	  {.dname = &RRS_DNAMES[2]},
          {.raw_data = adress} };

static dnslib_rdata_t RRS_RDATA[RRS_RDATA_COUNT] =
	{ {&RRS_ITEMS[0], 1, &RRS_RDATA[0]},
	  {&RRS_ITEMS[1], 1, &RRS_RDATA[1]}, /* first ns */
	  {&RRS_ITEMS[2], 1, &RRS_RDATA[2]}, /* second ns */
	  {&RRS_ITEMS[1], 1, &RRS_RDATA[4]}, /* both in cyclic list */
	  {&RRS_ITEMS[2], 1, &RRS_RDATA[3]} };

static struct test_rrsig_set test_rrsig_sets[TEST_RRSIG_SETS] = {
	{
		"example.com.",
		2,
		DNSLIB_CLASS_IN,
		3600,
		NULL,
	},
	{
		"example2.com.",
		2,
		DNSLIB_CLASS_IN,
		3600,
		NULL,
	},
	{
		"example3.com.",
		2,
		DNSLIB_CLASS_IN,
		3600,
		NULL,
	},
	{ "example.com.", DNSLIB_RRTYPE_NS, DNSLIB_CLASS_IN,
	  3600, &RRS_RDATA[1] },
	{ "example.com.", DNSLIB_RRTYPE_NS, DNSLIB_CLASS_IN,
	  3600, &RRS_RDATA[2] },
	{ "example.com.", DNSLIB_RRTYPE_NS, DNSLIB_CLASS_IN,
	  3600, &RRS_RDATA[3] },
};

/* fills test_rrsig_sets with random rdata */
static void rrs_create_rdata()
{
	dnslib_rdata_t *r;
	for (int i = 0; i < TEST_RRSIG_SETS - 3; i++) {
		r = dnslib_rdata_new();
		dnslib_rdata_item_t item;
		item.raw_data = RDATA_ITEM_PTR;

		dnslib_rdata_set_item(r, 0, item);

		uint8_t data[DNSLIB_MAX_RDATA_WIRE_SIZE];
		generate_rdata(data, DNSLIB_MAX_RDATA_WIRE_SIZE);

		// from dnslib_rdata_tests.c
		fill_rdata(data, DNSLIB_MAX_RDATA_WIRE_SIZE, 
		           DNSLIB_RRTYPE_RRSIG, r);
		test_rrsig_sets[i].rdata = r;
	}
}

static int check_rrsig_set(const dnslib_rrsig_set_t *rrsig_set, int i,
                       int check_rdata, int check_items)
{
	int errors = 0;

	if (rrsig_set == NULL) {
		diag("RRSet not created!");
		return 1;
	}

	char *owner = dnslib_dname_to_str(rrsig_set->owner);
	if (strcmp(owner, test_rrsig_sets[i].owner) != 0) {
		diag("OWNER domain name wrong: '%s' (should be '%s')",
		     owner, test_rrsig_sets[i].owner);
		++errors;
	}
	free(owner);

	if (rrsig_set->type != test_rrsig_sets[i].type) {
		diag("TYPE wrong: %u (should be: %u)", rrsig_set->type,
		     test_rrsig_sets[i].type);
		++errors;
	}

	if (rrsig_set->rclass != test_rrsig_sets[i].rclass) {
		diag("CLASS wrong: %u (should be: %u)", rrsig_set->rclass,
		     test_rrsig_sets[i].rclass);
		++errors;
	}

	if (rrsig_set->ttl != test_rrsig_sets[i].ttl) {
		diag("TTL wrong: %u (should be: %u)", rrsig_set->ttl,
		     test_rrsig_sets[i].ttl);
		++errors;
	}

	if (check_rdata) {
		dnslib_rdata_t *rdata = rrsig_set->rdata;

		if (rdata == NULL) {
			diag("There are no RDATAs in the RRSet");
			++errors;
		}
		if (rdata != NULL) {
			while (rdata->next != NULL &&
			       rdata->next != rrsig_set->rdata) {
				rdata = rdata->next;
			}
			if (rdata->next == NULL) {
				diag("The list of RDATAs is not cyclical!");
				++errors;
			} else {
				assert(rdata == rrsig_set->rdata);
			}
		}
	}

	if (check_items) {
		dnslib_rrtype_descriptor_t *desc =
			dnslib_rrtype_descriptor_by_type(rrsig_set->type);
		if (dnslib_rdata_compare(rrsig_set->rdata,
			                 test_rrsig_sets[i].rdata,
					 desc->wireformat)) {
			diag("Rdata items do not match.");
			errors++;
		}
	}

	return errors;
}

/*!
 * \brief Tests dnslib_rrsig_set_new().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rrsig_set_create()
{
	int errors = 0;

	for (int i = 0; i < TEST_RRSIG_SETS; ++i) {
		dnslib_dname_t *owner = dnslib_dname_new_from_str(
		                            test_rrsig_sets[i].owner,
		                            strlen(test_rrsig_sets[i].owner),
		                            NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}
		dnslib_rrsig_set_t *rrsig_set = dnslib_rrsig_set_new(owner,
		                                         test_rrsig_sets[i].type,
		                                         test_rrsig_sets[i].rclass,
		                                         test_rrsig_sets[i].ttl);

		errors += check_rrsig_set(rrsig_set, i, 0, 0);

		dnslib_rrsig_set_free(&rrsig_set);
		dnslib_dname_free(&owner);
	}

	//diag("Total errors: %d", errors);

	return (errors == 0);
}

/*!
 * \brief Tests dnslib_rrsig_set_free().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 *
 * \todo How to test this?
 */
static int test_rrsig_set_delete()
{
	return 0;
}

static int test_rrsig_set_rdata()
{
	/* rdata add */
	int errors = 0;
	for (int i = 0; i < TEST_RRSIG_SETS; i++) {
		dnslib_dname_t *owner = dnslib_dname_new_from_str(
		                            test_rrsig_sets[i].owner,
		                            strlen(test_rrsig_sets[i].owner),
		                            NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}
		dnslib_rrsig_set_t *rrsig_set = dnslib_rrsig_set_new(owner,
		                                         test_rrsig_sets[i].type,
		                                         test_rrsig_sets[i].rclass,
		                                         test_rrsig_sets[i].ttl);

		dnslib_rrsig_set_add_rdata(rrsig_set, test_rrsig_sets[i].rdata);

		errors += check_rrsig_set(rrsig_set, i, 1, 0);

		dnslib_rrsig_set_free(&rrsig_set);
		dnslib_dname_free(&owner);
	}

	//test whether adding works properly = keeps order of added elements

	dnslib_rrsig_set_t *rrsig_set = dnslib_rrsig_set_new(NULL, 0, 0, 0);

	dnslib_rdata_t *r;

	dnslib_rdata_item_t *item;

	char *test_strings[10] =
	    { "-2", "9", "2", "10", "1", "5", "8", "4", "6", "7" };

	for (int i = 0; i < 10; i++) {
		r = dnslib_rdata_new();
		item = malloc(sizeof(dnslib_rdata_item_t));
		item->raw_data = (uint8_t *)test_strings[i];
		//following statement creates a copy
		dnslib_rdata_set_items(r, item, 1);
		dnslib_rrsig_set_add_rdata(rrsig_set, r);
		free(item);
	}

	dnslib_rdata_t *tmp = rrsig_set->rdata;

	int i = 0;
	while (tmp->next != rrsig_set->rdata && !errors) {
		if (strcmp(test_strings[i], (char *)tmp->items[0].raw_data)) {
			diag("Adding RDATA error!, is %s should be %s",
			tmp->items[0].raw_data, test_strings[i]);
			errors++;
		}
		i++;
		tmp = tmp->next;
	}

	tmp = rrsig_set->rdata;

	dnslib_rdata_t *next;

	while (tmp->next != rrsig_set->rdata) {
		next = tmp->next;
		dnslib_rdata_free(&tmp);
		tmp = next;
	}

	dnslib_rdata_free(&tmp);

	dnslib_rrsig_set_free(&rrsig_set);

	return (errors == 0);
}

static int test_rrsig_set_merge()
{
	dnslib_rrsig_set_t *merger1;
	dnslib_rrsig_set_t *merger2;

	dnslib_dname_t *owner1 =
		dnslib_dname_new_from_str(test_rrsig_sets[3].owner,
		                          strlen(test_rrsig_sets[3].owner), NULL);
	merger1 = dnslib_rrsig_set_new(owner1, test_rrsig_sets[3].type,
	                           test_rrsig_sets[3].rclass,
				   test_rrsig_sets[3].ttl);

	dnslib_rrsig_set_add_rdata(merger1, test_rrsig_sets[3].rdata);

	dnslib_dname_t *owner2 =
		dnslib_dname_new_from_str(test_rrsig_sets[4].owner,
		                          strlen(test_rrsig_sets[4].owner), NULL);
	merger2 = dnslib_rrsig_set_new(owner2, test_rrsig_sets[4].type,
	                           test_rrsig_sets[4].rclass,
				   test_rrsig_sets[4].ttl);

	dnslib_rrsig_set_add_rdata(merger2, test_rrsig_sets[4].rdata);

	dnslib_rrsig_set_merge((void **)&merger1, (void **)&merger2);

	if (check_rrsig_set(merger1, 5, 0, 1)) {
		diag("Merged rdata are wrongly set.");
		return 0;
	}

	dnslib_dname_free(&owner1);
	dnslib_dname_free(&owner2);
	dnslib_rrsig_set_free(&merger1);
	dnslib_rrsig_set_free(&merger2);

	return 1;
}

static int test_rrsig_set_type(dnslib_rrsig_set_t **rrsig_sets)
{
	int errors = 0;
	for (int i = 0; i < TEST_RRSIG_SETS; i++) {
		if (dnslib_rrsig_set_type(rrsig_sets[i]) != test_rrsig_sets[i].type) {
			errors++;
			diag("Got wrong value for type from rrsig_set.");
		}
	}
	return errors;
}

static int test_rrsig_set_class(dnslib_rrsig_set_t **rrsig_sets)
{
	int errors = 0;
	for (int i = 0; i < TEST_RRSIG_SETS; i++) {
		if (dnslib_rrsig_set_class(rrsig_sets[i]) != test_rrsig_sets[i].rclass) {
			errors++;
			diag("Got wrong value for class from rrsig_set.");
		}
	}
	
	return errors;
}

static int test_rrsig_set_ttl(dnslib_rrsig_set_t **rrsig_sets)
{
	int errors = 0;
	for (int i = 0; i < TEST_RRSIG_SETS; i++) {
		if (dnslib_rrsig_set_ttl(rrsig_sets[i]) != test_rrsig_sets[i].ttl) {
			errors++;
			diag("Got wrong value for ttl from rrsig_set.");
		}
	}
	return errors;
}

static int test_rrsig_set_getters(uint type)
{
	int errors = 0;

	dnslib_rrsig_set_t *rrsig_sets[TEST_RRSIG_SETS];

	for (int i = 0; i < TEST_RRSIG_SETS; i++) {
		dnslib_dname_t *owner = dnslib_dname_new_from_str(
		                            test_rrsig_sets[i].owner,
		                            strlen(test_rrsig_sets[i].owner),
		                            NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}
		rrsig_sets[i] = dnslib_rrsig_set_new(owner,
		                             test_rrsig_sets[i].type,
		                             test_rrsig_sets[i].rclass,
		                             test_rrsig_sets[i].ttl);

		dnslib_rrsig_set_add_rdata(rrsig_sets[i], test_rrsig_sets[i].rdata);
	}

	switch (type) {
		case 0: {
			errors += test_rrsig_set_type(rrsig_sets);
			break;
		}
		case 1: {
			errors += test_rrsig_set_class(rrsig_sets);
			break;
		}
		case 2: {
			errors += test_rrsig_set_ttl(rrsig_sets);
			break;
		}
	} /* switch */

	for (int i = 0; i < TEST_RRSIG_SETS; i++) {
		dnslib_dname_free(&rrsig_sets[i]->owner);
		dnslib_rrsig_set_free(&rrsig_sets[i]);
	}


	return (errors == 0);
}

static int test_rrsig_set_deep_free()
{
	int errors = 0;
/* \note this cannot be tested, because some of the rdata are on stack */
/*	dnslib_rrsig_set_t  *tmp_rrsig_set;
	dnslib_dname_t *owner;
	for (int i = 0; i < TEST_RRSIG_SETS - 3; i++) {
		owner = dnslib_dname_new_from_str(
		                            test_rrsig_sets[i].owner,
		                            strlen(test_rrsig_sets[i].owner),
		                            NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}

		tmp_rrsig_set = dnslib_rrsig_set_new(owner,
		                             test_rrsig_sets[i].type,
		                             test_rrsig_sets[i].rclass,
		                             test_rrsig_sets[i].ttl);

		dnslib_rrsig_set_add_rdata(tmp_rrsig_set, test_rrsig_sets[i].rdata);

		dnslib_rrsig_set_deep_free(&tmp_rrsig_set, 1, 0);

		errors += (tmp_rrsig_set != NULL);
	} */

	return (errors == 0);
}

/*----------------------------------------------------------------------------*/

static const int DNSLIB_RRSIG_SET_TEST_COUNT = 8;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_rrsig_set_tests_count(int argc, char *argv[])
{
	return DNSLIB_RRSIG_SET_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_rrsig_set_tests_run(int argc, char *argv[])
{
	int res = 0,
	    res_final = 1;

	rrs_create_rdata();

	res = test_rrsig_set_create();
	ok(res, "rrsig_set: create");
	res_final *= res;

	skip(!res, 11);

	todo();

	ok(res = test_rrsig_set_delete(), "rrsig_set: delete");
	//res_final *= res;

	endtodo;

	ok(res = test_rrsig_set_getters(0), "rrsig_set: type");
	res_final *= res;

	ok(res = test_rrsig_set_getters(1), "rrsig_set: class");
	res_final *= res;

	ok(res = test_rrsig_set_getters(2), "rrsig_set: ttl");
	res_final *= res;

	ok(res = test_rrsig_set_rdata(), "rrsig_set: rdata manipulation");
	res_final *= res;

	ok(res = test_rrsig_set_merge(), "rrsig_set: rdata merging");
	res_final *= res;

	todo();

	ok(res = test_rrsig_set_deep_free(), "rrsig_set: deep free");
	res_final *= res;

	endtodo;

	endskip;	/* !res_create */


/*	dnslib_rrtype_descriptor_t *desc;

	for (int i = 0; i < TEST_RRSIG_SETS; i++) {
		desc =  dnslib_rrtype_descriptor_by_type(test_rrsig_sets[i].type);
		for (int x = 0; x < test_rrsig_sets[i].rdata->count; x++) {
			if (
			desc->wireformat[x] == 
			DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
			desc->wireformat[x] == 
			DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
			desc->wireformat[x] == DNSLIB_RDATA_WF_LITERAL_DNAME) {
				dnslib_dname_free(
				&(test_rrsig_sets[i].rdata->items[x].dname));
			}
		}
		dnslib_rdata_free(&test_rrsig_sets[i].rdata);
	} */

	return res_final;
}
