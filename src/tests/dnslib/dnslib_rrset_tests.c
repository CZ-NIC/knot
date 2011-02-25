/*!
 * \file dnslib_rrset_tests.c
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * Contains unit tests for RRSet (dnslib_rrset_t) and its API.
 *
 * Contains tests for:
 * -
 */

#include "dnslib/rrset.h"
#include "dnslib/dname.h"
#include "dnslib/rdata.h"

static int dnslib_rrset_tests_count(int argc, char *argv[]);
static int dnslib_rrset_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dnslib_rrset_tests_api = {
	"DNS library - rrset",        //! Unit name
	&dnslib_rrset_tests_count,  //! Count scheduled tests
	&dnslib_rrset_tests_run     //! Run scheduled tests
};

/*----------------------------------------------------------------------------*/
/*
 *  Unit implementation.
 */

enum { TEST_RRSETS = 6 , TEST_RRSIGS = 6};

//void *RRSIG_ADDRESS = (void *)0xDEADBEEF;
//void *RRSIG_FIRST = RRSIG_ADDRESS + 10;

struct test_rrset {
	char *owner;
	uint16_t type;
	uint16_t rclass;
	uint32_t  ttl;
	dnslib_rdata_t *rdata;
	const dnslib_rrsig_set_t *rrsigs;
};

static const char *signature_strings[TEST_RRSIGS] = 
{"signature 1", "signature 2", "signature 3",
 "signature 4", "signature 5", "signature 6"};

enum {
	RR_DNAMES_COUNT = 3,
	RR_ITEMS_COUNT = 3,
	RR_RDATA_COUNT = 5,
};

static dnslib_dname_t RR_DNAMES[RR_DNAMES_COUNT] =
	{ {(uint8_t *)"\7example\3com", 13, NULL}, //0's at the end are added
          {(uint8_t *)"\2ns1\7example\3com", 17, NULL},
          {(uint8_t *)"\2ns2\7example\3com", 17, NULL} };

/*			   192.168.1.1 */
static uint8_t adress[4] = {0xc0, 0xa8, 0x01, 0x01};

static dnslib_rdata_item_t RR_ITEMS[RR_ITEMS_COUNT] =
	{ {.dname = &RR_DNAMES[1]},
	  {.dname = &RR_DNAMES[2]},
          {.raw_data = adress} };

static dnslib_rdata_t RR_RDATA[RR_RDATA_COUNT] =
	{ {&RR_ITEMS[0], 1, &RR_RDATA[0]},
	  {&RR_ITEMS[1], 1, &RR_RDATA[1]}, /* first ns */
	  {&RR_ITEMS[2], 1, &RR_RDATA[2]}, /* second ns */
	  {&RR_ITEMS[1], 1, &RR_RDATA[4]}, /* both in cyclic list */
	  {&RR_ITEMS[2], 1, &RR_RDATA[3]} };

static struct test_rrset test_rrsets[TEST_RRSETS] = {
	{
		"example.com.",
		2,
		DNSLIB_CLASS_IN,
		3600,
		NULL,
		NULL,
	},
	{
		"example2.com.",
		2,
		DNSLIB_CLASS_IN,
		3600,
		NULL,
		NULL,
	},
	{
		"example3.com.",
		2,
		DNSLIB_CLASS_IN,
		3600,
		NULL,
		NULL,
	},
	{ "example.com.", DNSLIB_RRTYPE_NS, DNSLIB_CLASS_IN,
	  3600, &RR_RDATA[1], NULL },
	{ "example.com.", DNSLIB_RRTYPE_NS, DNSLIB_CLASS_IN,
	  3600, &RR_RDATA[2], NULL },
	{ "example.com.", DNSLIB_RRTYPE_NS, DNSLIB_CLASS_IN,
	  3600, &RR_RDATA[3], NULL },
};

static const struct test_rrset test_rrsigs[TEST_RRSIGS] = {
	{
		"example.com.",
		46,
		1,
		3600,
		NULL,
	},
	{
		"example2.com.",
		46,
		1,
		3600,
		NULL,
	},
	{
		"example3.com.",
		46,
		1,
		3600,
		NULL,
	},
	{
		"example4.com.",
		46,
		1,
		3600,
		NULL,
	},
	{
		"example5.com.",
		46,
		1,
		3600,
		NULL,
	},
	{
		"example6.com.",
		46,
		1,
		3600,
		NULL,
	}
};


/* fills test_rrsets with random rdata */
static void create_rdata()
{
	dnslib_rdata_t *r;
	for (int i = 0; i < TEST_RRSETS; i++) {
		r = dnslib_rdata_new();
		dnslib_rdata_item_t item;
		item.raw_data = RDATA_ITEM_PTR;

		dnslib_rdata_set_item(r, 0, item);

		uint8_t data[DNSLIB_MAX_RDATA_WIRE_SIZE];
		generate_rdata(data, DNSLIB_MAX_RDATA_WIRE_SIZE);

		// from dnslib_rdata_tests.c
		fill_rdata(data, DNSLIB_MAX_RDATA_WIRE_SIZE, 
		           test_rrsets[i].type, r);
		test_rrsets[i].rdata = r;
	}
}

static int check_rrset(const dnslib_rrset_t *rrset, int i,
                       int check_rdata, int check_items,
		       int check_rrsigs)
{
	int errors = 0;

	if (rrset == NULL) {
		diag("RRSet not created!");
		return 1;
	}

	char *owner = dnslib_dname_to_str(rrset->owner);
	if (strcmp(owner, test_rrsets[i].owner) != 0) {
		diag("OWNER domain name wrong: '%s' (should be '%s')",
		     owner, test_rrsets[i].owner);
		++errors;
	}
	free(owner);

	if (rrset->type != test_rrsets[i].type) {
		diag("TYPE wrong: %u (should be: %u)", rrset->type,
		     test_rrsets[i].type);
		++errors;
	}

	if (rrset->rclass != test_rrsets[i].rclass) {
		diag("CLASS wrong: %u (should be: %u)", rrset->rclass,
		     test_rrsets[i].rclass);
		++errors;
	}

	if (rrset->ttl != test_rrsets[i].ttl) {
		diag("TTL wrong: %u (should be: %u)", rrset->ttl,
		     test_rrsets[i].ttl);
		++errors;
	}

	if (check_rdata) {
		dnslib_rdata_t *rdata = rrset->rdata;

		if (rdata == NULL) {
			diag("There are no RDATAs in the RRSet");
			++errors;
		}
		if (rdata != NULL) {
			while (rdata->next != NULL &&
			       rdata->next != rrset->rdata) {
				rdata = rdata->next;
			}
			if (rdata->next == NULL) {
				diag("The list of RDATAs is not cyclical!");
				++errors;
			} else {
				assert(rdata == rrset->rdata);
			}
		}
	}

	if (check_items) {
		dnslib_rrtype_descriptor_t *desc =
			dnslib_rrtype_descriptor_by_type(rrset->type);
		if (dnslib_rdata_compare(rrset->rdata,
			                 test_rrsets[i].rdata,
					 desc->wireformat)) {
			diag("Rdata items do not match.");
			errors++;
		}
	}

	/* will work only with nul terminated strings,
	 * consider changing to more versatile implementation */

	 /* How about, once it's tested, using rdata_compare */

	if (check_rrsigs) {

		const dnslib_rrsig_set_t *rrsigs;

		rrsigs = dnslib_rrset_rrsigs(rrset);
		if (strcmp((const char *)rrsigs->rdata->items[0].raw_data,
		                signature_strings[i])) {
			diag("Signatures are not equal"
			     "to those set when creating."
			     "Comparing %s with %s",
			     rrsigs->rdata->items[0].raw_data,
			     signature_strings[i]);
			errors++;
		}
	}
	return errors;
}

/*!
 * \brief Tests dnslib_rrset_new().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rrset_create()
{
	int errors = 0;

	for (int i = 0; i < TEST_RRSETS; ++i) {
		dnslib_dname_t *owner = dnslib_dname_new_from_str(
		                            test_rrsets[i].owner,
		                            strlen(test_rrsets[i].owner),
		                            NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}
		dnslib_rrset_t *rrset = dnslib_rrset_new(owner,
		                                         test_rrsets[i].type,
		                                         test_rrsets[i].rclass,
		                                         test_rrsets[i].ttl);

		errors += check_rrset(rrset, i, 0, 0, 0);

		dnslib_rrset_free(&rrset);
		dnslib_dname_free(&owner);
	}

	//diag("Total errors: %d", errors);

	return (errors == 0);
}

/*!
 * \brief Tests dnslib_rrset_free().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 *
 * \todo How to test this?
 */
static int test_rrset_delete()
{
	return 0;
}

static int test_rrset_rdata()
{
	/* rdata add */
	int errors = 0;
	for (int i = 0; i < TEST_RRSETS; i++) {
		dnslib_dname_t *owner = dnslib_dname_new_from_str(
		                            test_rrsets[i].owner,
		                            strlen(test_rrsets[i].owner),
		                            NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}
		dnslib_rrset_t *rrset = dnslib_rrset_new(owner,
		                                         test_rrsets[i].type,
		                                         test_rrsets[i].rclass,
		                                         test_rrsets[i].ttl);

		dnslib_rrset_add_rdata(rrset, test_rrsets[i].rdata);

		errors += check_rrset(rrset, i, 1, 0, 0);

		dnslib_rrset_free(&rrset);
		dnslib_dname_free(&owner);
	}

	//test whether adding works properly = keeps order of added elements

	dnslib_rrset_t *rrset = dnslib_rrset_new(NULL, 0, 0, 0);

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
		dnslib_rrset_add_rdata(rrset, r);
		free(item);
	}

	dnslib_rdata_t *tmp = rrset->rdata;

	int i = 0;
	while (tmp->next != rrset->rdata && !errors) {
		if (strcmp(test_strings[i], (char *)tmp->items[0].raw_data)) {
			diag("Adding RDATA error!, is %s should be %s",
			tmp->items[0].raw_data, test_strings[i]);
			errors++;
		}
		i++;
		tmp = tmp->next;
	}

	tmp = rrset->rdata;

	dnslib_rdata_t *next;

	while (tmp->next != rrset->rdata) {
		next = tmp->next;
		dnslib_rdata_free(&tmp);
		tmp = next;
	}

	dnslib_rdata_free(&tmp);

	dnslib_rrset_free(&rrset);

	return (errors == 0);
}

static int test_rrset_rrsigs()
{
	int errors = 0;

	dnslib_rdata_item_t *item;

	dnslib_rdata_t *tmp;

	dnslib_dname_t *owner;

	dnslib_rrset_t *rrset;

	for (int i = 0; i < TEST_RRSETS; i++) {
		owner = dnslib_dname_new_from_str(test_rrsets[i].owner,
		strlen(test_rrsets[i].owner), NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}

		rrset = dnslib_rrset_new(owner, test_rrsets[i].type,
		test_rrsets[i].rclass, test_rrsets[i].ttl);

		dnslib_rrset_add_rdata(rrset, test_rrsets[i].rdata);

		//owners are the same

		assert(TEST_RRSETS == TEST_RRSIGS);

		dnslib_rrsig_set_t *rrsig = dnslib_rrsig_set_new(owner,
		                                         test_rrsigs[i].type,
		                                         test_rrsigs[i].rclass,
		                                         test_rrsigs[i].ttl);

		tmp = dnslib_rdata_new();
		item = malloc(sizeof(dnslib_rdata_item_t));
		/* signature is just a string, 
		 * should be sufficient for testing */
		item->raw_data = (uint8_t *)signature_strings[i];
		dnslib_rdata_set_items(tmp, item, 1);
		dnslib_rrsig_set_add_rdata(rrsig, tmp);

		if (dnslib_rrset_set_rrsigs(rrset, rrsig)
		      != 0) {
			diag("Could not set rrsig");
			errors++;
		}
		errors += check_rrset(rrset, i, 0, 0, 1);
		dnslib_dname_free(&owner);
		dnslib_rrset_free(&rrset);
		free(item);
		dnslib_rdata_free(&tmp);
		dnslib_rrsig_set_free(&rrsig);
	}
	return (errors == 0);
}

static int test_rrset_merge()
{
	dnslib_rrset_t *merger1;
	dnslib_rrset_t *merger2;

	dnslib_dname_t *owner1 =
		dnslib_dname_new_from_str(test_rrsets[3].owner,
		                          strlen(test_rrsets[3].owner), NULL);
	merger1 = dnslib_rrset_new(owner1, test_rrsets[3].type,
	                           test_rrsets[3].rclass,
				   test_rrsets[3].ttl);

	dnslib_rrset_add_rdata(merger1, test_rrsets[3].rdata);

	dnslib_dname_t *owner2 =
		dnslib_dname_new_from_str(test_rrsets[4].owner,
		                          strlen(test_rrsets[4].owner), NULL);
	merger2 = dnslib_rrset_new(owner2, test_rrsets[4].type,
	                           test_rrsets[4].rclass,
				   test_rrsets[4].ttl);

	dnslib_rrset_add_rdata(merger2, test_rrsets[4].rdata);

	dnslib_rrset_merge((void **)&merger1, (void **)&merger2);

	if (check_rrset(merger1, 5, 0, 1, 0)) {
		diag("Merged rdata are wrongly set.");
		return 0;
	}

	dnslib_dname_free(&owner1);
	dnslib_dname_free(&owner2);
	dnslib_rrset_free(&merger1);
	dnslib_rrset_free(&merger2);

	return 1;
}

static int test_rrset_owner(dnslib_rrset_t **rrsets)
{
	int errors = 0;
	for (int i = 0; i < TEST_RRSETS; i++) {
		char *dname_str =
			dnslib_dname_to_str(dnslib_rrset_owner(rrsets[i]));
		if (strcmp(dname_str, test_rrsets[i].owner)) {
			diag("Got wrong value for owner from rrset.");
			errors++;
		}
		free(dname_str);
	}
	return errors;
}

static int test_rrset_type(dnslib_rrset_t **rrsets)
{
	int errors = 0;
	for (int i = 0; i < TEST_RRSETS; i++) {
		if (dnslib_rrset_type(rrsets[i]) != test_rrsets[i].type) {
			errors++;
			diag("Got wrong value for type from rrset.");
		}
	}
	return errors;
}

static int test_rrset_class(dnslib_rrset_t **rrsets)
{
	int errors = 0;
	for (int i = 0; i < TEST_RRSETS; i++) {
		if (dnslib_rrset_class(rrsets[i]) != test_rrsets[i].rclass) {
			errors++;
			diag("Got wrong value for class from rrset.");
		}
	}
	
	return errors;
}

static int test_rrset_ttl(dnslib_rrset_t **rrsets)
{
	int errors = 0;
	for (int i = 0; i < TEST_RRSETS; i++) {
		if (dnslib_rrset_ttl(rrsets[i]) != test_rrsets[i].ttl) {
			errors++;
			diag("Got wrong value for ttl from rrset.");
		}
	}
	return errors;
}

static int test_rrset_ret_rdata(dnslib_rrset_t **rrsets)
{
	int errors = 0;
	
	dnslib_rrtype_descriptor_t *desc;

	for (int i = 0; i < TEST_RRSETS; i++) {
		desc = dnslib_rrtype_descriptor_by_type(rrsets[i]->type);
		assert(desc);
		if (dnslib_rdata_compare(dnslib_rrset_rdata(rrsets[i]),
			                 test_rrsets[i].rdata,
					 desc->wireformat)) {
			errors++;
			diag("Got wrong value for rdata from rrset.");
		}
	}
	return errors;
}

static int test_rrset_get_rdata(dnslib_rrset_t **rrsets)
{
	int errors = 0;

	dnslib_rrtype_descriptor_t *desc;

	for (int i = 0; i < TEST_RRSETS; i++) {
		desc = dnslib_rrtype_descriptor_by_type(rrsets[i]->type);
		assert(desc);
		if (dnslib_rdata_compare(dnslib_rrset_get_rdata(rrsets[i]),
			                 test_rrsets[i].rdata,
					 desc->wireformat)) {
			errors++;
			diag("Got wrong value for rdata from rrset. (Get)");
		}
	}
	return errors;
}

static int test_rrset_ret_rrsigs(dnslib_rrset_t **rrsets)
{
	int errors = 0;

	for (int i = 0; i < TEST_RRSETS; i++) {
		/* TODO should I test the insides of structure as well? */
		if (dnslib_rrset_rrsigs(rrsets[i]) != test_rrsets[i].rrsigs) {
			errors++;
			diag("Got wrong value for rrsigs from rrset.");
		}
	}
	return errors;
}

static int test_rrset_getters(uint type)
{
	int errors = 0;

	dnslib_rrset_t *rrsets[TEST_RRSETS];

	for (int i = 0; i < TEST_RRSETS; i++) {
		dnslib_dname_t *owner = dnslib_dname_new_from_str(
		                            test_rrsets[i].owner,
		                            strlen(test_rrsets[i].owner),
		                            NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}
		rrsets[i] = dnslib_rrset_new(owner,
		                             test_rrsets[i].type,
		                             test_rrsets[i].rclass,
		                             test_rrsets[i].ttl);

		dnslib_rrset_add_rdata(rrsets[i], test_rrsets[i].rdata);
	}

	switch (type) {
		case 0: {
			errors += test_rrset_owner(rrsets);
			break;
		}
		case 1: {
			errors += test_rrset_type(rrsets);
			break;
		}
		case 2: {
			errors += test_rrset_class(rrsets);
			break;
		}
		case 3: {
			errors += test_rrset_ttl(rrsets);
			break;
		}
		case 4: {
			errors += test_rrset_ret_rdata(rrsets);
			break;
		}
		case 5: {
			errors += test_rrset_get_rdata(rrsets);
			break;
		}
		case 6: {
			errors += test_rrset_ret_rrsigs(rrsets);
			break;
		}
	} /* switch */

	for (int i = 0; i < TEST_RRSETS; i++) {
		dnslib_dname_free(&rrsets[i]->owner);
		dnslib_rrset_free(&rrsets[i]);
	}


	return (errors == 0);
}

static int test_rrset_deep_free()
{
	int errors = 0;

	dnslib_rrset_t  *tmp_rrset;
	dnslib_dname_t *owner;
	for (int i = 0; i < TEST_RRSETS; i++) {
		owner = dnslib_dname_new_from_str(
		                            test_rrsets[i].owner,
		                            strlen(test_rrsets[i].owner),
		                            NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}

		tmp_rrset = dnslib_rrset_new(owner,
		                             test_rrsets[i].type,
		                             test_rrsets[i].rclass,
		                             test_rrsets[i].ttl);

		dnslib_rrset_add_rdata(tmp_rrset, test_rrsets[i].rdata);

		dnslib_rrset_deep_free(&tmp_rrset, 1, 0);

		errors += (tmp_rrset != NULL);
	}

	return (errors == 0);
}

/*----------------------------------------------------------------------------*/

static const int DNSLIB_RRSET_TEST_COUNT = 13;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_rrset_tests_count(int argc, char *argv[])
{
	return DNSLIB_RRSET_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_rrset_tests_run(int argc, char *argv[])
{
	int res = 0,
	    res_final = 1;

	create_rdata();

	res = test_rrset_create();
	ok(res, "rrset: create");
	res_final *= res;

	skip(!res, 11);

	todo();

	ok(res = test_rrset_delete(), "rrset: delete");
	//res_final *= res;

	endtodo;

	ok(res = test_rrset_getters(0), "rrset: owner");
	res_final *= res;

	ok(res = test_rrset_getters(1), "rrset: type");
	res_final *= res;

	ok(res = test_rrset_getters(2), "rrset: class");
	res_final *= res;

	ok(res = test_rrset_getters(3), "rrset: ttl");
	res_final *= res;

	ok(res = test_rrset_getters(4), "rrset: rdata");
	res_final *= res;

	ok(res = test_rrset_getters(5), "rrset: get rdata");
	res_final *= res;

	ok(res = test_rrset_getters(6), "rrset: rrsigs");
	res_final *= res;

	ok(res = test_rrset_rdata(), "rrset: rdata manipulation");
	res_final *= res;

	ok(res = test_rrset_rrsigs(), "rrset: rrsigs manipulation");
	res_final *= res;

	ok(res = test_rrset_merge(), "rrset: rdata merging");
	res_final *= res;

	ok(res = test_rrset_deep_free(), "rrset: deep free");
	res_final *= res;

	endskip;	/* !res_create */


/*	dnslib_rrtype_descriptor_t *desc;

	for (int i = 0; i < TEST_RRSETS; i++) {
		desc =  dnslib_rrtype_descriptor_by_type(test_rrsets[i].type);
		for (int x = 0; x < test_rrsets[i].rdata->count; x++) {
			if (
			desc->wireformat[x] == 
			DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
			desc->wireformat[x] == 
			DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
			desc->wireformat[x] == DNSLIB_RDATA_WF_LITERAL_DNAME) {
				dnslib_dname_free(
				&(test_rrsets[i].rdata->items[x].dname));
			}
		}
		dnslib_rdata_free(&test_rrsets[i].rdata);
	} */

	return res_final;
}
