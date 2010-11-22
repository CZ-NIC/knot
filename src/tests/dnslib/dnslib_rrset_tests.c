/*!
 * \file dnslib_rrset_tests.c
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * Contains unit tests for RRSet (dnslib_rrset_t) and its API.
 *
 * Contains tests for:
 * -
 */

#include "tap_unit.h"

#include "common.h"
#include "rrset.h"
#include "dname.h"
#include "rdata.h"

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

enum { TEST_RRSETS = 3 , TEST_RRSIGS = 3};

//void *RRSIG_ADDRESS = (void *)0xDEADBEEF;
//void *RRSIG_FIRST = RRSIG_ADDRESS + 10;

static dnslib_rdata_t *rdatas[TEST_RRSETS];

struct test_rrset {
	char *owner;
	uint16_t type;
	uint16_t rclass;
	uint32_t  ttl;
	dnslib_rdata_t *rdata;
	const dnslib_rrset_t *rrsigs;
	const dnslib_rdata_t *rrsig_first;
	uint rrsig_count;
};

static const char *signature_strings[TEST_RRSIGS] = {"signature 1", "signature 2", "signature 3"};

static struct test_rrset test_rrsets[TEST_RRSETS] = {
	{ "example.com.", 
    2,
    1, 
    3600, 
    (dnslib_rdata_t *) "signature 1",
    NULL,
    NULL,
    0 },
 	{ "example2.com.", 
    2,
    1, 
    3600,
    (dnslib_rdata_t *) "signature 2",
    NULL,
    NULL,
    0 },
 	{ "example3.com.", 
    2,
    1, 
    3600, 
    (dnslib_rdata_t *) "signature 3",
    NULL,
    NULL,
    0 }
};

static const struct test_rrset test_rrsigs[TEST_RRSIGS] = {
    { "example.com.", 
    46,
    1, 
    3600, 
//    {NULL, {"signature data", 1, NULL}}, how to initialize unions?
    NULL,
    NULL,
    NULL,
    1 }, 
    { "example2.com.", 
    46,
    1, 
    3600, 
    NULL,
    NULL,
    NULL,
    1 },
    { "example3.com.", 
    46,
    1, 
    3600, 
    NULL,
    NULL,
    NULL,
    1 }
};


/* fills test_rrsets with random rdata */
static void create_rdata()
{
 	dnslib_rdata_t *rdata = dnslib_rdata_new();
	dnslib_rdata_item_t item;
	item.raw_data = RDATA_ITEM_PTR;

	dnslib_rdata_set_item(rdata, 0, item);

    for (int i = 0; i < TEST_RRSETS; i++) {
        rdatas[i] = dnslib_rdata_new(); 
       	dnslib_rdata_item_t item;
      	item.raw_data = RDATA_ITEM_PTR;
  
  	    dnslib_rdata_set_item(rdata, 0, item);
  
    	  uint8_t data[DNSLIB_MAX_RDATA_WIRE_SIZE];
    	  generate_rdata(data, DNSLIB_MAX_RDATA_WIRE_SIZE);

	      // set items through set_items() and then call set_item()
      	uint16_t rrtype = rand() % DNSLIB_RRTYPE_LAST + 1;
    	  fill_rdata(data, DNSLIB_MAX_RDATA_WIRE_SIZE, rrtype, rdatas[i]);
        test_rrsets[i].rdata = rdatas[i];
    }
}

static int check_rrset( const dnslib_rrset_t *rrset, int i,
						int check_rdata, int check_rrsigs )
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
			while (rdata->next != NULL && rdata->next != rrset->rdata) {
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

	if (check_rrsigs) {

      const dnslib_rrset_t *rrsigs;

          rrsigs = dnslib_rrset_rrsigs(rrset);
          if (strcmp((const char *)rrsigs->rdata->items[0].raw_data, signature_strings[i])) {
              diag("Signatures are not equal to those set when creating. Comparing "
                "%s with %s", rrsigs->rdata->items[0].raw_data, signature_strings[i]);
               errors++;
             }
  }
	return errors;
}

/*!
 * \brief Tests dnslib_rrset_new().
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rrset_create()
{
	int errors = 0;

	for (int i = 0; i < TEST_RRSETS; ++i) {
		dnslib_dname_t *owner = dnslib_dname_new_from_str(test_rrsets[i].owner, 
                            strlen(test_rrsets[i].owner), NODE_ADDRESS);
		if (owner == NULL) {
			diag("Error creating owner domain name!");
			return 0;
		}
		dnslib_rrset_t *rrset = dnslib_rrset_new(owner, test_rrsets[i].type,
							test_rrsets[i].rclass, test_rrsets[i].ttl);

//    dnslib_rrset_add_rdata(rrset, test_rrsets[i].rdata);

		errors += check_rrset(rrset, i, 0, 0);

		dnslib_rrset_free(&rrset);
		dnslib_dname_free(&owner);
	}

	//diag("Total errors: %d", errors);

	return (errors == 0);
}

/*!
 * \brief Tests dnslib_rrset_free().
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
    		dnslib_dname_t *owner = dnslib_dname_new_from_str(test_rrsets[i].owner, 
                                strlen(test_rrsets[i].owner), NODE_ADDRESS);
    		if (owner == NULL) {
    			diag("Error creating owner domain name!");
    			return 0;
    		}
    		dnslib_rrset_t *rrset = dnslib_rrset_new(owner, test_rrsets[i].type,
    							test_rrsets[i].rclass, test_rrsets[i].ttl);

        dnslib_rrset_add_rdata(rrset, test_rrsets[i].rdata);

    		errors += check_rrset(rrset, i, 1, 0);

    		dnslib_rrset_free(&rrset);
    		dnslib_dname_free(&owner);
    }

    //test whether sorting works
    //TODO test with actual RDATA and corresponing compare function

    dnslib_rrset_t *rrset = dnslib_rrset_new(NULL, 0, 0, 0);

    dnslib_rdata_t *tmp;

    dnslib_rdata_item_t *item;

    char *test_strings[10] = { "-2", "9", "2", "10", "1", "5", "8", "4", "6", "7" };
    
    for (int i = 0; i < 10; i++) {
        tmp = dnslib_rdata_new();
        item=malloc(sizeof(dnslib_rdata_item_t));
        item->raw_data = (uint8_t*)test_strings[i];
        dnslib_rdata_set_items(tmp, item, 1);
        dnslib_rrset_add_rdata(rrset, tmp);
    }

    tmp = rrset->rdata;
    
    int i = 0;
    while (tmp->next!=rrset->rdata && !errors)
    {
		if (strcmp(test_strings[i], (char *)tmp->items[0].raw_data)) {
            diag("Adding RDATA error!, is %s should be %s",
                 tmp->items[0].raw_data, test_strings[i]);
            errors++;
        }
        i++;
        tmp = tmp->next;
    }

    dnslib_rrset_free(&rrset);
    //TODO free Rdatas

    return (errors == 0);
}

static int test_rrset_rrsigs()
{
    int errors = 0;

    dnslib_rdata_item_t *item;
    
    dnslib_rdata_t *tmp; 

    for (int i = 0; i < TEST_RRSETS; i++) {
    dnslib_dname_t *owner = dnslib_dname_new_from_str(test_rrsets[i].owner, 
                            strlen(test_rrsets[i].owner), NODE_ADDRESS);
    if (owner == NULL) {
     	diag("Error creating owner domain name!");
    	return 0;
   	}
    dnslib_rrset_t *rrset = dnslib_rrset_new(owner, test_rrsets[i].type,
    	test_rrsets[i].rclass, test_rrsets[i].ttl);

    dnslib_rrset_add_rdata(rrset, test_rrsets[i].rdata);

    //owners are the same
    dnslib_rrset_t *rrsig = dnslib_rrset_new(owner, test_rrsigs[i].type,
    	test_rrsigs[i].rclass, test_rrsigs[i].ttl);

    tmp = dnslib_rdata_new();
    item=malloc(sizeof(dnslib_rdata_item_t));
    item->raw_data = (uint8_t*)signature_strings[i];
    dnslib_rdata_set_items(tmp, item, 1);
    dnslib_rrset_add_rdata(rrsig, tmp);

    if (dnslib_rrset_set_rrsigs(rrset, rrsig, rrsig->rdata, 1)!=0) {
        ;
    }
    errors += check_rrset(rrset, i, 0, 1);

    }

    return (errors == 0);
}

/*----------------------------------------------------------------------------*/

static const int DNSLIB_RRSET_TEST_COUNT = 4;

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
	int res_create = 0;

  create_rdata();

	res_create = test_rrset_create();
	ok(res_create, "rrset: create");

	skip(!res_create, 3);

	todo();

	ok(test_rrset_delete(), "rrset: delete");

	endtodo;

	ok(test_rrset_rdata(), "rrset: rdata manipulation");

	ok(test_rrset_rrsigs(), "rrset: rrsigs manipulation");

	endskip;	/* !res_create */

	return 0;
}
