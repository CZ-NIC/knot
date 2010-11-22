#include "tap_unit.h"

#include "common.h"
#include "dname.h"
#include "node.h"

static int dnslib_node_tests_count(int argc, char *argv[]);
static int dnslib_node_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dnslib_node_tests_api = {
   "DNS library - node",        //! Unit name
   &dnslib_node_tests_count,  //! Count scheduled tests
   &dnslib_node_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

// C will not accept const int in other const definition
enum { TEST_NODES = 1};

struct test_node {
  dnslib_dname_t owner;
	dnslib_node_t *parent;
	uint size;
};

static struct test_node	test_nodes[TEST_NODES] = {
    {{(uint8_t *)"\3www\7example\3com", 17}, (dnslib_node_t *)0xBADDCAFE}
};

static dnslib_rrset_t rrsets[1] = {
    {{(uint8_t *)"\3www\7example\3com", 17}, 1, 1, 3600, NULL, NULL, NULL, 0}
};

static int test_node_create()
{
    dnslib_node_t *tmp;
    int errors = 0;
    for (int i = 0; i < TEST_NODES && !errors; i++) {
        tmp = dnslib_node_new(&test_nodes[i].owner, test_nodes[i].parent);
        if (tmp == NULL || tmp->owner != &test_nodes[i].owner || 
            tmp->parent != test_nodes[i].parent || tmp->rrsets == NULL) {
            errors++;
            diag("Failed to create node structure");
        }
        dnslib_node_free(&tmp);
    }
    return (errors == 0);
}

static int test_node_add_rrset()
{
    dnslib_node_t *tmp;
    dnslib_rrset_t *rrset;
    int errors = 0;
    for (int i = 0; i < TEST_NODES && !errors; i++) {
        tmp = dnslib_node_new(&test_nodes[i].owner, test_nodes[i].parent);
        rrset = &rrsets[0];
        if (dnslib_node_add_rrset(tmp, rrset)!=0) {
            errors++;
            diag("Failed to insert rrset into node");
        }
        if (dnslib_node_get_rrset(tmp, rrset->type) == NULL) {
            errors++;
            diag("Failed to get rrset from node");
        }
    }
    return (errors == 0);
}

static const int DNSLIB_NODE_TEST_COUNT = 1;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_node_tests_count(int argc, char *argv[])
{
   return DNSLIB_NODE_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_node_tests_run(int argc, char *argv[])
{

  ok(test_node_create(), "node: create");

  //skip

  ok(test_node_add_rrset(), "node: add");

	return 0;
}
