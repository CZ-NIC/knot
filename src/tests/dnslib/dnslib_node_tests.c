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
enum { TEST_NODES = 2, RRSETS = 5};

struct test_node {
  dnslib_dname_t owner;
	dnslib_node_t *parent;
	uint size;
};

static dnslib_dname_t test_dnames[TEST_NODES] = {
    {(uint8_t *)"\3www\7example\3com", 17},
    {(uint8_t *)"\3www\7example\3com", 17}
};

static struct test_node	test_nodes[TEST_NODES] = {
    {{(uint8_t *)"\3com", 4}, (dnslib_node_t *)NULL},
    {{(uint8_t *)"\3www\7example\3com", 17}, (dnslib_node_t *)0xBADDCAFE}
};

static dnslib_rrset_t rrsets[RRSETS] = {
    {&test_dnames[0], 1, 1, 3600, NULL, NULL, NULL, 0},
    {&test_dnames[1], 2, 1, 3600, NULL, NULL, NULL, 0},
    {&test_dnames[1], 7, 1, 3600, NULL, NULL, NULL, 0},
    {&test_dnames[1], 3, 1, 3600, NULL, NULL, NULL, 0},
    {&test_dnames[1], 9, 1, 3600, NULL, NULL, NULL, 0}   
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
        dnslib_node_free(&tmp);
    }

    return (errors == 0);
}

static int test_node_get_rrset()
{
    dnslib_node_t *tmp;
    dnslib_rrset_t *rrset;
    int errors = 0;

    dnslib_node_t *nodes[TEST_NODES];

    for (int i = 0; i < TEST_NODES && !errors; i++) {    
        tmp = dnslib_node_new(&test_nodes[i].owner, test_nodes[i].parent);
        nodes[i]=tmp;
        for (int j = 0; j < RRSETS; j++) {
            dnslib_node_add_rrset(tmp, &rrsets[j]);
        }
    }

    for (int i = 0; i < TEST_NODES && !errors; i++) {
        for (int j = 0; j < RRSETS; j++) {
            rrset = &rrsets[j];
            if (dnslib_node_get_rrset(nodes[i], rrset->type) != rrset) {
                errors++;
                diag("Failed to get proper rrset from node");
            }
        }
        dnslib_node_free(&nodes[i]);
    }

    return (errors == 0);
}

static int test_node_get_parent()
{
    dnslib_node_t *tmp;
    dnslib_rrset_t *rrset;
    int errors = 0;

    dnslib_node_t *nodes[TEST_NODES];

    for (int i = 0; i < TEST_NODES && !errors; i++) {    
        tmp = dnslib_node_new(&test_nodes[i].owner, test_nodes[i].parent);
        nodes[i]=tmp;
        rrset = &rrsets[i];
        dnslib_node_add_rrset(tmp, rrset);
    }

    for (int i = 0; i < TEST_NODES && !errors; i++) {
        rrset = &rrsets[i];
         if (dnslib_node_get_parent(nodes[i]) != test_nodes[i].parent) {
            errors++;
            diag("Failed to get proper parent from node");
        }
        dnslib_node_free(&nodes[i]);
    }
    return (errors == 0);
}

static int test_node_sorting()
{
    dnslib_node_t *tmp;
    dnslib_rrset_t *rrset;
    int errors = 0;

    tmp = dnslib_node_new(&test_nodes[0].owner, test_nodes[0].parent);

    for (int i = 0; i < RRSETS && !errors; i++) {    
        rrset = &rrsets[i];
        dnslib_node_add_rrset(tmp, rrset);
    }
    
    const skip_node *node;

    node = skip_first(tmp->rrsets);
    
    int last = *((uint16_t *)node->key);

    while ((node = skip_next(node))!=NULL) {
        if (last > *((uint16_t *)node->key)) {
            errors++;
            diag("RRset sorting error");
        }
    }
    return (errors == 0);
}

static int test_node_delete()
{
    return 0;
}

static const int DNSLIB_NODE_TEST_COUNT = 6;

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

  int ret;
  ret = test_node_create();
  ok(ret, "node: create");

  skip(!ret, 4)

  ok(test_node_add_rrset(), "node: add");

  ok(test_node_get_rrset(), "node: get");

  ok(test_node_get_parent(), "node: get parent");

  ok(test_node_sorting(), "node: sort");

  endskip;

  todo();

  ok(test_node_delete(), "node: delete");

  endtodo;

	return 0;
}
