#include <stdio.h>

#include "tap_unit.h"
#include "conf/conf.h"

/* Resources. */
#include "sample_conf.rc"

static int conf_tests_count(int argc, char *argv[]);
static int conf_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api conf_tests_api = {
	"Configuration parser", //! Unit name
	&conf_tests_count,      //! Count scheduled tests
	&conf_tests_run         //! Run scheduled tests
};

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int conf_tests_count(int argc, char *argv[])
{
	return 10;
}

/*! Run all scheduled tests for given parameters.
 */
static int conf_tests_run(int argc, char *argv[])
{

	// Test 1: Allocate new config
	const char *config_fn = "rc:/sample_conf";
	config_t *conf = config_new(config_fn);
	ok(conf != 0, "config_new()");

	// Test 2: Parse config
	int ret = config_parse_str(conf, sample_conf_rc);
	ok(ret == 0, "parsing configuration file %s", config_fn);

	// Test 3: Test server version (0-level depth)
	is(conf->version, "Infinitesimal", "server version loaded ok");

	// Test 4: Test interfaces (1-level depth)
	ok(!EMPTY_LIST(conf->ifaces), "configured interfaces exist");

	// Test 5,6,7,8: Interfaces content (2-level depth)
	struct node *n = HEAD(conf->ifaces);
	conf_iface_t *iface = (conf_iface_t*)n;
	is(iface->address, "10.10.1.1", "interface0 address check");
	cmp_ok(iface->port, "==", 53, "interface0 port check");
	n = n->next;
	iface = (conf_iface_t*)n;
	is(iface->address, "::0", "interface1 address check");
	cmp_ok(iface->port, "==", 53, "interface1 default port check");

	// Test 9,10: Check first key (2-level depth)
	n = HEAD(conf->keys);
	conf_key_t *key = (conf_key_t*)n;
	cmp_ok(key->algorithm, "==", HMAC_MD5, "key0 algorithm enum check");
	is(key->secret, "Wg==", "key0 secret check");

	//! \todo Level-3 checks (logs), postprocess check (server->key,iface)

	// Deallocating config
	config_free(conf);

	return 0;
}
