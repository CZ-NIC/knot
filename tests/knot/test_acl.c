/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <tap/basic.h>

#include "test_conf.h"
#include "libknot/libknot.h"
#include "knot/updates/acl.h"
#include "contrib/sockaddr.h"

#define ZONE	"example.zone"
#define KEY1	"key1_md5"
#define KEY2	"key2_md5"
#define KEY3	"key3_sha256"

static void check_sockaddr_set(struct sockaddr_storage *ss, int family,
                               const char *straddr, int port)
{
	int ret = sockaddr_set(ss, family, straddr, port);
	ok(ret == 0, "set address '%s'", straddr);
}

static void test_acl_allowed(void)
{
	int ret;
	conf_val_t acl;
	struct sockaddr_storage addr = { 0 };

	knot_dname_t *zone_name = knot_dname_from_str_alloc(ZONE);
	ok(zone_name != NULL, "create zone dname");
	knot_dname_t *key1_name = knot_dname_from_str_alloc(KEY1);
	ok(key1_name != NULL, "create "KEY1);
	knot_dname_t *key2_name = knot_dname_from_str_alloc(KEY2);
	ok(key2_name != NULL, "create "KEY2);
	knot_dname_t *key3_name = knot_dname_from_str_alloc(KEY3);
	ok(key3_name != NULL, "create "KEY3);

	knot_tsig_key_t key0 = { 0 };
	knot_tsig_key_t key1 = { DNSSEC_TSIG_HMAC_MD5,    key1_name };
	knot_tsig_key_t key2 = { DNSSEC_TSIG_HMAC_MD5,    key2_name };
	knot_tsig_key_t key3 = { DNSSEC_TSIG_HMAC_SHA256, key3_name };

	const char *conf_str =
		"key:\n"
		"  - id: "KEY1"\n"
		"    algorithm: hmac-md5\n"
		"    secret: Zm9v\n"
		"  - id: "KEY2"\n"
		"    algorithm: hmac-md5\n"
		"    secret: Zm9v\n"
		"  - id: "KEY3"\n"
		"    algorithm: hmac-sha256\n"
		"    secret: Zm8=\n"
		"\n"
		"acl:\n"
		"  - id: acl_key_addr\n"
		"    address: [ 2001::1 ]\n"
		"    key: [ key1_md5 ]\n"
		"    action: [ transfer ]\n"
		"  - id: acl_deny\n"
		"    address: [ 240.0.0.2 ]\n"
		"    action: [ notify ]\n"
		"    deny: on\n"
		"  - id: acl_no_action_deny\n"
		"    address: [ 240.0.0.3 ]\n"
		"    deny: on\n"
		"  - id: acl_multi_addr\n"
		"    address: [ 192.168.1.1, 240.0.0.0/24 ]\n"
		"    action: [ notify, update ]\n"
		"  - id: acl_multi_key\n"
		"    key: [ key2_md5, key3_sha256 ]\n"
		"    action: [ notify, update ]\n"
		"  - id: acl_range_addr\n"
		"    address: [ 100.0.0.0-100.0.0.5, ::0-::5 ]\n"
		"    action: [ transfer ]\n"
		"  - id: acl_update_key\n"
		"    key: key1_md5\n"
		"    update-owner: key\n"
		"    update-type: A\n"
		"    action: [ update ]\n"
		"\n"
		"zone:\n"
		"  - domain: "ZONE"\n"
		"    acl: [ acl_key_addr, acl_deny, acl_no_action_deny ]\n"
		"    acl: [ acl_multi_addr, acl_multi_key ]\n"
		"    acl: [ acl_range_addr ]\n"
		"  - domain: "KEY1"\n"
		"    acl: acl_update_key";

	ret = test_conf(conf_str, NULL);
	is_int(KNOT_EOK, ret, "Prepare configuration");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "2001::1", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_NONE, &addr, &key1, zone_name, NULL);
	ok(ret == true, "Address, key, empty action");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "2001::1", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_TRANSFER, &addr, &key1, zone_name, NULL);
	ok(ret == true, "Address, key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "2001::2", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_TRANSFER, &addr, &key1, zone_name, NULL);
	ok(ret == false, "Address not match, key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "2001::1", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_TRANSFER, &addr, &key0, zone_name, NULL);
	ok(ret == false, "Address match, no key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "2001::1", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_TRANSFER, &addr, &key2, zone_name, NULL);
	ok(ret == false, "Address match, key not match, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "2001::1", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_NOTIFY, &addr, &key1, zone_name, NULL);
	ok(ret == false, "Address, key match, action not match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "240.0.0.1", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_NOTIFY, &addr, &key0, zone_name, NULL);
	ok(ret == true, "Second address match, no key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "240.0.0.1", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_NOTIFY, &addr, &key1, zone_name, NULL);
	ok(ret == false, "Second address match, extra key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "240.0.0.2", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_NOTIFY, &addr, &key0, zone_name, NULL);
	ok(ret == false, "Denied address match, no key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "240.0.0.2", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_UPDATE, &addr, &key0, zone_name, NULL);
	ok(ret == true, "Denied address match, no key, action not match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "240.0.0.3", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_UPDATE, &addr, &key0, zone_name, NULL);
	ok(ret == false, "Denied address match, no key, no action");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "1.1.1.1", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_UPDATE, &addr, &key3, zone_name, NULL);
	ok(ret == true, "Arbitrary address, second key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "100.0.0.1", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_TRANSFER, &addr, &key0, zone_name, NULL);
	ok(ret == true, "IPv4 address from range, no key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "::1", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_TRANSFER, &addr, &key0, zone_name, NULL);
	ok(ret == true, "IPv6 address from range, no key, action match");

	knot_pkt_t *query = knot_pkt_new(NULL, 512, NULL);
	knot_rrset_t A;
	knot_rrset_init(&A, key1_name, KNOT_RRTYPE_A, KNOT_CLASS_IN, 3600);
	knot_pkt_begin(query, KNOT_ADDITIONAL);
	knot_pkt_put(query, 0, &A, 0);

	acl = conf_zone_get(conf(), C_ACL, key1_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "1.2.3.4", 0);
	ret = acl_allowed(conf(), &acl, ACL_ACTION_UPDATE, &addr, &key1, key1_name, query);
	ok(ret == true, "Correct type and owner, first key, action match");

	knot_pkt_free(query);
	conf_free(conf());
	knot_dname_free(zone_name, NULL);
	knot_dname_free(key1_name, NULL);
	knot_dname_free(key2_name, NULL);
	knot_dname_free(key3_name, NULL);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	diag("acl_allowed");
	test_acl_allowed();

	return 0;
}
