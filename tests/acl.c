/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <tap/basic.h>

#include "test_conf.h"
#include "libknot/libknot.h"
#include "knot/updates/acl.h"
#include "contrib/sockaddr.h"

static void check_sockaddr_set(struct sockaddr_storage *ss, int family,
                               const char *straddr, int port)
{
	int ret = sockaddr_set(ss, family, straddr, port);
	ok(ret == KNOT_EOK, "set address '%s'", straddr);
}

static void test_netblock_match(void)
{
	int ret;
	struct sockaddr_storage t = { 0 };

	// 127 dec ~ 01111111 bin
	// 170 dec ~ 10101010 bin
	struct sockaddr_storage ref4 = { 0 };
	check_sockaddr_set(&ref4, AF_INET, "127.170.170.127", 0);

	// 7F hex ~ 01111111 bin
	// AA hex ~ 10101010 bin
	struct sockaddr_storage ref6 = { 0 };
	check_sockaddr_set(&ref6, AF_INET6, "7FAA::AA7F", 0);

	ret = netblock_match(&ref4, &ref6, 32);
	ok(ret == false, "match: family mismatch");

	ret = netblock_match(NULL, &ref4, 32);
	ok(ret == false, "match: NULL first parameter");
	ret = netblock_match(&ref4, NULL, 32);
	ok(ret == false, "match: NULL second parameter");

	ret = netblock_match(&ref4, &ref4, -1);
	ok(ret == true, "match: ipv4 - identity, auto full prefix");
	ret = netblock_match(&ref4, &ref4, 31);
	ok(ret == true, "match: ipv4 - identity, subnet");
	ret = netblock_match(&ref4, &ref4, 32);
	ok(ret == true, "match: ipv4 - identity, full prefix");
	ret = netblock_match(&ref4, &ref4, 33);
	ok(ret == true, "match: ipv4 - identity, prefix overflow");

	ret = netblock_match(&ref6, &ref6, -1);
	ok(ret == true, "match: ipv6 - identity, auto full prefix");
	ret = netblock_match(&ref6, &ref6, 127);
	ok(ret == true, "match: ipv6 - identity, subnet");
	ret = netblock_match(&ref6, &ref6, 128);
	ok(ret == true, "match: ipv6 - identity, full prefix");
	ret = netblock_match(&ref6, &ref6, 129);
	ok(ret == true, "match: ipv6 - identity, prefix overflow");

	// 124 dec ~ 01111100 bin
	check_sockaddr_set(&t, AF_INET, "124.0.0.0", 0);
	ret = netblock_match(&t, &ref4, 5);
	ok(ret == true, "match: ipv4 - first byte, shorter prefix");
	ret = netblock_match(&t, &ref4, 6);
	ok(ret == true, "match: ipv4 - first byte, precise prefix");
	ret = netblock_match(&t, &ref4, 7);
	ok(ret == false, "match: ipv4 - first byte, not match");

	check_sockaddr_set(&t, AF_INET, "127.170.170.124", 0);
	ret = netblock_match(&t, &ref4, 29);
	ok(ret == true, "match: ipv4 - last byte, shorter prefix");
	ret = netblock_match(&t, &ref4, 30);
	ok(ret == true, "match: ipv4 - last byte, precise prefix");
	ret = netblock_match(&t, &ref4, 31);
	ok(ret == false, "match: ipv4 - last byte, not match");

	// 7C hex ~ 01111100 bin
	check_sockaddr_set(&t, AF_INET6, "7CAA::", 0);
	ret = netblock_match(&t, &ref6, 5);
	ok(ret == true, "match: ipv6 - first byte, shorter prefix");
	ret = netblock_match(&t, &ref6, 6);
	ok(ret == true, "match: ipv6 - first byte, precise prefix");
	ret = netblock_match(&t, &ref6, 7);
	ok(ret == false, "match: ipv6 - first byte, not match");

	check_sockaddr_set(&t, AF_INET6, "7FAA::AA7C", 0);
	ret = netblock_match(&t, &ref6, 125);
	ok(ret == true, "match: ipv6 - last byte, shorter prefix");
	ret = netblock_match(&t, &ref6, 126);
	ok(ret == true, "match: ipv6 - last byte, precise prefix");
	ret = netblock_match(&t, &ref6, 127);
	ok(ret == false, "match: ipv6 - last byte, not match");
}

static void test_netrange_match(void)
{
	bool ret;
	struct sockaddr_storage t = { 0 };
	struct sockaddr_storage min = { 0 };
	struct sockaddr_storage max = { 0 };

	// IPv4 tests.

	check_sockaddr_set(&min, AF_INET, "0.0.0.0", 0);
	check_sockaddr_set(&max, AF_INET, "255.255.255.255", 0);

	check_sockaddr_set(&t, AF_INET, "0.0.0.0", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == true, "match: ipv4 max range - minimum");
	check_sockaddr_set(&t, AF_INET, "255.255.255.255", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == true, "match: ipv4 max range - maximum");

	check_sockaddr_set(&min, AF_INET, "1.13.113.213", 0);
	check_sockaddr_set(&max, AF_INET, "2.24.124.224", 0);

	check_sockaddr_set(&t, AF_INET, "1.12.113.213", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == false, "match: ipv4 middle range - negative far min");
	check_sockaddr_set(&t, AF_INET, "1.13.113.212", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == false, "match: ipv4 middle range - negative close min");
	check_sockaddr_set(&t, AF_INET, "1.13.113.213", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == true, "match: ipv4 middle range - minimum");
	check_sockaddr_set(&t, AF_INET, "1.13.213.213", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == true, "match: ipv4 middle range - middle");
	check_sockaddr_set(&t, AF_INET, "2.24.124.224", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == true, "match: ipv4 middle range - max");
	check_sockaddr_set(&t, AF_INET, "2.24.124.225", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == false, "match: ipv4 middle range - negative close max");
	check_sockaddr_set(&t, AF_INET, "2.25.124.225", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == false, "match: ipv4 middle range - negative far max");

	// IPv6 tests.

	check_sockaddr_set(&min, AF_INET6, "::0", 0);
	check_sockaddr_set(&max, AF_INET6,
	                   "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", 0);

	check_sockaddr_set(&t, AF_INET6, "::0", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == true, "match: ipv6 max range - minimum");
	check_sockaddr_set(&t, AF_INET6,
	                   "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == true, "match: ipv6 max range - maximum");

	check_sockaddr_set(&min, AF_INET6, "1:13::ABCD:200B", 0);
	check_sockaddr_set(&max, AF_INET6, "2:A24::124:224", 0);

	check_sockaddr_set(&t, AF_INET6, "1:12::BCD:2000", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == false, "match: ipv6 middle range - negative far min");
	check_sockaddr_set(&t, AF_INET6, "1:13::ABCD:200A", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == false, "match: ipv6 middle range - negative close min");
	check_sockaddr_set(&t, AF_INET6, "1:13::ABCD:200B", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == true, "match: ipv6 middle range - minimum");
	check_sockaddr_set(&t, AF_INET6, "1:13:0:12:34:0:ABCD:200B", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == true, "match: ipv6 middle range - middle");
	check_sockaddr_set(&t, AF_INET6, "2:A24::124:224", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == true, "match: ipv6 middle range - max");
	check_sockaddr_set(&t, AF_INET6, "2:A24::124:225", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == false, "match: ipv6 middle range - negative close max");
	check_sockaddr_set(&t, AF_INET6, "2:FA24::4:24", 0);
	ret = netrange_match(&t, &min, &max);
	ok(ret == false, "match: ipv6 middle range - negative far max");
}

#define ZONE	"example.zone"
#define KEY1	"key1_md5"
#define KEY2	"key2_md5"
#define KEY3	"key3_sha256"

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
		"\n"
		"zone:\n"
		"  - domain: "ZONE"\n"
		"    acl: [ acl_key_addr, acl_deny, acl_no_action_deny ]\n"
		"    acl: [ acl_multi_addr, acl_multi_key ]\n"
		"    acl: [ acl_range_addr ]";

	ret = test_conf(conf_str, NULL);
	ok(ret == KNOT_EOK, "Prepare configuration");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "2001::1", 0);
	ret = acl_allowed(&acl, ACL_ACTION_NONE, &addr, &key1);
	ok(ret == true, "Address, key, empty action");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "2001::1", 0);
	ret = acl_allowed(&acl, ACL_ACTION_TRANSFER, &addr, &key1);
	ok(ret == true, "Address, key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "2001::2", 0);
	ret = acl_allowed(&acl, ACL_ACTION_TRANSFER, &addr, &key1);
	ok(ret == false, "Address not match, key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "2001::1", 0);
	ret = acl_allowed(&acl, ACL_ACTION_TRANSFER, &addr, &key0);
	ok(ret == false, "Address match, no key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "2001::1", 0);
	ret = acl_allowed(&acl, ACL_ACTION_TRANSFER, &addr, &key2);
	ok(ret == false, "Address match, key not match, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "2001::1", 0);
	ret = acl_allowed(&acl, ACL_ACTION_NOTIFY, &addr, &key1);
	ok(ret == false, "Address, key match, action not match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "240.0.0.1", 0);
	ret = acl_allowed(&acl, ACL_ACTION_NOTIFY, &addr, &key0);
	ok(ret == true, "Second address match, no key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "240.0.0.1", 0);
	ret = acl_allowed(&acl, ACL_ACTION_NOTIFY, &addr, &key1);
	ok(ret == false, "Second address match, extra key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "240.0.0.2", 0);
	ret = acl_allowed(&acl, ACL_ACTION_NOTIFY, &addr, &key0);
	ok(ret == false, "Denied address match, no key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "240.0.0.2", 0);
	ret = acl_allowed(&acl, ACL_ACTION_UPDATE, &addr, &key0);
	ok(ret == true, "Denied address match, no key, action not match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "240.0.0.3", 0);
	ret = acl_allowed(&acl, ACL_ACTION_UPDATE, &addr, &key0);
	ok(ret == false, "Denied address match, no key, no action");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "1.1.1.1", 0);
	ret = acl_allowed(&acl, ACL_ACTION_UPDATE, &addr, &key3);
	ok(ret == true, "Arbitrary address, second key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET, "100.0.0.1", 0);
	ret = acl_allowed(&acl, ACL_ACTION_TRANSFER, &addr, &key0);
	ok(ret == true, "IPv4 address from range, no key, action match");

	acl = conf_zone_get(conf(), C_ACL, zone_name);
	ok(acl.code == KNOT_EOK, "Get zone ACL");
	check_sockaddr_set(&addr, AF_INET6, "::1", 0);
	ret = acl_allowed(&acl, ACL_ACTION_TRANSFER, &addr, &key0);
	ok(ret == true, "IPv6 address from range, no key, action match");

	conf_free(conf());
	knot_dname_free(&zone_name, NULL);
	knot_dname_free(&key1_name, NULL);
	knot_dname_free(&key2_name, NULL);
	knot_dname_free(&key3_name, NULL);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	diag("netblock_match");
	test_netblock_match();

	diag("netrange_match");
	test_netrange_match();

	diag("acl_allowed");
	test_acl_allowed();

	return 0;
}
