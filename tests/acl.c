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

#include <config.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <tap/basic.h>

#include "common/errcode.h"
#include "common/sockaddr.h"
#include "knot/updates/acl.h"
#include "knot/conf/conf.h"

static int acl_insert(list_t *acl, const struct sockaddr_storage *addr,
                      uint8_t prefix, knot_tsig_key_t *key)
{
	assert(acl);
	assert(addr);

	conf_iface_t *iface = malloc(sizeof(conf_iface_t));
	assert(iface);
	conf_remote_t *remote = malloc(sizeof(conf_remote_t));
	assert(remote);
	remote->remote = iface;

	memset(iface, 0, sizeof(conf_iface_t));
	iface->prefix = prefix;
	iface->key = key;
	memcpy(&iface->addr, addr, sizeof(struct sockaddr_storage));

	add_tail(acl, &remote->n);
	return KNOT_EOK;
}

int main(int argc, char *argv[])
{
	plan(15);

	conf_iface_t *match = NULL;
	list_t acl;
	init_list(&acl);

	// Create IPv4 address
	struct sockaddr_storage test_v4;
	int ret = sockaddr_set(&test_v4, AF_INET, "127.0.0.1", 12345);
	ok(ret == KNOT_EOK, "acl: new IPv4 address");

	// Create IPv6 address
	struct sockaddr_storage test_v6;
	ret = sockaddr_set(&test_v6, AF_INET6, "::1", 54321);
	ok(ret == KNOT_EOK, "acl: new IPv6 address");

	// Create simple IPv4 rule
	ret = acl_insert(&acl, &test_v4, IPV4_PREFIXLEN, NULL);
	ok(ret == KNOT_EOK, "acl: inserted IPv4 rule");

	// Create simple IPv6 rule
	ret = acl_insert(&acl, &test_v6, IPV6_PREFIXLEN, NULL);
	ok(ret == KNOT_EOK, "acl: inserted IPv6 rule");

	// Attempt to match unmatching address
	struct sockaddr_storage unmatch_v4;
	sockaddr_set(&unmatch_v4, AF_INET, "10.10.10.10", 24424);
	match = acl_find(&acl, &unmatch_v4, NULL);
	ok(match == NULL, "acl: matching non-existing address");

	// Attempt to match unmatching IPv6 address
	struct sockaddr_storage unmatch_v6;
	sockaddr_set(&unmatch_v6, AF_INET6, "2001:db8::1428:57ab", 24424);
	match = acl_find(&acl, &unmatch_v6, NULL);
	ok(match == NULL, "acl: matching non-existing IPv6 address");

	// Attempt to match matching address
	match = acl_find(&acl, &test_v4, NULL);
	ok(match != NULL, "acl: matching existing address");

	// Attempt to match matching address
	match = acl_find(&acl, &test_v6, NULL);
	ok(match != NULL, "acl: matching existing IPv6 address");

	// Attempt to match subnet
	struct sockaddr_storage match_pf4, test_pf4;
	sockaddr_set(&match_pf4, AF_INET, "192.168.1.0", 0);
	acl_insert(&acl, &match_pf4, 24, NULL);
	sockaddr_set(&test_pf4, AF_INET, "192.168.1.20", 0);
	match = acl_find(&acl, &test_pf4, NULL);
	ok(match != NULL, "acl: searching address in matching prefix /24");

	// Attempt to search non-matching subnet
	sockaddr_set(&test_pf4, AF_INET, "192.168.2.20", 0);
	match = acl_find(&acl, &test_pf4, NULL);
	ok(match == NULL, "acl: searching address in non-matching prefix /24");

	// Attempt to match v6 subnet
	struct sockaddr_storage match_pf6, test_pf6;
	sockaddr_set(&match_pf6, AF_INET6, "2001:0DB8:0400:000e:0:0:0:AB00", 0);
	acl_insert(&acl, &match_pf6, 120, NULL);
	sockaddr_set(&test_pf6, AF_INET6, "2001:0DB8:0400:000e:0:0:0:AB03", 0);
	match = acl_find(&acl, &test_pf6, NULL);
	ok(match != NULL, "acl: searching v6 address in matching prefix /120");

	// Attempt to search non-matching subnet
	sockaddr_set(&test_pf6, AF_INET6, "2001:0DB8:0400:000e:0:0:0:CCCC", 0);
	match = acl_find(&acl, &test_pf6, NULL);
	ok(match == NULL, "acl: searching v6 address in non-matching prefix /120");

	// Attempt to search subnet with key (multiple keys)
	knot_tsig_key_t key_a, key_b;
	knot_tsig_create_key("tsig-key1", KNOT_TSIG_ALG_HMAC_MD5, "Wg==", &key_a);
	knot_tsig_create_key("tsig-key2", KNOT_TSIG_ALG_HMAC_MD5, "Wg==", &key_b);
	acl_insert(&acl, &match_pf6, 120, &key_a);
	acl_insert(&acl, &match_pf6, 120, &key_b);
	sockaddr_set(&test_pf6, AF_INET6, "2001:0DB8:0400:000e:0:0:0:AB03", 0);
	match = acl_find(&acl, &test_pf6, key_a.name);
	ok(match != NULL && match->key == &key_a, "acl: searching v6 address with TSIG key A");
	match = acl_find(&acl, &test_pf6, key_b.name);
	ok(match != NULL && match->key == &key_b, "acl: searching v6 address with TSIG key B");

	// Attempt to search subnet with mismatching key
	knot_tsig_key_t badkey;
	knot_tsig_create_key("tsig-bad", KNOT_TSIG_ALG_HMAC_MD5, "Wg==", &badkey);
	match = acl_find(&acl, &test_pf6, badkey.name);
	ok(match == NULL, "acl: searching v6 address with bad TSIG key");
	knot_tsig_key_free(&badkey);

	knot_tsig_key_free(&key_a);
	knot_tsig_key_free(&key_b);

	conf_remote_t *remote = NULL, *next = NULL;
	WALK_LIST_DELSAFE(remote, next, acl) {
		free(remote->remote);
		free(remote);
	}

	// Return
	return 0;
}
