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

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>
#include <stdbool.h>

#include "knot/updates/acl.h"
#include "knot/conf/conf.h"
#include "libknot/libknot.h"
#include "libknot/internal/endian.h"
#include "libknot/internal/sockaddr.h"

static const uint8_t* ipv4_addr(const struct sockaddr_storage *ss) {
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)ss;
	return (uint8_t *)&ipv4->sin_addr.s_addr;
}

static const uint8_t* ipv6_addr(const struct sockaddr_storage *ss) {
	struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)ss;
	return (uint8_t *)&ipv6->sin6_addr.s6_addr;
}

bool netblock_match(const struct sockaddr_storage *ss1,
                    const struct sockaddr_storage *ss2,
                    unsigned prefix)
{
	if (ss1 == NULL || ss2 == NULL) {
		return false;
	}

	if (ss1->ss_family != ss2->ss_family) {
		return false;
	}

	const uint8_t *addr1, *addr2;
	switch (ss1->ss_family) {
	case AF_INET:
		addr1 = ipv4_addr(ss1);
		addr2 = ipv4_addr(ss2);
		prefix = prefix > IPV4_PREFIXLEN ? IPV4_PREFIXLEN : prefix;
		break;
	case AF_INET6:
		addr1 = ipv6_addr(ss1);
		addr2 = ipv6_addr(ss2);
		prefix = prefix > IPV6_PREFIXLEN ? IPV6_PREFIXLEN : prefix;
		break;
	default:
		return false;
	}

	/* Compare full bytes address block. */
	uint8_t full_bytes = prefix / 8;
	for (int i = 0; i < full_bytes; i++) {
		if (addr1[i] != addr2[i]) {
			return false;
		}
	}

	/* Compare last partial byte address block. */
	uint8_t rest_bits = prefix % 8;
	if (rest_bits > 0) {
		uint8_t rest1 = addr1[full_bytes] >> (8 - rest_bits);
		uint8_t rest2 = addr2[full_bytes] >> (8 - rest_bits);
		if (rest1 != rest2) {
			return false;
		}
	}

	return true;
}

bool acl_allowed(conf_val_t *acl, acl_action_t action,
                 const struct sockaddr_storage *addr,
                 knot_tsig_key_t *tsig)
{
	if (acl == NULL || addr == NULL || tsig == NULL) {
		return NULL;
	}

	while (acl->code == KNOT_EOK) {
		/* Check if the action is allowed. */
		bool match = false, deny = false;
		conf_val_t action_val = conf_id_get(conf(), C_ACL, C_ACTION, acl);
		while (action_val.code == KNOT_EOK) {
			unsigned act = conf_opt(&action_val);
			if (act & action) {
				match = true;
			}
			if (act == ACL_ACTION_DENY) {
				deny = true;
			}
			conf_val_next(&action_val);
		}
		if (!match) {
			conf_val_next(acl);
			continue;
		}

		/* Check if the address prefix matches. */
		conf_val_t addr_val = conf_id_get(conf(), C_ACL, C_ADDR, acl);
		if (addr_val.code == KNOT_EOK) {
			unsigned prefix;
			struct sockaddr_storage ss;
			ss = conf_net(&addr_val, &prefix);
			if (!netblock_match(addr, &ss, prefix)) {
				conf_val_next(acl);
				continue;
			}
		}

		/* Check if the key matches. */
		conf_val_t key_val = conf_id_get(conf(), C_ACL, C_KEY, acl);
		if (key_val.code == KNOT_EOK) {
			/* No key provided, but required. */
			if (tsig->name == NULL) {
				conf_val_next(acl);
				continue;
			}

			/* Compare key names. */
			const knot_dname_t *key_name = conf_dname(&key_val);
			if (knot_dname_cmp(key_name, tsig->name) != 0) {
				conf_val_next(acl);
				continue;
			}

			/* Compare key algorithms. */
			conf_val_t alg_val = conf_id_get(conf(), C_KEY, C_ALG,
			                                 &key_val);
			if (conf_opt(&alg_val) != tsig->algorithm) {
				conf_val_next(acl);
				continue;
			}
		/* No key required, but provided. */
		} else if (tsig->name != NULL) {
			conf_val_next(acl);
			continue;
		}

		if (deny) {
			conf_val_next(acl);
			continue;
		}

		/* Fill the output with tsig secret. */
		if (tsig->name != NULL) {
			conf_val_t secret_val = conf_id_get(conf(), C_KEY,
			                                    C_SECRET, &key_val);
			conf_data(&secret_val);
			tsig->secret.data = (uint8_t *)secret_val.data;
			tsig->secret.size = secret_val.len;
		}

		return true;
	}

	return false;
}
