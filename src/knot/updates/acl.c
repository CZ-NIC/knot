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
#include "libknot/yparser/yptrafo.h"

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
                    int prefix)
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
		if (prefix < 0 || prefix > IPV4_PREFIXLEN) {
			prefix = IPV4_PREFIXLEN;
		}
		break;
	case AF_INET6:
		addr1 = ipv6_addr(ss1);
		addr2 = ipv6_addr(ss2);
		if (prefix < 0 || prefix > IPV6_PREFIXLEN) {
			prefix = IPV6_PREFIXLEN;
		}
		break;
	default:
		return false;
	}

	/* Compare full bytes address block. */
	uint8_t full_bytes = prefix / 8;
	if (memcmp(addr1, addr2, full_bytes) != 0) {
		return false;
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

bool netrange_match(const struct sockaddr_storage *ss,
                    const struct sockaddr_storage *ss_min,
                    const struct sockaddr_storage *ss_max)
{
	if (ss == NULL || ss_min == NULL || ss_max == NULL) {
		return false;
	}

	assert(ss_min->ss_family == ss_max->ss_family);

	if (sockaddr_cmp(ss, ss_min) < 0 || sockaddr_cmp(ss, ss_max) > 0) {
		return false;
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
		conf_val_t val;

		/* Check if the address matches the current acl address list. */
		val = conf_id_get(conf(), C_ACL, C_ADDR, acl);
		while (val.code == KNOT_EOK) {
			struct sockaddr_storage ss, ss_max;
			int prefix;

			ss = conf_addr_range(&val, &ss_max, &prefix);
			if (ss_max.ss_family == AF_UNSPEC) {
				if (!netblock_match(addr, &ss, prefix)) {
					conf_val_next(&val);
					continue;
				}
			} else {
				if (!netrange_match(addr, &ss, &ss_max)) {
					conf_val_next(&val);
					continue;
				}
			}

			break;
		}
		/* Check for address match or empty list. */
		if (val.code != KNOT_EOK && val.code != KNOT_ENOENT) {
			goto next_acl;
		}

		/* Check if the key matches the current acl key list. */
		conf_val_t key_val = conf_id_get(conf(), C_ACL, C_KEY, acl);
		while (key_val.code == KNOT_EOK) {
			/* No key provided, but required. */
			if (tsig->name == NULL) {
				conf_val_next(&key_val);
				continue;
			}

			/* Compare key names. */
			const knot_dname_t *key_name = conf_dname(&key_val);
			if (knot_dname_cmp(key_name, tsig->name) != 0) {
				conf_val_next(&key_val);
				continue;
			}

			/* Compare key algorithms. */
			conf_val_t alg_val = conf_id_get(conf(), C_KEY, C_ALG,
			                                 &key_val);
			if (conf_opt(&alg_val) != tsig->algorithm) {
				conf_val_next(&key_val);
				continue;
			}

			break;
		}
		/* Check for key match or empty list without key provided. */
		if (key_val.code != KNOT_EOK &&
		    !(key_val.code == KNOT_ENOENT && tsig->name == NULL)) {
			goto next_acl;
		}

		/* Check if the action is allowed. */
		if (action != ACL_ACTION_NONE) {
			val = conf_id_get(conf(), C_ACL, C_ACTION, acl);
			while (val.code == KNOT_EOK) {
				if (conf_opt(&val) != action) {
					conf_val_next(&val);
					continue;
				}

				break;
			}
			/* Check for action match. */
			if (val.code != KNOT_EOK) {
				goto next_acl;
			}
		}

		/* Check if denied. */
		val = conf_id_get(conf(), C_ACL, C_DENY, acl);
		if (conf_bool(&val)) {
			return false;
		}

		/* Fill the output with tsig secret if provided. */
		if (tsig->name != NULL) {
			val = conf_id_get(conf(), C_KEY, C_SECRET, &key_val);
			tsig->secret.data = (uint8_t *)conf_bin(&val, &tsig->secret.size);
		}

		return true;
next_acl:
		conf_val_next(acl);
	}

	return false;
}
