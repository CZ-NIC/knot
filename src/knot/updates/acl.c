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

#include "common/errcode.h"
#include "knot/updates/acl.h"
#include "libknot/util/endian.h"
#include "libknot/rdata/tsig.h"

static inline uint32_t ipv4_chunk(const struct sockaddr_in *ipv4)
{
	/* Stored as big end first. */
	return ipv4->sin_addr.s_addr;
}

static inline uint32_t ipv6_chunk(const struct sockaddr_in6 *ipv6, uint8_t idx)
{
	/* Is byte array, 4x 32bit value. */
	return ((uint32_t *)&ipv6->sin6_addr)[idx];
}

static inline uint32_t ip_chunk(const struct sockaddr_storage *ss, uint8_t idx)
{
	if (ss->ss_family == AF_INET6) {
		return ipv6_chunk((const struct sockaddr_in6 *)ss, idx);
	} else {
		return ipv4_chunk((const struct sockaddr_in *)ss);
	}
}

/*! \brief Compare chunks using given mask. */
static int cmp_chunk(const netblock_t *a1, const struct sockaddr_storage *a2,
                     uint8_t idx, uint32_t mask)
{
	const uint32_t c1 = ip_chunk(&a1->ss, idx) & mask;
	const uint32_t c2 = ip_chunk(a2, idx) & mask;

	if (c1 > c2)
		return  1;
	if (c1 < c2)
		return -1;
	return 0;
}

/*!
 * \brief Calculate bitmask for byte array from the MSB.
 *
 * \note i.e. 8 means top 8 bits set, 11111111000000000000000000000000
 *
 * \param nbits number of bits set to 1
 * \return mask
 */
static uint32_t acl_fill_mask32(short nbits)
{
	assert(nbits >= 0 && nbits <= 32);
	uint32_t r = 0;
	for (char i = 0; i < nbits; ++i) {
		r |= 1 << (31 - i);
	}

	/* Make sure the mask is in network byte order. */
	return htonl(r);
}

int netblock_match(const netblock_t *a1, const struct sockaddr_storage *a2)
{
	int ret = 0;
	uint32_t mask = 0xffffffff;
	short mask_bits = a1->prefix;
	const short chunk_bits = sizeof(mask) * CHAR_BIT;

	/* Check different length, IPv4 goes first. */
	if (a1->ss.ss_family != a2->ss_family) {
		if (a1->ss.ss_family < a2->ss_family) {
			return -1;
		} else {
			return 1;
		}
	}

	/* At most 4xchunk_bits for IPv6 */
	unsigned i = 0;
	while (ret == 0 && mask_bits > 0) {
		/* Compute mask for current chunk. */
		if (mask_bits <= chunk_bits) {
			mask = acl_fill_mask32(mask_bits);
			mask_bits = 0; /* Last chunk */
		} else {
			mask_bits -= chunk_bits;
		}

		/* Empty mask - shortcut, we're done. */
		if (mask > 0) {
			ret = cmp_chunk(a1, a2, i, mask);
		}
		++i;
	}

	return ret;
}

acl_t *acl_new()
{
	acl_t *acl = malloc(sizeof(acl_t));
	if (acl == NULL) {
		return NULL;
	}

	memset(acl, 0, sizeof(acl_t));
	init_list(acl);
	return acl;
}

void acl_delete(acl_t **acl)
{
	if (acl == NULL || *acl == NULL) {
		return;
	}

	acl_truncate(*acl);

	/* Free ACL. */
	free(*acl);
	*acl = 0;
}

int acl_insert(acl_t *acl, const struct sockaddr_storage *addr, uint8_t prefix, knot_tsig_key_t *key)
{
	if (acl == NULL || addr == NULL) {
		return KNOT_EINVAL;
	}

	/* Create new match. */
	acl_match_t *match = malloc(sizeof(acl_match_t));
	if (match == NULL) {
		return KNOT_ENOMEM;
	}

	match->netblock.prefix = prefix;
	memcpy(&match->netblock.ss, addr, sizeof(struct sockaddr_storage));
	match->key = key;

	add_tail(acl, &match->n);

	return KNOT_EOK;
}

acl_match_t* acl_find(acl_t *acl, const struct sockaddr_storage *addr, const knot_dname_t *key_name)
{
	if (acl == NULL || addr == NULL) {
		return NULL;
	}

	acl_match_t *cur = NULL;
	WALK_LIST(cur, *acl) {
		if (netblock_match(&cur->netblock, addr) == 0) {
			/* NOKEY entry. */
			if (cur->key == NULL) {
				if (key_name == NULL) {
					return cur;
				}
				/* NOKEY entry, but key provided. */
				continue;
			}

			/* NOKEY provided, but key required. */
			if (key_name == NULL) {
				continue;
			}

			/* Key name match. */
			if (knot_dname_is_equal(cur->key->name, key_name)) {
				return cur;
			}
		}
	}

	return NULL;
}

void acl_truncate(acl_t *acl)
{
	if (acl == NULL) {
		return;
	}

	WALK_LIST_FREE(*acl);
}
