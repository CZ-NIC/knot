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
#include "common/acl.h"
#include "libknot/util/endian.h"

static inline uint32_t ipv4_chunk(const sockaddr_t *a)
{
	/* Stored as big end first. */
	return a->addr4.sin_addr.s_addr;
}

static inline uint32_t ipv6_chunk(const sockaddr_t *a, uint8_t idx)
{
	/* Is byte array, 4x 32bit value. */
	return ((uint32_t *)&a->addr6.sin6_addr)[idx];
}

static inline uint32_t ip_chunk(const sockaddr_t *a, uint8_t idx)
{
	if (sockaddr_family(a) == AF_INET)
		return ipv4_chunk(a);

	return ipv6_chunk(a, idx);
}

/*! \brief Compare chunks using given mask. */
static int cmp_chunk(const sockaddr_t *a1, const sockaddr_t *a2,
                     uint8_t idx, uint32_t mask)
{
	const uint32_t c1 = ip_chunk(a1, idx) & mask;
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

static int acl_compare(const sockaddr_t *a1, const sockaddr_t *a2)
{
	int ret = 0;
	uint32_t mask = 0xffffffff;
	short mask_bits = a1->prefix;
	const short chunk_bits = sizeof(mask) * CHAR_BIT;

	/* Check different length, IPv4 goes first. */
	if (a1->len != a2->len) {
		if (a1->len < a2->len)
			return -1;
		else
			return 1;
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
		if (mask > 0)
			ret = cmp_chunk(a1, a2, i, mask);
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

int acl_insert(acl_t *acl, const sockaddr_t *addr, void *val)
{
	if (acl == NULL || addr == NULL) {
		return KNOT_EINVAL;
	}

	/* Create new match. */
	acl_match_t *key = malloc(sizeof(acl_match_t));
	if (key == NULL) {
		return KNOT_ENOMEM;
	}

	memcpy(&key->addr, addr, sizeof(sockaddr_t));
	key->val = val;

	/* Sort by prefix length.
	 * This way the longest prefix match always goes first.
	 */
	if (EMPTY_LIST(*acl)) {
		add_head(acl, &key->n);
	} else {
		bool inserted = false;
		acl_match_t *cur = NULL, *prev = NULL;
		WALK_LIST(cur, *acl) {
			/* Next node prefix is equal/shorter than current key.
			 * This means we need to insert before the next node.
			 */
			if (cur->addr.prefix < addr->prefix) {
				if (prev == NULL) { /* First node. */
					add_head(acl, &key->n);
				} else {
					insert_node(&key->n, &prev->n);
				}
				inserted = true;
				break;
			}
			prev = cur;
		}

		/* Didn't find any better fit, insert at the end. */
		if (!inserted) {
			add_tail(acl, &key->n);
		}
	}

	return KNOT_EOK;
}

acl_match_t* acl_find(acl_t *acl, const sockaddr_t *addr)
{
	if (acl == NULL || addr == NULL) {
		return NULL;
	}

	acl_match_t *cur = NULL;
	WALK_LIST(cur, *acl) {
		/* Since the list is sorted by prefix length, the first match
		 * is guaranteed to be longest prefix match (most precise).
		 */
		if (acl_compare(&cur->addr, addr) == 0) {
			return cur;
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
