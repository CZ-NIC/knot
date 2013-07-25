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

#include "common/acl.h"
#include "libknot/util/endian.h"

static inline uint32_t ipv4_chunk(sockaddr_t *a)
{
	/* Stored as big end first. */
	return a->addr4.sin_addr.s_addr;
}

static inline uint32_t ipv6_chunk(sockaddr_t *a, uint8_t idx)
{
	/* Is byte array, 4x 32bit value. */
	return ((uint32_t *)&a->addr6.sin6_addr)[idx];
}

static inline uint32_t ip_chunk(sockaddr_t *a, uint8_t idx)
{
	if (sockaddr_family(a) == AF_INET)
		return ipv4_chunk(a);

	return ipv6_chunk(a, idx);
}

/*! \brief Compare chunks using given mask. */
static int cmp_chunk(sockaddr_t *a, sockaddr_t *b, uint8_t idx, uint32_t mask)
{
	const uint32_t c1 = ip_chunk(a, idx) & mask;
	const uint32_t c2 = ip_chunk(b, idx) & mask;

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

static int acl_compare(void *k1, void *k2)
{
	int ret = 0;
	sockaddr_t* a1 = (sockaddr_t *)k1;
	sockaddr_t* a2 = (sockaddr_t *)k2;
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

acl_t *acl_new(acl_rule_t default_rule, const char *name)
{
	/* Trailing '\0' for NULL name. */
	size_t name_len = 1;
	if (name) {
		name_len += strlen(name);
	} else {
		name = "";
	}

	/* Allocate memory for ACL. */
	acl_t* acl = malloc(sizeof(acl_t) + name_len);
	if (!acl) {
		return 0;
	}

	/* Initialize skip list. */
	acl->rules = skip_create_list(acl_compare);
	if (!acl->rules) {
		free(acl);
		return 0;
	}

	/* Initialize skip list for rules with TSIG. */
	/*! \todo This needs a better structure to make
	 *        nodes with TSIG preferred, but for now
	 *        it will do to sort nodes into two lists.
	 *        (issue #1675)
	 */
	acl->rules_pref = skip_create_list(acl_compare);
	if (!acl->rules_pref) {
		skip_destroy_list(&acl->rules, 0, free);
		free(acl);
		return 0;
	}

	/* Initialize. */
	memcpy(&acl->name, name, name_len);
	acl->default_rule = default_rule;
	return acl;
}

void acl_delete(acl_t **acl)
{
	if ((acl == NULL) || (*acl == NULL)) {
		return;
	}

	/* Truncate rules. */
	skip_destroy_list(&(*acl)->rules, 0, free);
	skip_destroy_list(&(*acl)->rules_pref, 0, free);

	/* Free ACL. */
	free(*acl);
	*acl = 0;
}

int acl_create(acl_t *acl, const sockaddr_t* addr, acl_rule_t rule, void *val,
               unsigned flags)
{
	if (!acl || !addr) {
		return ACL_ERROR;
	}

	/* Insert into skip list. */
	acl_key_t *key = malloc(sizeof(acl_key_t));
	if (key == NULL) {
		return ACL_ERROR;
	}

	memcpy(&key->addr, addr, sizeof(sockaddr_t));
	key->rule = rule;
	key->val = val;


	if (flags & ACL_PREFER) {
		skip_insert(acl->rules_pref, &key->addr, key, 0);
	} else {
		skip_insert(acl->rules, &key->addr, key, 0);
	}

	return ACL_ACCEPT;
}

int acl_match(acl_t *acl, const sockaddr_t* addr, acl_key_t **key)
{
	if (!acl || !addr) {
		return ACL_ERROR;
	}

	acl_key_t *found = skip_find(acl->rules_pref, (void*)addr);
	if (found == NULL) {
		found = skip_find(acl->rules, (void*)addr);
	}

	/* Set stored value if exists. */
	if (key != NULL) {
		*key = found;
	}

	/* Return appropriate rule. */
	if (found == NULL) {
		return acl->default_rule;
	}

	return found->rule;
}

int acl_truncate(acl_t *acl)
{
	if (acl == NULL) {
		return ACL_ERROR;
	}

	/* Destroy all rules. */
	skip_destroy_list(&acl->rules, 0, free);
	skip_destroy_list(&acl->rules_pref, 0, free);
	acl->rules = skip_create_list(acl_compare);
	acl->rules_pref = skip_create_list(acl_compare);
	if (acl->rules == NULL || acl->rules_pref == NULL) {
		return ACL_ERROR;
	}

	return ACL_ACCEPT;
}
