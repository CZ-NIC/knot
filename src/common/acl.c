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

#include "common/acl.h"

static inline uint32_t acl_sa_ipv4(sockaddr_t *a) {
	return a->addr4.sin_addr.s_addr;
}

static inline uint32_t acl_fill_mask32(short c) {
	/*! \todo Consider optimizing using LUT. */
	assert(c >= 0 && c <= 32);
	unsigned r = 0;
	/*! This actually builds big-endian mask
	 *  as we will match against addresses in
	 *  network byte-order (big-endian).
	 *  Otherwise it should be built from
	 *  HO bit -> LO bit.
	 */
	for (char i = 0; i < c; ++i) {
		r |= (1 << i);
	}
	return r;
}

static int acl_compare(void *k1, void *k2)
{
	sockaddr_t* a1 = (sockaddr_t *)k1;
	sockaddr_t* a2 = (sockaddr_t *)k2;

	/* Check different length, IPv4 goes first. */
	int ldiff = a1->len - a2->len;
	if (ldiff != 0) {
		return ldiff < 0 ? -1 : 1;
	}

	/* Compare integers if IPv4. */
	if (a1->family == AF_INET) {
		
		/* Compute mask .*/
		uint32_t mask = acl_fill_mask32(a1->prefix);

		/* Compare address. */
		int cmp1 = (acl_sa_ipv4(a1) & mask);
		int cmp2 = (acl_sa_ipv4(a2) & mask);
		if (cmp1 > cmp2) return  1;
		if (cmp1 < cmp2) return -1;
		return 0;
	}

	/* IPv6 matching. */
#ifndef DISABLE_IPV6
	if (a1->family == AF_INET6) {
		
		/* Get mask .*/
		short chunk = a1->prefix;
		
		/* Compare address by 32bit chunks. */
		uint32_t* a1p = (uint32_t *)(&a1->addr6.sin6_addr);
		uint32_t* a2p = (uint32_t *)(&a2->addr6.sin6_addr);
		
		/* Mask 0 = 0 bits to compare from LO->HO (in big-endian).
		 * Mask 128 = 128 bits to compare.
		 */
		while (chunk > 0) {
			uint32_t mask = 0xffffffff;
			if (chunk > sizeof(mask) << 3) {
				chunk -= sizeof(mask) << 3;
			} else {
				mask = acl_fill_mask32(chunk);
				chunk = 0;
			}

			int cmp1 = (*(a1p++) & mask);
			int cmp2 = (*(a2p++) & mask);
			if (cmp1 > cmp2) return  1;
			if (cmp1 < cmp2) return -1;
		}

		return 0;
	}
#endif

	return 0;
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
	sockaddr_update(&key->addr);
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
