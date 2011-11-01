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

#include "common/acl.h"

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
	if (a1->len == sizeof(struct sockaddr_in)) {

		/* Allow if k1 == INADDR_ANY. */
		if (a1->addr4.sin_addr.s_addr == 0) {
			return 0;
		}

		/* Compare address. */
		ldiff = a1->addr4.sin_addr.s_addr - a2->addr4.sin_addr.s_addr;
		if (ldiff != 0) {
			return ldiff < 0 ? -1 : 1;
		}

		/* Port = 0 means any port match. */
		if (a1->addr4.sin_port == 0) {
			return 0;
		}

		/* Compare ports on address match. */
		ldiff = ntohs(a1->addr4.sin_port) - ntohs(a2->addr4.sin_port);
		if (ldiff != 0) {
			return ldiff < 0 ? -1 : 1;
		}
		return 0;
	}

	/* IPv6 matching. */
#ifndef DISABLE_IPV6
	if (a1->len == sizeof(struct sockaddr_in6)) {

		/* Compare address. */
		/*! \todo Maybe use memcmp()? */
		ldiff = 0;
		const unsigned int *a6 = (const unsigned int *)&a1->addr6.sin6_addr;
		const unsigned int *b6 = (const unsigned int *)&a2->addr6.sin6_addr;
		for (int i = 0; i <  (sizeof(struct in6_addr)/ sizeof(int)) ; ++i) {
			ldiff = a6[i] - b6[i];
			if (ldiff < 0) {
				return -1;
			}
			if (ldiff > 0) {
				return 1;
			}
		}

		/* Port = 0 means any port match. */
		if (a1->addr6.sin6_port == 0) {
			return 0;
		}

		/* Compare ports on address match. */
		ldiff = ntohs(a1->addr6.sin6_port) - ntohs(a2->addr6.sin6_port);
		if (ldiff != 0) {
			return ldiff < 0 ? -1 : 1;
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
	if (acl_truncate(*acl) != ACL_ACCEPT) {
		return;
	}

	/* Free ACL. */
	free(*acl);
	*acl = 0;
}

int acl_create(acl_t *acl, const sockaddr_t* addr, acl_rule_t rule)
{
	if (!acl || !addr || rule < 0) {
		return ACL_ERROR;
	}

	/* Insert into skip list. */
	sockaddr_t *key = malloc(sizeof(sockaddr_t));
	memcpy(key, addr, sizeof(sockaddr_t));

	skip_insert(acl->rules, key, (void*)((ssize_t)rule + 1), 0);

	return ACL_ACCEPT;
}

int acl_match(acl_t *acl, sockaddr_t* addr)
{
	if (!acl || !addr) {
		return ACL_ERROR;
	}

	/* Return default rule if not found.
	 * Conversion to the same length integer is made,
	 * but we can be sure, that the value range is within <-1,1>.
	 */
	ssize_t val = ((ssize_t)skip_find(acl->rules, addr)) - 1;
	if (val < 0) {
		return acl->default_rule;
	}

	/* Return stored rule if found. */
	return (int)val;
}

int acl_truncate(acl_t *acl)
{
	if (acl == NULL) {
		return ACL_ERROR;
	}

	/* Destroy all rules. */
	skip_destroy_list(&acl->rules, free, 0);

	return ACL_ACCEPT;
}
