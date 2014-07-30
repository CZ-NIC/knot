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
/*!
 * \file acl.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Access control lists.
 *
 * Simple access control list is implemented as a linked list, sorted by
 * prefix length. This way, longest prefix match is always found first.
 *
 * \addtogroup common_lib
 * @{
 */

#pragma once

#include "common-knot/lists.h"
#include "common-knot/sockaddr.h"
#include "libknot/mempattern.h"
#include "libknot/rrtype/tsig.h"

struct conf_iface_t;

/*! \brief Match address against netblock. */
int netblock_match(struct conf_iface_t *a1, const struct sockaddr_storage *a2);

/*!
 * \brief Match address against ACL.
 *
 * \param acl Pointer to ACL instance.
 * \param addr IP address.
 * \param key_name TSIG key name (optional)
 *
 * \retval Matching rule instance if found.
 * \retval NULL if it didn't find a match.
 */
struct conf_iface_t* acl_find(list_t *acl, const struct sockaddr_storage *addr,
                              const knot_dname_t *key_name);

/*! @} */
