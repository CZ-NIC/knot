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
 * \file resolv.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief resolv.conf processing.
 *
 * \addtogroup utils
 * @{
 */

#ifndef _UTILS__RESOLV_H_
#define _UTILS__RESOLV_H_

#include "common/lists.h"		// node

#define DEFAULT_IPV4_NAME       "127.0.0.1"                                     
#define DEFAULT_IPV6_NAME       "::1"
#define SEP_CHARS               "\n\t "

/*! \brief Structure containing nameserver information. */
typedef struct {
	/*!< List node (for list container). */
	node	n;
	/*!< Name or address of the server. */
	char	*name;
	/*!< Name or numbers of the service. */
	char	*service;
} server_t;

server_t* create_server(const char *name, const char *service);

void server_free(server_t *server);

server_t* parse_nameserver(const char *nameserver);

int get_nameservers(list *servers);

#endif // _UTILS__RESOLV_H_

/*! @} */
