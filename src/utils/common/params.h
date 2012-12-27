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
 * \file host_params.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief Host command line parameters.
 *
 * \addtogroup utils
 * @{
 */

#ifndef _UTILS__PARAMS_H_
#define _UTILS__PARAMS_H_

#include <stdbool.h>
#include <stdint.h>

#include "common/lists.h"		// node

#define DEFAULT_UDP_SIZE     	512
#define MAX_PACKET_SIZE     	65535

/*! \brief Structure containing basic parameters for DNS query. */
typedef struct {
	/*!< List node (for list container). */
	node		n;
	/*!< Name to query on. */
	char		*name;
	/*!< Type number to query on. */
	uint16_t	type;
} query_t;

typedef enum {
	IP_ALL,
	IP_4,
	IP_6
} ip_version_t;

typedef enum {
	PROTO_ALL,
	PROTO_TCP,
	PROTO_UDP
} protocol_t;

query_t* create_query(const char *name, const uint16_t type);

void query_free(query_t *query);

int parse_class(const char *class, uint16_t *class_num);

int parse_type(const char *type, int32_t *type_num, int64_t *ixfr_serial);

char* get_reverse_name(const char *name);

#endif // _UTILS__PARAMS_H_

/*! @} */
