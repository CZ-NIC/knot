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

#include "utils/common/params.h"

#include <stdlib.h>			// free

#include "common/errcode.h"		// KNOT_EOK
#include "libknot/util/descriptor.h"	// KNOT_RRTYPE
#include "utils/common/msg.h"		// WARN
#include "utils/common/netio.h"

#define IPV4_REVERSE_DOMAIN	"in-addr.arpa."
#define IPV6_REVERSE_DOMAIN	"ip6.arpa."
#define ASCII_0			48

query_t* create_query(const char *name, const uint16_t type)
{
	// Create output structure.
	query_t *query = calloc(1, sizeof(query_t));

	// Check output.
	if (query == NULL) {
		return NULL;
	}

	// Fill output.
	query->name = strdup(name);
	query->type = type;

	return query;
}

void query_free(query_t *query)
{
	if (query == NULL) {
		return;
	}

	free(query->name);
	free(query);
}

int parse_class(const char *class, uint16_t *class_num)
{
	*class_num = knot_rrclass_from_string(class);

	return KNOT_EOK;
}

int parse_type(const char *type, int32_t *type_num, int64_t *ixfr_serial)
{
	size_t param_pos = strcspn(type, "=");

	// There is no additional parameter.
	if (param_pos == strlen(type)) {
		*type_num = knot_rrtype_from_string(type);

		// IXFR requires serial parameter.
		if (*type_num == KNOT_RRTYPE_IXFR) {
			ERR("required SOA serial for IXFR query\n");
			return KNOT_ERROR;
		}
	} else {
		char *type_char = strndup(type, param_pos);

		*type_num = knot_rrtype_from_string(type_char);

		free(type_char);

		// Additional parameter is acceptet for IXFR only.
		if (*type_num == KNOT_RRTYPE_IXFR) {
			const char *param_str = type + 1 + param_pos;
			char *end;

			// Convert string to serial.
			unsigned long serial = strtoul(param_str, &end, 10);

			// Check for bad serial string.
			if (end == param_str || *end != '\0' ||
			    serial > UINT32_MAX) {
				ERR("bad SOA serial in IXFR query\n");
				return KNOT_ERROR;
			}

			*ixfr_serial = serial;
		} else {
			char buf[64] = "";
			knot_rrtype_to_string(*type_num, buf, sizeof(buf));
			ERR("type %s can't have a parameter\n", buf);
			return KNOT_ERROR;
		}
	}

	return KNOT_EOK;
}

char* get_reverse_name(const char *name)
{
	struct in_addr	addr4;
	struct in6_addr	addr6;
	char		buf[128] = "\0";

        // Check name for IPv4 address, IPv6 address or other.
	if (inet_pton(AF_INET, name, &addr4) == 1) {
		uint32_t num = ntohl(addr4.s_addr);

		// Create IPv4 reverse FQD name.
		sprintf(buf, "%u.%u.%u.%u.%s",
		        (num >>  0) & 0xFF, (num >>  8) & 0xFF,
		        (num >> 16) & 0xFF, (num >> 24) & 0xFF,
		        IPV4_REVERSE_DOMAIN);

		return strdup(buf);
	} else if (inet_pton(AF_INET6, name, &addr6) == 1) {
		char	*pos = buf;
		uint8_t left, right;

		// Create IPv6 reverse name.
		for (int i = 15; i >= 0; i--) {
			left = ((addr6.s6_addr)[i] & 0xF0) >> 4;
			right = (addr6.s6_addr)[i] & 0x0F;
			pos += sprintf(pos, "%x.%x.", right, left);
		}

		// Add IPv6 reverse domain.
		strcat(buf, IPV6_REVERSE_DOMAIN);

		return strdup(buf);
	} else {
		return NULL;
	}
}

