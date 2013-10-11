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

#include <config.h>
#include "utils/common/resolv.h"

#include <stdio.h>			// fopen
#include <stdlib.h>			// free

#include "common/lists.h"		// list
#include "common/errcode.h"		// KNOT_ENOENT
#include "utils/common/msg.h"		// DBG_NULL
#include "utils/common/params.h"	// DEFAULT_IPV6_NAME

#define RESOLV_FILE	"/etc/resolv.conf"

server_t* parse_nameserver(const char *nameserver, const char *def_port)
{
	if (nameserver == NULL || def_port == NULL) {
		DBG_NULL;
		return NULL;
	}

	// OpenBSD notation: nameserver [address]:port
	if (nameserver[0] == '[') {
		char *addr, *port;

		char   *start = (char *)nameserver + 1;
		char   *end = index(nameserver, ']');
		size_t addr_len = end - start;

		// Missing closing bracket -> stop processing.
		if (end == NULL) {
			return NULL;
		}

		// Fill enclosed address.
		addr = strndup(start, addr_len);

		// Find possible port.
		start += addr_len + 1;
		if (strlen(start) > 0) {
			// Check for colon separation.
			if (*start != ':') {
				free(addr);
				return NULL;
			}

			size_t port_len = strlen(++start);

			// Check port string length.
			if (port_len == 0 || port_len >= sizeof(port)) {
				free(addr);
				return NULL;
			}

			// Fill port part.
			port = strdup(start);
		} else {
			port = strdup(def_port);
		}

		// Create server structure.
		server_t *server = server_create(addr, port);

		free(addr);
		free(port);

		return server;
	} else {
		return server_create(nameserver, def_port);
	}
}

static int get_resolv_nameservers(list_t *servers, const char *def_port)
{
	char	line[512];

	// Open config file.
	FILE *f = fopen(RESOLV_FILE, "r");

	// Check correct open.
	if (f == NULL) {
		return KNOT_ENOENT;
	}

	// Read lines from config file.
	while (fgets(line, sizeof(line), f) != NULL) {
		size_t len;
		char   *pos = line;
		char   *option, *value;

		// Find leading white characters.
		len = strspn(pos, SEP_CHARS);
		pos += len;

		// Start of the first token.
		option = pos;

		// Find length of the token.
		len = strcspn(pos, SEP_CHARS);
		pos += len;

		// Check if the token is not empty.
		if (len <= 0) {
			continue;
		}

		// Find separating white characters.
		len = strspn(pos, SEP_CHARS);
		pos += len;

		// Check if there is a separation between tokens.
		if (len <= 0) {
			continue;
		}

		// Copy of the second token.
		value = strndup(pos, strcspn(pos, SEP_CHARS));

		// Process value with respect to option name.
		if (strncmp(option, "nameserver", strlen("nameserver")) == 0) {
			server_t *server;

			server = parse_nameserver(value, def_port);

			// If value is correct, add nameserver to the list.
			if (server != NULL) {
				add_tail(servers, (node_t *)server);
			}
		}

		// Drop value string.
		free(value);
	}

	// Close config file.
	fclose(f);

	// Return number of servers.
	return list_size(servers);
}

int get_nameservers(list_t *servers, const char *def_port)
{
	if (servers == NULL || def_port == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Initialize list of servers.
	init_list(servers);

	// Read nameservers from resolv file.
	int ret = get_resolv_nameservers(servers, def_port);

	// If found nameservers or error.
	if (ret != 0) {
		return ret;
	// If no nameservers.
	} else {
		server_t *server;

		// Add default ipv6 nameservers.
		server = server_create(DEFAULT_IPV6_NAME, def_port);

		if (server != NULL) {
			add_tail(servers, (node_t *)server);
		}

		// Add default ipv4 nameservers.
		server = server_create(DEFAULT_IPV4_NAME, def_port);

		if (server != NULL) {
			add_tail(servers, (node_t *)server);
		}

		return list_size(servers);
	}
}
