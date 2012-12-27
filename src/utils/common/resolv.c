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

#include "utils/common/resolv.h"

#include <stdio.h>			// fopen
#include <stdlib.h>			// free

#include "common/errcode.h"		// KNOT_ENOENT
#include "common/lists.h"		// list

#define RESOLV_FILE		"/etc/resolv.conf"
#define SEP_CHARS		"\n\t "

server_t* create_server(const char *name, const char *service)
{
	// Create output structure.
	server_t *server = calloc(1, sizeof(server_t));

	// Check output.
	if (server == NULL) {
		return NULL;
	}

	// Fill output.
	server->name = strdup(name);
	server->service = strdup(service);

	// Return result.
	return server;
}

server_t* parse_nameserver(const char *nameserver)
{
	char	addr[128];
	char	port[64];

	// Fill nameserver address and port.
	strncpy(addr, nameserver, sizeof(addr));
	addr[sizeof(addr) - 1] = '\0';
	strcpy(port, DEFAULT_DNS_PORT);

	// OpenBSD address + port notation: nameserver [address]:port
	if (nameserver[0] == '[') {
		char *start = (char *)nameserver + 1;
		char *end = index(nameserver, ']');

		// Missing closing bracket -> stop processing.
		if (end == NULL) {
			return NULL;
		}

		// Fill enclosed address.
		strncpy(addr, start, end - start);
		addr[end - start] = '\0';

		// Find possible port.
		start = index(end, ':') + 1;

		// Check port occurence.
		if (start != NULL) {
			// Check port string length.
			if (strlen(start) >= sizeof(port)) {
				return NULL;
			}

			// Fill port part.
			strcpy(port, start);
		}
	}

	return create_server(addr, port);
}

static int get_resolv_nameservers(list *servers)
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
			server_t *server = parse_nameserver(value);

			// If value is correct, add nameserver to the list.
			if (server != NULL) {
				add_tail(servers, (node *)server);
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

int get_nameservers(list *servers)
{
	int ret;

	// Initialize list of servers.
	init_list(servers);

	// Read nameservers from resolv file.
	ret = get_resolv_nameservers(servers);

	// If found nameservers or error.
	if (ret != 0) {
		return ret;
	// If no nameservers.
	} else {
		server_t *server;

		// Add default ipv6 nameservers.
		server = create_server(DEFAULT_IPV6_NAME, DEFAULT_DNS_PORT);

		if (server != NULL) {                                   
			add_tail(servers, (node *)server);              
		}

		// Add default ipv4 nameservers.
		server = create_server(DEFAULT_IPV4_NAME, DEFAULT_DNS_PORT);

		if (server != NULL) {                                   
			add_tail(servers, (node *)server);              
		}

		return list_size(servers);
	}
}

void server_free(server_t *server)
{
	free(server->name);
	free(server->service);
	free(server);
}
