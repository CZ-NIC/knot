/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils/common/resolv.h"
#include "utils/common/msg.h"
#include "utils/common/params.h"
#include "libknot/libknot.h"
#include "contrib/ucw/lists.h"

#define RESOLV_FILE	"/etc/resolv.conf"

srv_info_t* parse_nameserver(const char *str, const char *def_port)
{
	char *host = NULL, *port = NULL;
	const char *addr = NULL, *sep = NULL;
	size_t addr_len = 0;
	char separator = ':';

	if (str == NULL || def_port == NULL) {
		DBG_NULL;
		return NULL;
	}

	const size_t str_len = strlen(str);
	const char *str_end = str + str_len;

	// [address]:port notation.
	if (*str == '[') {
		addr = str + 1;
		const char *addr_end = strchr(addr, ']');
		// Missing closing bracket -> stop processing.
		if (addr_end == NULL) {
			return NULL;
		}
		addr_len = addr_end - addr;
		str += 1 + addr_len + 1;
	// Address@port notation.
	} else if ((sep = strchr(str, '@')) != NULL) {
		addr = str;
		addr_len = sep - addr;
		str += addr_len;
		separator = '@';
	// Address#port notation.
	} else if ((sep = strchr(str, '#')) != NULL) {
		addr = str;
		addr_len = sep - addr;
		str += addr_len;
		separator = '#';
	// IPv4:port notation.
	} else if ((sep = strchr(str, ':')) != NULL) {
		addr = str;
		// Not IPv4 address -> no port.
		if (strchr(sep + 1, ':') != NULL) {
			addr_len = str_len;
			str = str_end;
		} else {
			addr_len = sep - addr;
			str += addr_len;
		}
	// No port specified.
	} else {
		addr = str;
		addr_len = str_len;
		str = str_end;
	}

	// Process port.
	if (str < str_end) {
		// Check port separator.
		if (*str != separator) {
			return NULL;
		}
		str++;

		// Check for missing port.
		if (str >= str_end) {
			return NULL;
		}

		port = strdup(str);
	} else {
		port = strdup(def_port);
	}

	host = strndup(addr, addr_len);

	// Create server structure.
	srv_info_t *server = srv_info_create(host, port);

	free(host);
	free(port);

	return server;
}

static size_t get_resolv_nameservers(list_t *servers, const char *def_port)
{
	char	line[512];

	// Open config file.
	FILE *f = fopen(RESOLV_FILE, "r");
	if (f == NULL) {
		return 0;
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
		if (len == 0) {
			continue;
		}

		// Find separating white characters.
		len = strspn(pos, SEP_CHARS);
		pos += len;

		// Check if there is a separation between tokens.
		if (len == 0) {
			continue;
		}

		// Copy of the second token.
		value = strndup(pos, strcspn(pos, SEP_CHARS));

		// Process value with respect to option name.
		if (strncmp(option, "nameserver", strlen("nameserver")) == 0) {
			srv_info_t *server;

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

void get_nameservers(list_t *servers, const char *def_port)
{
	if (servers == NULL || def_port == NULL) {
		DBG_NULL;
		return;
	}

	// Initialize list of servers.
	init_list(servers);

	// Read nameservers from resolv file or use the default ones.
	if (get_resolv_nameservers(servers, def_port) == 0) {
		srv_info_t *server;

		// Add default ipv6 nameservers.
		server = srv_info_create(DEFAULT_IPV6_NAME, def_port);

		if (server != NULL) {
			add_tail(servers, (node_t *)server);
		}

		// Add default ipv4 nameservers.
		server = srv_info_create(DEFAULT_IPV4_NAME, def_port);

		if (server != NULL) {
			add_tail(servers, (node_t *)server);
		}
	}
}
