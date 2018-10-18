/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef LIBIDN
#include LIBIDN_HEADER
#endif

#include "utils/common/params.h"
#include "utils/common/msg.h"
#include "utils/common/resolv.h"
#include "utils/common/token.h"
#include "libknot/libknot.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/strtonum.h"

#define IPV4_REVERSE_DOMAIN	"in-addr.arpa."
#define IPV6_REVERSE_DOMAIN	"ip6.arpa."

char *name_from_idn(const char *idn_name) {
#ifdef LIBIDN
	char *name = NULL;

	int rc = idna_to_ascii_lz(idn_name, &name, 0);
	if (rc != IDNA_SUCCESS) {
		ERR("IDNA (%s)\n", idna_strerror(rc));
		return NULL;
	}

	return name;
#endif
	return strdup(idn_name);
}

void name_to_idn(char **name) {
#ifdef LIBIDN
	char *idn_name = NULL;

	int rc = idna_to_unicode_8zlz(*name, &idn_name, 0);
	if (rc != IDNA_SUCCESS) {
		return;
	}

	free(*name);
	*name = idn_name;
#endif
	return;
}

/*!
 * \brief Checks if string is a prefix of reference string.
 *
 * \param pref		Prefix string.
 * \param pref_len	Prefix length.
 * \param str		Reference string (must have trailing zero).
 *
 * \retval -1		\a pref is not a prefix of \a str.
 * \retval  0<=		number of chars after prefix \a pref in \a str.
 */
static int cmp_prefix(const char *pref, const size_t pref_len,
                      const char *str)
{
	size_t i = 0;
	while (1) {
		// Different characters => NOT prefix.
		if (pref[i] != str[i]) {
			return -1;
		}

		i++;

		// Pref IS a prefix of pref.
		if (i == pref_len) {
			size_t rest = 0;
			while (str[i + rest] != '\0') {
				rest++;
			}
			return rest;
		// Pref is longer then ref => NOT prefix.
		} else if (str[i] == '\0') {
			return -1;
		}
	}
}

int best_param(const char *str, const size_t str_len, const param_t *tbl,
               bool *unique)
{
	if (str == NULL || str_len == 0 || tbl == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	int best_pos = -1;
	int best_match = INT_MAX;
	size_t matches = 0;
	for (int i = 0; tbl[i].name != NULL; i++) {
		int ret = cmp_prefix(str, str_len, tbl[i].name);
		switch (ret) {
		case -1:
			continue;
		case 0:
			*unique = true;
			return i;
		default:
			if (ret < best_match) {
				best_pos = i;
				best_match = ret;
			}
			matches++;
		}
	}

	switch (matches) {
	case 0:
		return KNOT_ENOTSUP;
	case 1:
		*unique = true;
		return best_pos;
	default:
		*unique = false;
		return best_pos;
	}
}

char *get_reverse_name(const char *name)
{
	struct in_addr	addr4;
	struct in6_addr	addr6;
	int		ret;
	char		buf[128] = "\0";

	if (name == NULL) {
		DBG_NULL;
		return NULL;
	}

	// Check name for IPv4 address, IPv6 address or other.
	if (inet_pton(AF_INET, name, &addr4) == 1) {
		uint32_t num = ntohl(addr4.s_addr);

		// Create IPv4 reverse FQD name.
		ret = snprintf(buf, sizeof(buf), "%u.%u.%u.%u.%s",
		               (num >>  0) & 0xFF, (num >>  8) & 0xFF,
		               (num >> 16) & 0xFF, (num >> 24) & 0xFF,
		               IPV4_REVERSE_DOMAIN);
		if (ret < 0 || (size_t)ret >= sizeof(buf)) {
			return NULL;
		}

		return strdup(buf);
	} else if (inet_pton(AF_INET6, name, &addr6) == 1) {
		char	*pos = buf;
		size_t  len = sizeof(buf);
		uint8_t left, right;

		// Create IPv6 reverse name.
		for (int i = 15; i >= 0; i--) {
			left = ((addr6.s6_addr)[i] & 0xF0) >> 4;
			right = (addr6.s6_addr)[i] & 0x0F;

			ret = snprintf(pos, len, "%x.%x.", right, left);
			if (ret < 0 || (size_t)ret >= len) {
				return NULL;
			}

			pos += ret;
			len -= ret;
		}

		// Add IPv6 reverse domain.
		ret = snprintf(pos, len, "%s", IPV6_REVERSE_DOMAIN);
		if (ret < 0 || (size_t)ret >= len) {
			return NULL;
		}

		return strdup(buf);
	} else {
		return NULL;
	}
}

char *get_fqd_name(const char *name)
{
	char *fqd_name = NULL;

	if (name == NULL) {
		DBG_NULL;
		return NULL;
	}

	size_t name_len = strlen(name);

	// If the name is FQDN, make a copy.
	if (name[name_len - 1] == '.') {
		fqd_name = strdup(name);
	// Else make a copy and append a trailing dot.
	} else {
		size_t fqd_name_size = name_len + 2;
		fqd_name = malloc(fqd_name_size);
		if (fqd_name != NULL) {
			strlcpy(fqd_name, name, fqd_name_size);
			fqd_name[name_len] = '.';
			fqd_name[name_len + 1] = 0;
		}
	}

	return fqd_name;
}

int params_parse_class(const char *value, uint16_t *rclass)
{
	if (value == NULL || rclass == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	if (knot_rrclass_from_string(value, rclass) == 0) {
		return KNOT_EOK;
	} else {
		return KNOT_EINVAL;
	}
}

int params_parse_type(const char *value, uint16_t *rtype, int64_t *serial,
                      bool *notify)
{
	if (value == NULL || rtype == NULL || serial == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Find and parse type name.
	size_t param_pos = strcspn(value, "=");
	char *type_char = strndup(value, param_pos);

	if (knot_rrtype_from_string(type_char, rtype) != 0) {
		size_t cmp_len = MAX(strlen("NOTIFY"), param_pos);
		if (strncasecmp(type_char, "NOTIFY", cmp_len) == 0) {
			*rtype = KNOT_RRTYPE_SOA;
			*notify = true;
		} else {
			free(type_char);
			return KNOT_EINVAL;
		}
	} else {
		*notify = false;
	}

	free(type_char);

	// Parse additional parameter.
	if (param_pos == strlen(value)) {
		// IXFR requires serial parameter.
		if (*rtype == KNOT_RRTYPE_IXFR) {
			DBG("SOA serial is required for IXFR query\n");
			return KNOT_EINVAL;
		} else {
			*serial = -1;
		}
	} else {
		// Additional parameter is accepted for IXFR or NOTIFY.
		if (*rtype == KNOT_RRTYPE_IXFR || *notify) {
			const char *param_str = value + 1 + param_pos;
			char *end;

			// Convert string to serial.
			unsigned long long num = strtoull(param_str, &end, 10);

			// Check for bad serial string.
			if (end == param_str || *end != '\0' || num > UINT32_MAX) {
				DBG("bad SOA serial '%s'\n", param_str);
				return KNOT_EINVAL;
			}

			*serial = num;
		} else {
			DBG("unsupported parameter '%s'\n", value);
			return KNOT_EINVAL;
		}
	}

	return KNOT_EOK;
}

int params_parse_server(const char *value, list_t *servers, const char *def_port)
{
	if (value == NULL || servers == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Add specified nameserver.
	srv_info_t *server = parse_nameserver(value, def_port);
	if (server == NULL) {
		return KNOT_EINVAL;
	}
	add_tail(servers, (node_t *)server);

	return KNOT_EOK;
}

int params_parse_wait(const char *value, int32_t *dst)
{
	if (value == NULL || dst == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	uint32_t num = 0;
	int ret = str_to_u32(value, &num);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Check for minimal value.
	if (num < 1) {
		num = 1;
	// Reduce maximal value. Poll takes signed int in milliseconds.
	} else if (num > INT32_MAX / 1000) {
		num = INT32_MAX / 1000;
	}

	*dst = num;

	return KNOT_EOK;
}
