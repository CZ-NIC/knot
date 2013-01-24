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
#include <netinet/in.h>                 // in_addr
#include <arpa/inet.h>			// inet_pton
#include <sys/socket.h>			// AF_INET (BSD)

#include "common/errcode.h"		// KNOT_EOK
#include "common/mempattern.h"		// strcdup
#include "libknot/util/descriptor.h"	// KNOT_RRTYPE
#include "utils/common/msg.h"		// WARN
#include "libknot/dname.h"

#define IPV4_REVERSE_DOMAIN	"in-addr.arpa."
#define IPV6_REVERSE_DOMAIN	"ip6.arpa."

static knot_dname_t* create_fqdn_from_str(const char *str, size_t len)
{
	knot_dname_t *d = NULL;
	if (str[len - 1] != '.') {
		char *fqdn = strcdup(str, ".");
		d = knot_dname_new_from_str(fqdn, len + 1, NULL);
		free(fqdn);
	} else {
		d = knot_dname_new_from_str(str, len, NULL);
	}
	return d;
}

query_t* query_create(const char *name, const uint16_t type)
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
	query->xfr_serial = -1;

	return query;
}

void query_set_serial(query_t *query, const uint32_t serial)
{
	query->xfr_serial = serial;
}

void query_free(query_t *query)
{
	if (query == NULL) {
		return;
	}

	free(query->name);
	free(query);
}

int parse_class(const char *rclass, uint16_t *class_num)
{
	*class_num = knot_rrclass_from_string(rclass);

	return KNOT_EOK;
}

int parse_type(const char *rtype, int32_t *type_num, int64_t *xfr_serial)
{
	size_t param_pos = strcspn(rtype, "=");

	// There is no additional parameter.
	if (param_pos == strlen(rtype)) {
		*type_num = knot_rrtype_from_string(rtype);

		// IXFR requires serial parameter.
		if (*type_num == KNOT_RRTYPE_IXFR) {
			ERR("required SOA serial for IXFR query\n");
			return KNOT_ERROR;
		}
	} else {
		char *type_char = strndup(rtype, param_pos);

		*type_num = knot_rrtype_from_string(type_char);

		free(type_char);

		// Additional parameter is acceptet for IXFR only.
		if (*type_num == KNOT_RRTYPE_IXFR) {
			const char *param_str = rtype + 1 + param_pos;
			char *end;

			// Convert string to serial.
			unsigned long serial = strtoul(param_str, &end, 10);

			// Check for bad serial string.
			if (end == param_str || *end != '\0' ||
			    serial > UINT32_MAX) {
				ERR("bad SOA serial in IXFR query\n");
				return KNOT_ERROR;
			}

			*xfr_serial = serial;
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

char* get_fqd_name(const char *name)
{
	char *fqd_name = NULL;

	if (name == NULL) {
		return NULL;
	}

	// If name is FQD, make copy.
	if (name[strlen(name) - 1] == '.') {
		fqd_name = strdup(name);
	// Else append trailing dot.
	} else {
		fqd_name = malloc(strlen(name) + 2);
		strcpy(fqd_name, name);
		strcat(fqd_name, ".");
	}

	return fqd_name;
}

void params_flag_tcp(params_t *params)
{
	params->protocol = PROTO_TCP;
}

void params_flag_verbose(params_t *params)
{
	params->format = FORMAT_VERBOSE;
	
}

int params_parse_interval(const char *value, int32_t *dst)
{
	char *end;

	/* Convert string to number. */
	long num = strtol(value, &end, 10);

	/* Check for bad string (empty or incorrect). */
	if (end == value || *end != '\0') {
		ERR("bad interval value\n");
		return KNOT_ERROR;
	} else if (num < 1) {
		num = 1;
		WARN("interval is too short, using %ld seconds\n", num);
	/* Reduce maximal value. Poll takes signed int in milliseconds. */
	} else if (num > INT32_MAX) {
		num = INT32_MAX / 1000;
		WARN("interval is too long, using %ld seconds\n", num);
	}

	*dst = num;

	return KNOT_EOK;
}

int params_parse_num(const char *value, uint32_t *dst)
{
	char *end;

	// Convert string to number.
	unsigned long num = strtoul(value, &end, 10);

	// Check for bad string.
	if (end == value || *end != '\0' || num > UINT32_MAX) {
		ERR("bad numeric value\n");
		return KNOT_ERROR;
	}

	*dst = num;

	return KNOT_EOK;
}

int params_parse_tsig(const char *value, knot_key_t *key)
{
	/* Invalidate previous key. */
	if (key->name) {
		knot_dname_free(&key->name);
		key->algorithm = KNOT_TSIG_ALG_NULL;
		free(key->secret);
		key->secret = NULL;
	}
	
	char *h = strdup(value);
	if (!h) {
		return KNOT_ENOMEM;
	}
	
	/* Separate to avoid multiple allocs. */
	char *k = NULL, *s = NULL;
	if ((k = (char*)strchr(h, ':'))) { /* Second part - NAME|SECRET */
		*k++ = '\0';               /* String separator */
		s = (char*)strchr(k, ':'); /* Thirt part - |SECRET */
	}
	
	/* Determine algorithm. */
	key->algorithm = KNOT_TSIG_ALG_HMAC_MD5;
	if (s) {
		*s++ = '\0';               /* Last part separator */
		knot_lookup_table_t *alg = NULL;
		alg = knot_lookup_by_name(tsig_alg_table, h);
		if (alg) {
			DBG("%s: parsed algorithm '%s'\n", __func__, h);
			key->algorithm = alg->id;
		} else {
			ERR("invalid TSIG algorithm name '%s'\n", h);
			free(h);
			return KNOT_EINVAL;
		}
	} else {
		s = k; /* Ignore first part, push down. */
		k = h;
	}
	
	/* Parse key name. */
	key->name = create_fqdn_from_str(k, strlen(k));
	key->secret = strdup(s);
	
	/* Check name and secret. */
	if (!key->name || !key->secret) {
		knot_dname_free(&key->name); /* Sets to NULL */
		free(key->secret);
		key->secret = NULL;
		free(h);
		return KNOT_EINVAL;
	}
	
	DBG("%s: parsed name '%s'\n", __func__, k);
	DBG("%s: parsed secret '%s'\n", __func__, s);
	free(h);
	
	return KNOT_EOK;
}
