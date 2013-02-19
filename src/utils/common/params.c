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

/* FreeBSD POSIX2008 getline() */
#ifndef _WITH_GETLINE
 #define _WITH_GETLINE
#endif

#include "utils/common/params.h"

#include <stdio.h>
#include <stdlib.h>			// free
#include <netinet/in.h>			// in_addr
#include <arpa/inet.h>			// inet_pton
#include <sys/socket.h>			// AF_INET (BSD)

#include "common/errcode.h"		// KNOT_EOK
#include "common/mempattern.h"		// strcdup
#include "libknot/dname.h"		// knot_dname_t
#include "libknot/util/descriptor.h"	// KNOT_RRTYPE
#include "utils/common/msg.h"		// WARN
#include "utils/common/resolv.h"	// parse_nameserver
#include "utils/common/token.h"		// token

#define IPV4_REVERSE_DOMAIN	"in-addr.arpa."
#define IPV6_REVERSE_DOMAIN	"ip6.arpa."

const style_t DEFAULT_STYLE = {
	.format = FORMAT_VERBOSE,
	.show_header = true,
	.show_footer = true,
	.show_query = false,
	.show_question = true,
	.show_answer = true,
	.show_authority = true,
	.show_additional = true,
	.show_class = true,
	.show_ttl = true,
};

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

/* Table of known keys in private-key-format */
static const char *pkey_tbl[] = {
	"\x09" "Activate:",
	"\x0a" "Algorithm:",
	"\x05" "Bits:",
	"\x08" "Created:",
	"\x04" "Key:",
	"\x13" "Private-key-format:",
	"\x08" "Publish:",
	NULL
};

enum {
	T_PKEY_ACTIVATE = 0,
	T_PKEY_ALGO,
	T_PKEY_BITS,
	T_PKEY_CREATED,
	T_PKEY_KEY,
	T_PKEY_FORMAT,
	T_PKEY_PUBLISH
};

static int params_parse_keyline(char *lp, int len, void *arg)
{
	/* Discard nline */
	if (lp[len - 1] == '\n') {
		lp[len - 1] = '\0';
		len -= 1;
	}

	knot_key_t *key = (knot_key_t *)arg;
	int lpm = -1;
	int bp = 0;
	if ((bp = tok_scan(lp, pkey_tbl, &lpm)) < 0) {
		DBG("%s: unknown token on line '%s', ignoring\n", __func__, lp);
		return KNOT_EOK;
	}

	/* Found valid key. */
	const char *k = pkey_tbl[bp];
	char *v = (char *)tok_skipspace(lp + TOK_L(k));
	size_t vlen = 0;
	uint32_t n = 0;
	switch(bp) {
	case T_PKEY_ALGO:
		vlen = strcspn(v, SEP_CHARS);
		v[vlen] = '\0'; /* Term after first tok */
		if (params_parse_num(v, &n) != KNOT_EOK) {
			return KNOT_EPARSEFAIL;
		}
		key->algorithm = n;
		DBG("%s: algo = %u\n", __func__, n);
		break;
	case T_PKEY_KEY:
		if (key->secret) free(key->secret);
		key->secret = strndup(v, len);
		DBG("%s: secret = '%s'\n", __func__, key->secret);
		break;
	default:
		DBG("%s: %s = '%s' (ignoring)\n", __func__, TOK_S(k), v);
		break;
	}

	return KNOT_EOK;
}

char* get_reverse_name(const char *name)
{
	struct in_addr	addr4;
	struct in6_addr	addr6;
	char		buf[128] = "\0";

	if (name == NULL) {
		DBG_NULL;
		return NULL;
	}

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
		DBG_NULL;
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

int params_parse_type(const char *value, uint16_t *rtype, uint32_t *xfr_serial)
{
	if (value == NULL || rtype == NULL || xfr_serial == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	size_t param_pos = strcspn(value, "=");

	// There is no additional parameter.
	if (param_pos == strlen(value)) {
		if (knot_rrtype_from_string(value, rtype) != 0) {
			return KNOT_EINVAL;
		}

		// IXFR requires serial parameter.
		if (*rtype == KNOT_RRTYPE_IXFR) {
			DBG("SOA serial is required for IXFR query\n");
			return KNOT_EINVAL;
		}
	} else {
		char *type_char = strndup(value, param_pos);

		if (knot_rrtype_from_string(type_char, rtype) != 0) {
			free(type_char);
			return KNOT_EINVAL;
		}

		free(type_char);

		// Additional parameter is accepted for IXFR only.
		if (*rtype == KNOT_RRTYPE_IXFR) {
			const char *param_str = value + 1 + param_pos;
			char *end;

			// Convert string to serial.
			unsigned long serial = strtoul(param_str, &end, 10);

			// Check for bad serial string.
			if (end == param_str || *end != '\0' ||
			    serial > UINT32_MAX) {
				DBG("bad SOA serial %s\n", param_str);
				return KNOT_EINVAL;
			}

			*xfr_serial = serial;
		} else {
			char buf[64] = "";
			knot_rrtype_to_string(*rtype, buf, sizeof(buf));
			DBG("type %s can't have a parameter\n", buf);
			return KNOT_EINVAL;
		}
	}

	return KNOT_EOK;
}

int params_parse_server(const char *value, list *servers, const char *def_port)
{
	if (value == NULL || servers == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Add specified nameserver.
	server_t *server = parse_nameserver(value, def_port);
	if (server == NULL) {
		ERR("bad nameserver %s\n", value);
		return KNOT_EINVAL;
	}
	add_tail(servers, (node *)server);

	return KNOT_EOK;
}

int params_parse_wait(const char *value, int32_t *dst)
{
	char *end;

	if (value == NULL || dst == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	/* Convert string to number. */
	long num = strtol(value, &end, 10);

	/* Check for bad string (empty or incorrect). */
	if (end == value || *end != '\0') {
		ERR("bad time value %s\n", value);
		return KNOT_EINVAL;
	} else if (num < 1) {
		num = 1;
		WARN("time %s is too short, using %ld instead\n", value, num);
	/* Reduce maximal value. Poll takes signed int in milliseconds. */
	} else if (num > INT32_MAX) {
		num = INT32_MAX / 1000;
		WARN("time %s is too big, using %ld instead\n", value, num);
	}

	*dst = num;

	return KNOT_EOK;
}

int params_parse_num(const char *value, uint32_t *dst)
{
	char *end;

	if (value == NULL || dst == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Convert string to number.
	unsigned long num = strtoul(value, &end, 10);

	// Check for bad string.
	if (end == value || *end != '\0') {
		ERR("bad number %s\n", value);
		return KNOT_EINVAL;
	}

	if (num > UINT32_MAX) {
		num = UINT32_MAX;
		WARN("number %s is too big, using %lu instead\n", value, num);
	}

	*dst = num;

	return KNOT_EOK;
}

int params_parse_bufsize(const char *value, int32_t *dst)
{
	char *end;

	if (value == NULL || dst == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Convert string to number.
	unsigned long num = strtoul(value, &end, 10);

	// Check for bad string.
	if (end == value || *end != '\0') {
		ERR("bad size %s\n", value);
		return KNOT_EINVAL;
	}

	if (num > UINT16_MAX) {
		num = UINT16_MAX;
		WARN("size %s is too big, using %lu instead\n", value, num);
	}

	*dst = num;

	return KNOT_EOK;
}

int params_parse_tsig(const char *value, knot_key_t *key)
{
	if (value == NULL || key == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

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

	if (!s) {
		ERR("invalid key option format, use [hmac:]keyname:secret\n");
		free(h);
		return KNOT_EINVAL;
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

int params_parse_keyfile(const char *filename, knot_key_t *key)
{
	int ret = KNOT_EOK;

	if (filename == NULL || key == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	/*! \todo #2360 read key name from RR record in .key file */

	/* Fetch keyname from filename. */
	const char *bn = strrchr(filename, '/');
	if (!bn) bn = filename;
	else     ++bn; /* Skip final slash */
	if (*bn == 'K') ++bn; /* Skip K */
	const char* np = strchr(bn, '+');
	if (np) { /* Attempt to extract dname */
		key->name = knot_dname_new_from_str(bn, np-bn, NULL);
	}
	if (!key->name) {
		ERR("keyfile not in format K{name}.+157+{rnd}.private\n");
		return KNOT_ERROR;
	}

	FILE *fp = fopen(filename, "r"); /* Open file */
	if (!fp) {
		ERR("could not open key file '%s': %s\n",
		    filename, strerror(errno));
		return KNOT_ERROR;
	}

	/* Set defaults. */
	key->algorithm = KNOT_TSIG_ALG_HMAC_MD5;

	/* Parse lines. */
	ret = tok_process_lines(fp, params_parse_keyline, key);

	fclose(fp);
	return ret;
}

