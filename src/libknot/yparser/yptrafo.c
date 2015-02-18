/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "libknot/internal/macros.h"
#include "libknot/yparser/yptrafo.h"
#include "libknot/internal/base64.h"
#include "libknot/internal/sockaddr.h"
#include "libknot/libknot.h"

#define TXT_BIN_PARAMS char const *txt, size_t txt_len, uint8_t *bin, size_t *bin_len
#define BIN_TXT_PARAMS uint8_t const *bin, size_t bin_len, char *txt, size_t *txt_len

enum {
	UNIT_BYTE = 'B',
	UNIT_KILO = 'K',
	UNIT_MEGA = 'M',
	UNIT_GIGA = 'G',
	UNIT_SEC  = 's',
	UNIT_MIN  = 'm',
	UNIT_HOUR = 'h',
	UNIT_DAY  = 'd'
};

enum {
	MULTI_BYTE = 1,
	MULTI_KILO = 1024,
	MULTI_MEGA = 1024 * 1024,
	MULTI_GIGA = 1024 * 1024 * 1024,
	MULTI_SEC  = 1,
	MULTI_MIN  = 60,
	MULTI_HOUR = 3600,
	MULTI_DAY  = 24 * 3600
};

static int yp_str_to_bin(
	TXT_BIN_PARAMS)
{
	if (*bin_len <= txt_len) {
		return KNOT_ESPACE;
	}

	memcpy(bin, txt, txt_len);
	bin[txt_len] = '\0';
	*bin_len = txt_len + 1;

	return KNOT_EOK;
}

static int yp_str_to_txt(
	BIN_TXT_PARAMS)
{
	if (*txt_len < bin_len) {
		return KNOT_ESPACE;
	}

	memcpy(txt, bin, bin_len);
	*txt_len = bin_len - 1;

	return KNOT_EOK;
}

static int yp_bool_to_bin(
	TXT_BIN_PARAMS)
{
	if (strcasecmp(txt, "on") == 0) {
		bin[0] = '\0'; // Just in case.
		*bin_len = 1;
		return KNOT_EOK;
	} else if (strcasecmp(txt, "off") == 0) {
		*bin_len = 0;
		return KNOT_EOK;
	}

	return KNOT_EINVAL;
}

static int yp_bool_to_txt(
	BIN_TXT_PARAMS)
{
	int ret;

	switch (bin_len) {
	case 0:
		ret = snprintf(txt, *txt_len, "off");
		if (ret <= 0 || ret >= *txt_len) {
			return KNOT_ERANGE;
		}
		*txt_len = ret;
		return KNOT_EOK;
	case 1:
		ret = snprintf(txt, *txt_len, "on");
		if (ret <= 0 || ret >= *txt_len) {
			return KNOT_ERANGE;
		}
		*txt_len = ret;
		return KNOT_EOK;
	}

	return KNOT_EINVAL;
}

static int remove_unit(
	int64_t *number,
	char unit,
	yp_style_t style)
{
	int64_t multiplier = 1;

	// Get the multiplier for the unit.
	if (style & YP_SSIZE) {
		switch (unit) {
		case UNIT_BYTE:
			multiplier = MULTI_BYTE;
			break;
		case UNIT_KILO:
			multiplier = MULTI_KILO;
			break;
		case UNIT_MEGA:
			multiplier = MULTI_MEGA;
			break;
		case UNIT_GIGA:
			multiplier = MULTI_GIGA;
			break;
		default:
			return KNOT_ENOTSUP;
		}
	} else if (style & YP_STIME) {
		switch (unit) {
		case UNIT_SEC:
			multiplier = MULTI_SEC;
			break;
		case UNIT_MIN:
			multiplier = MULTI_MIN;
			break;
		case UNIT_HOUR:
			multiplier = MULTI_HOUR;
			break;
		case UNIT_DAY:
			multiplier = MULTI_DAY;
			break;
		default:
			return KNOT_ENOTSUP;
		}
	} else {
		return KNOT_ENOTSUP;
	}

	// Check for possible number overflow.
	if (INT64_MAX / multiplier < (*number >= 0 ? *number : -*number)) {
		return KNOT_ERANGE;
	}

	*number *= multiplier;

	return KNOT_EOK;
}

static int yp_int_to_bin(
	TXT_BIN_PARAMS,
	int64_t min,
	int64_t max,
	uint8_t min_bytes,
	yp_style_t style)
{
	char *end = (char *)txt;

	int64_t number = strtoll(txt, &end, 10);

	// Check if the whole string is invalid.
	if (end == txt) {
		return KNOT_EINVAL;
	}

	// Check the rest of the string for a unit.
	if (*end != '\0') {
		// Check just for one-char rest.
		if (*(end + 1) != '\0') {
			return KNOT_EINVAL;
		}

		// Try to apply the unit on the number.
		if (remove_unit(&number, *end, style) != KNOT_EOK) {
			return KNOT_EINVAL;
		}
	}

	if (number < min || number > max) {
		return KNOT_ERANGE;
	}

	// Convert the number to litte-endian byte order.
	number = htole64(number);

	// Store the result
	memcpy(bin, &number, sizeof(number));
	*bin_len = sizeof(number);

	// Ignore trailing zeroes.
	for (int i = 7; i >= min_bytes; i--) {
		if (((uint8_t *)&number)[i] != 0) {
			break;
		}
		(*bin_len)--;
	}

	return KNOT_EOK;
}

static void add_unit(
	int64_t *number,
	char *unit,
	yp_style_t style)
{
	int64_t new_multi = 1;
	char new_unit = '\0';

	if (*number == 0) {
		return;
	}

	// Get the multiplier for the unit.
	if (style & YP_SSIZE) {
		if (*number < MULTI_KILO) {
			new_multi = MULTI_BYTE;
			new_unit = UNIT_BYTE;
		} else if (*number < MULTI_MEGA) {
			new_multi = MULTI_KILO;
			new_unit = UNIT_KILO;
		} else if (*number < MULTI_GIGA) {
			new_multi = MULTI_MEGA;
			new_unit = UNIT_MEGA;
		} else {
			new_multi = MULTI_GIGA;
			new_unit = UNIT_GIGA;
		}
	} else if (style & YP_STIME) {
		if (*number < MULTI_MIN) {
			new_multi = MULTI_SEC;
			new_unit = UNIT_SEC;
		} else if (*number < MULTI_HOUR) {
			new_multi = MULTI_MIN;
			new_unit = UNIT_MIN;
		} else if (*number < MULTI_DAY) {
			new_multi = MULTI_HOUR;
			new_unit = UNIT_HOUR;
		} else {
			new_multi = MULTI_DAY;
			new_unit = UNIT_DAY;
		}
	}

	if (new_unit != '\0' && (*number % new_multi) == 0) {
		*number /= new_multi;
		*unit = new_unit;
	}
}

static int yp_int_to_txt(
	BIN_TXT_PARAMS,
	yp_style_t style)
{
	int64_t data = 0, number = 0;
	char unit[2] = { '\0' };

	memcpy(&data, bin, bin_len);
	number = le64toh(data);

	add_unit(&number, unit, style);

	int ret = snprintf(txt, *txt_len, "%"PRId64"%s", number, unit);
	if (ret <= 0 || ret >= *txt_len) {
		return KNOT_ERANGE;
	}
	*txt_len = ret;

	return KNOT_EOK;
}

static int addr_to_bin(
	TXT_BIN_PARAMS,
	bool allow_unix)
{
	struct in_addr  addr4;
	struct in6_addr addr6;

	uint8_t type;
	size_t addr_len;
	const void *addr;

	if (inet_pton(AF_INET, txt, &addr4) == 1) {
		type = 4;
		addr_len = sizeof(addr4.s_addr);
		addr = &(addr4.s_addr);
	} else if (inet_pton(AF_INET6, txt, &addr6) == 1) {
		type = 6;
		addr_len = sizeof(addr6.s6_addr);
		addr = &(addr6.s6_addr);
	} else if (allow_unix && txt_len > 0) {
		type = 0;
		addr_len = txt_len;
		addr = txt;
	} else {
		return KNOT_EINVAL;
	}

	if (*bin_len < sizeof(type) + addr_len) {
		return KNOT_ESPACE;
	}

	*bin = type;
	memcpy(bin + sizeof(type), addr, addr_len);
	*bin_len = sizeof(type) + addr_len;

	return KNOT_EOK;
}

static int addr_to_txt(
	BIN_TXT_PARAMS)
{
	struct in_addr  addr4;
	struct in6_addr addr6;

	uint8_t type = *bin;
	bin += sizeof(type);
	bin_len -= sizeof(type);

	int ret;
	switch (type) {
	case 0:
		ret = snprintf(txt, *txt_len, "%.*s", (int)bin_len, bin);
		if (ret <= 0 || ret >= *txt_len) {
			return KNOT_ESPACE;
		}
		break;
	case 4:
		if (bin_len != sizeof(addr4.s_addr)) {
			return KNOT_EINVAL;
		}
		memcpy(&(addr4.s_addr), bin, bin_len);
		if (inet_ntop(AF_INET, &addr4, txt, *txt_len) == NULL) {
			return KNOT_ESPACE;
		}
		break;
	case 6:
		if (bin_len != sizeof(addr6.s6_addr)) {
			return KNOT_EINVAL;
		}
		memcpy(&(addr6.s6_addr), bin, bin_len);
		if (inet_ntop(AF_INET6, &addr6, txt, *txt_len) == NULL) {
			return KNOT_ESPACE;
		}
		break;
	default:
		return KNOT_EINVAL;
	}

	*txt_len = strlen(txt);

	return KNOT_EOK;
}

static int yp_addr_to_bin(
	TXT_BIN_PARAMS,
	bool net)
{
	// Check for separator.
	char *pos = index(txt, net ? '/' : '@');
	if (pos == NULL) {
		int ret = addr_to_bin(txt, txt_len, bin, bin_len, !net);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else {
		size_t txt_addr_len = pos - txt;
		char *addr = strndup(txt, txt_addr_len);
		if (addr == NULL) {
			return KNOT_ENOMEM;
		}

		// Address part.
		size_t bin_addr_len = *bin_len;
		int ret = addr_to_bin(addr, txt_addr_len, bin, &bin_addr_len,
		                      false);
		if (ret != KNOT_EOK) {
			free(addr);
			return ret;
		}

		// Set maximal port/prefix length.
		uint8_t type = *bin;
		size_t max_num;
		if (net) {
			if (type == 4) {
				max_num = 32;
			} else {
				max_num = 128;
			}
		} else {
			max_num = UINT16_MAX;
		}

		txt += txt_addr_len + sizeof(char);
		bin += bin_addr_len;

		// Port/prefix length part.
		size_t bin_num_len = *bin_len - bin_addr_len;
		ret = yp_int_to_bin(txt, txt_len - txt_addr_len - 1,
		                    bin, &bin_num_len, 0, max_num,
		                    net ? sizeof(uint8_t) : sizeof(uint16_t),
		                    YP_SNONE);
		if (ret != KNOT_EOK) {
			free(addr);
			return ret;
		}

		free(addr);

		*bin_len = bin_addr_len + bin_num_len;
	}

	return KNOT_EOK;
}

static int yp_addr_to_txt(
	BIN_TXT_PARAMS,
	bool net)
{
	// Set binary address length.
	uint8_t type = *bin;
	size_t bin_addr_len = sizeof(type);
	switch (type) {
	case 0:
		bin_addr_len += bin_len - sizeof(type);
		break;
	case 4:
		bin_addr_len += sizeof(((struct in_addr *)NULL)->s_addr);
		break;
	case 6:
		bin_addr_len += sizeof(((struct in6_addr *)NULL)->s6_addr);
		break;
	default:
		return KNOT_EINVAL;
	}

	// Write address.
	size_t txt_addr_len = *txt_len;
	int ret = addr_to_txt(bin, bin_addr_len, txt, &txt_addr_len);
	if (ret != KNOT_EOK) {
		return ret;
	}
	bin_len -= bin_addr_len;
	bin += bin_addr_len;
	txt += txt_addr_len;

	if (bin_len == 0) {
		*txt_len = txt_addr_len;
		return KNOT_EOK;
	}

	// Write separator.
	char *sep = net ? "/" :"@";
	size_t txt_sep_len = *txt_len - txt_addr_len;
	ret = yp_str_to_txt((uint8_t *)sep, 2, txt, &txt_sep_len);
	if (ret != KNOT_EOK) {
		return ret;
	}
	txt += txt_sep_len;

	// Write port/prefix length.
	size_t txt_num_len = *txt_len - txt_addr_len - txt_sep_len;
	ret = yp_int_to_txt(bin, bin_len, txt, &txt_num_len, YP_SNONE);
	if (ret != KNOT_EOK) {
		return ret;
	}

	*txt_len = txt_addr_len + txt_sep_len + txt_num_len;

	return KNOT_EOK;
}

static int yp_option_to_bin(
	TXT_BIN_PARAMS,
	const lookup_table_t *opts)
{
	while (opts->name != NULL) {
		if (strcasecmp(txt, opts->name) == 0) {
			bin[0] = opts->id;
			*bin_len = 1;
			return KNOT_EOK;
		}
		opts++;
	}

	return KNOT_EINVAL;
}

static int yp_option_to_txt(
	BIN_TXT_PARAMS,
	const lookup_table_t *opts)
{
	while (opts->name != NULL) {
		if (bin[0] == opts->id) {
			int ret = snprintf(txt, *txt_len, "%s", opts->name);
			if (ret <= 0 || ret >= *txt_len) {
				return KNOT_ERANGE;
			}
			*txt_len = ret;
			return KNOT_EOK;
		}
		opts++;
	}

	return KNOT_EINVAL;
}

static int yp_base64_to_bin(
	TXT_BIN_PARAMS)
{
	int ret = base64_decode((uint8_t *)txt, txt_len, bin, *bin_len);
	if (ret < 0) {
		return ret;
	}

	*bin_len = ret;

	return KNOT_EOK;
}

static int yp_base64_to_txt(
	BIN_TXT_PARAMS)
{
	int ret = base64_encode(bin, bin_len, (uint8_t *)txt, *txt_len);
	if (ret < 0) {
		return ret;
	}

	if (ret >= *txt_len) {
		return KNOT_ESPACE;
	}
	*txt_len = ret;
	txt[*txt_len] = '\0';

	return KNOT_EOK;
}

static int yp_dname_to_bin(
	TXT_BIN_PARAMS)
{
	knot_dname_t *dname = knot_dname_from_str(bin, txt, *bin_len);
	if (dname == NULL) {
		return KNOT_EINVAL;
	}

	int ret = knot_dname_wire_check(bin, bin + *bin_len, NULL);
	if (ret <= 0) {
		return KNOT_EINVAL;
	}
	*bin_len = ret;

	ret = knot_dname_to_lower(bin);
	if (ret != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int yp_dname_to_txt(
	BIN_TXT_PARAMS)
{
	char *name = knot_dname_to_str(txt, bin, *txt_len);
	if (name == NULL) {
		return KNOT_EINVAL;
	}

	*txt_len = strlen(txt);

	return KNOT_EOK;
}

_public_
int yp_item_to_bin(
	const yp_item_t *item,
	const char *txt,
	size_t txt_len,
	uint8_t *bin,
	size_t *bin_len)
{
	if (item == NULL || txt == NULL || bin == NULL || bin_len == NULL) {
		return KNOT_EINVAL;
	}

	switch (item->type) {
	case YP_TINT:
		return yp_int_to_bin(txt, txt_len, bin, bin_len, item->var.i.min,
		                     item->var.i.max, 0, item->var.i.unit);
	case YP_TBOOL:
		return yp_bool_to_bin(txt, txt_len, bin, bin_len);
	case YP_TOPT:
		return yp_option_to_bin(txt, txt_len, bin, bin_len,
		                        item->var.o.opts);
	case YP_TSTR:
		return yp_str_to_bin(txt, txt_len, bin, bin_len);
	case YP_TADDR:
		return yp_addr_to_bin(txt, txt_len, bin, bin_len, false);
	case YP_TNET:
		return yp_addr_to_bin(txt, txt_len, bin, bin_len, true);
	case YP_TDNAME:
		return yp_dname_to_bin(txt, txt_len, bin, bin_len);
	case YP_TB64:
		return yp_base64_to_bin(txt, txt_len, bin, bin_len);
	case YP_TDATA:
		return item->var.d.to_bin(txt, txt_len, bin, bin_len);
	case YP_TREF:
		return yp_item_to_bin(item->var.r.ref->var.g.id, txt, txt_len,
		                      bin, bin_len);
	default:
		*bin_len = 0;
		return KNOT_EOK;
	}
}

static int yp_item_to_txt_unquoted(
	const yp_item_t *item,
	const uint8_t *bin,
	size_t bin_len,
	char *txt,
	size_t *txt_len,
	yp_style_t style)
{
	switch (item->type) {
	case YP_TINT:
		return yp_int_to_txt(bin, bin_len, txt, txt_len,
		                     item->var.i.unit & style);
	case YP_TBOOL:
		return yp_bool_to_txt(bin, bin_len, txt, txt_len);
	case YP_TOPT:
		return yp_option_to_txt(bin, bin_len, txt, txt_len,
		                        item->var.o.opts);
	case YP_TSTR:
		return yp_str_to_txt(bin, bin_len, txt, txt_len);
	case YP_TADDR:
		return yp_addr_to_txt(bin, bin_len, txt, txt_len, false);
	case YP_TNET:
		return yp_addr_to_txt(bin, bin_len, txt, txt_len, true);
	case YP_TDNAME:
		return yp_dname_to_txt(bin, bin_len, txt, txt_len);
	case YP_TB64:
		return yp_base64_to_txt(bin, bin_len, txt, txt_len);
	case YP_TDATA:
		return item->var.d.to_txt(bin, bin_len, txt, txt_len);
	case YP_TREF:
		return yp_item_to_txt(item->var.r.ref->var.g.id, bin, bin_len,
		                      txt, txt_len, style | YP_SNOQUOTE);
	default:
		*txt_len = 0;
		return KNOT_EOK;
	}
}

_public_
int yp_item_to_txt(
	const yp_item_t *item,
	const uint8_t *bin,
	size_t bin_len,
	char *txt,
	size_t *txt_len,
	yp_style_t style)
{
	if (item == NULL || txt == NULL || txt_len == NULL) {
		return KNOT_EINVAL;
	}

	// Print unquoted item value.
	if (style & YP_SNOQUOTE) {
		return yp_item_to_txt_unquoted(item, bin, bin_len, txt, txt_len,
		                               style);
	}

	size_t out_len = 0;

	// Print leading quote.
	if (*txt_len < 1) {
		return KNOT_ESPACE;
	}
	*(txt++) = '\"';
	out_len += sizeof(char);

	// Print unquoted item value.
	size_t len = *txt_len - out_len;
	int ret = yp_item_to_txt_unquoted(item, bin, bin_len, txt, &len, style);
	if (ret != KNOT_EOK) {
		return ret;
	}
	txt += len;
	out_len += len;

	// Print trailing quote.
	if (*txt_len - out_len < 2) {
		return KNOT_ESPACE;
	}
	*(txt++) = '\"';
	out_len += sizeof(char);

	// Print string terminator.
	*txt = '\0';
	*txt_len = out_len;

	return KNOT_EOK;
}

_public_
struct sockaddr_storage yp_addr(
	const uint8_t *data,
	size_t data_len,
	int *num)
{
	struct sockaddr_storage ss = { AF_UNSPEC };

	uint8_t type = *data;
	data += sizeof(type);
	data_len -= sizeof(type);

	// Set binary address length.
	int family;
	size_t bin_addr_len;
	switch (type) {
	case 0:
		family = AF_UNIX;
		bin_addr_len = data_len;
		break;
	case 4:
		family = AF_INET;
		bin_addr_len = sizeof(((struct in_addr *)NULL)->s_addr);
		break;
	case 6:
		family = AF_INET6;
		bin_addr_len = sizeof(((struct in6_addr *)NULL)->s6_addr);
		break;
	default:
		*num = -1;
		return ss;
	}

	sockaddr_set_raw(&ss, family, data, bin_addr_len);
	data += bin_addr_len;
	data_len -= bin_addr_len;

	*num = (data_len == 0) ? -1 : yp_int(data, data_len);

	return ss;
}
