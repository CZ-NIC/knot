/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "libdnssec/binary.h"
#include "libdnssec/keytag.h"
#include "libknot/attribute.h"
#include "libknot/rrset-dump.h"
#include "libknot/codes.h"
#include "libknot/consts.h"
#include "libknot/descriptor.h"
#include "libknot/errcode.h"
#include "libknot/lookup.h"
#include "libknot/rrtype/rrsig.h"
#include "libknot/wire.h"
#include "contrib/base32hex.h"
#include "contrib/base64.h"
#include "contrib/color.h"
#include "contrib/ctype.h"
#include "contrib/wire_ctx.h"

#define RRSET_DUMP_LIMIT (2 * 1024 * 1024)

#define TAB_WIDTH		8
#define BLOCK_WIDTH		40
#define BLOCK_INDENT		"\n\t\t\t\t"

#define LOC_ZERO		2147483648	// 2^31

/*! \brief macros with repetitive (mostly error-checking) code of methods from first section of this file */
#define CHECK_PRET if (p->ret < 0) return;
#define CHECK_INMAX(mininmax) if (p->in_max < (mininmax)) { p->ret = -1; return; }
#define CHECK_RET_OUTMAX_SNPRINTF if (ret <= 0 || (size_t)ret >= p->out_max) { p->ret = -1; return; }
#define STRING_TERMINATION if (p->out_max > 0) { *p->out = '\0'; } else { p->ret = -1; return; }
#define FILL_IN_INPUT(pdata) if (memcpy(&(pdata), p->in, in_len) == NULL) { p->ret = -1; return; }
#define CHECK_RET_POSITIVE if (ret <= 0) { p->ret = -1; return; }

#define SNPRINTF_CHECK(ret, max_len)			\
	if ((ret) < 0 || (size_t)(ret) >= (max_len)) {	\
		return KNOT_ESPACE;			\
	}

typedef struct {
	const knot_dump_style_t *style;
	const uint8_t *in;
	size_t        in_max;
	char          *out;
	size_t        out_max;
	size_t        total;
	int           ret;
} rrset_dump_params_t;

_public_
const knot_dump_style_t KNOT_DUMP_STYLE_DEFAULT = {
	.wrap = false,
	.show_class = false,
	.show_ttl = true,
	.verbose = false,
	.original_ttl = true,
	.empty_ttl = false,
	.human_ttl = false,
	.human_tmstamp = true,
	.hide_crypto = false,
	.ascii_to_idn = NULL,
	.color = NULL,
};

static void dump_string(rrset_dump_params_t *p, const char *str)
{
	CHECK_PRET

	size_t in_len = strlen(str);

	// Check input size (+ 1 termination).
	if (in_len >= p->out_max) {
		p->ret = -1;
		return;
	}

	// Copy string including termination '\0'!
	if (memcpy(p->out, str, in_len + 1) == NULL) {
		p->ret = -1;
		return;
	}

	// Fill in output.
	p->out += in_len;
	p->out_max -= in_len;
	p->total += in_len;
}

static void wire_num8_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	uint8_t data = *(p->in);
	size_t  in_len = sizeof(data);
	size_t  out_len = 0;

	CHECK_INMAX(in_len)

	// Write number.
	int ret = snprintf(p->out, p->out_max, "%u", data);
	CHECK_RET_OUTMAX_SNPRINTF
	out_len = ret;

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
}

static void wire_num16_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	uint16_t data;
	size_t   in_len = sizeof(data);
	size_t   out_len = 0;

	CHECK_INMAX(in_len)

	// Fill in input data.
	data = knot_wire_read_u16(p->in);

	// Write number.
	int ret = snprintf(p->out, p->out_max, "%u", data);
	CHECK_RET_OUTMAX_SNPRINTF
	out_len = ret;

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
}

static void wire_num32_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	uint32_t data;
	size_t   in_len = sizeof(data);
	size_t   out_len = 0;

	CHECK_INMAX(in_len)

	// Fill in input data.
	data = knot_wire_read_u32(p->in);

	// Write number.
	int ret = snprintf(p->out, p->out_max, "%u", data);
	CHECK_RET_OUTMAX_SNPRINTF
	out_len = ret;

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
}

static void wire_num48_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	uint64_t data;
	size_t   in_len = 6;
	size_t   out_len = 0;

	CHECK_INMAX(in_len)

	// Fill in input data.
	data = knot_wire_read_u48(p->in);

	// Write number.
	int ret = snprintf(p->out, p->out_max, "%"PRIu64"", data);
	CHECK_RET_OUTMAX_SNPRINTF
	out_len = ret;

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
}

static void wire_ipv4_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	struct in_addr addr4;
	size_t in_len = sizeof(addr4.s_addr);
	size_t out_len = 0;

	CHECK_INMAX(in_len)

	FILL_IN_INPUT(addr4.s_addr)

	// Write address.
	if (inet_ntop(AF_INET, &addr4, p->out, p->out_max) == NULL) {
		p->ret = -1;
		return;
	}
	out_len = strlen(p->out);

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
}

static void wire_ipv6_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	struct in6_addr addr6;
	size_t in_len = sizeof(addr6.s6_addr);
	size_t out_len = 0;

	CHECK_INMAX(in_len)

	FILL_IN_INPUT(addr6.s6_addr)

	// Write address.
	if (inet_ntop(AF_INET6, &addr6, p->out, p->out_max) == NULL) {
		p->ret = -1;
		return;
	}
	out_len = strlen(p->out);

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
}

static void wire_type_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	char     type[32];
	uint16_t data;
	size_t   in_len = sizeof(data);
	size_t   out_len = 0;

	CHECK_INMAX(in_len)

	FILL_IN_INPUT(data)

	// Get record type name string.
	int ret = knot_rrtype_to_string(ntohs(data), type, sizeof(type));
	CHECK_RET_POSITIVE

	// Write string.
	ret = snprintf(p->out, p->out_max, "%s", type);
	CHECK_RET_OUTMAX_SNPRINTF
	out_len = ret;

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
}

static int hex_encode(const uint8_t  *in,
                      const uint32_t in_len,
                      uint8_t        *out,
                      const uint32_t out_len)
{
	static const char hex[] = "0123456789ABCDEF";

	if (out_len < 2 * in_len) {
		return -1;
	}

	for (uint32_t i = 0; i < in_len; i++) {
		out[2 * i]     = hex[in[i] / 16];
		out[2 * i + 1] = hex[in[i] % 16];
	}

	return 2 * in_len;
}

static int hex_encode_alloc(const uint8_t  *in,
                            const uint32_t in_len,
                            uint8_t        **out)
{
	uint32_t out_len = 2 * in_len;

	// Allocating output buffer.
	*out = malloc(out_len);

	if (*out == NULL) {
		return -1;
	}

	// Encoding data.
	return hex_encode(in, in_len, *out, out_len);
}

static int num48_encode(const uint8_t  *in,
                        const uint32_t in_len,
                        uint8_t        *out,
                        const uint32_t out_len)
{
	if (in_len != 6) {
		return -1;
	}

	uint64_t data = knot_wire_read_u48(in);

	int ret = snprintf((char *)out, out_len, "%"PRIu64"", data);
	if (ret <= 0 || (size_t)ret >= out_len) {
		return -1;
	}

	return ret;
}

typedef int (*encode_t)(const uint8_t *in, const uint32_t in_len,
                        uint8_t *out, const uint32_t out_len);

typedef int (*encode_alloc_t)(const uint8_t *in, const uint32_t in_len,
                              uint8_t **out);

static void wire_data_encode_to_str(rrset_dump_params_t *p,
                                    encode_t enc, encode_alloc_t enc_alloc)
{
	CHECK_PRET

	int    ret;
	size_t in_len = p->in_max;

	// One-line vs multi-line mode.
	if (p->style->wrap == false) {
		// Encode data directly to the output.
		ret = enc(p->in, in_len, (uint8_t *)(p->out), p->out_max);
		CHECK_RET_POSITIVE
		size_t out_len = ret;

		p->out += out_len;
		p->out_max -= out_len;
		p->total += out_len;
	} else {
		int     src_begin;
		uint8_t *buf;

		// Encode data to the temporary buffer.
		ret = enc_alloc(p->in, in_len, &buf);
		CHECK_RET_POSITIVE

		// Loop which wraps base64 block in more lines.
		for (src_begin = 0; src_begin < ret; src_begin += BLOCK_WIDTH) {
			if (src_begin > 0) {
				// Write indent block.
				dump_string(p, BLOCK_INDENT);
				if (p->ret < 0) {
					free(buf);
					return;
				}
			}

			// Compute block length (the last one can be shorter).
			int src_len = (ret - src_begin) < BLOCK_WIDTH ?
			              (ret - src_begin) : BLOCK_WIDTH;

			if ((size_t)src_len > p->out_max) {
				free(buf);
				p->ret = -1;
				return;
			}

			// Write data block.
			memcpy(p->out, buf + src_begin, src_len);

			p->out += src_len;
			p->out_max -= src_len;
			p->total += src_len;
		}

		// Destroy temporary buffer.
		free(buf);
	}

	STRING_TERMINATION

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
}

static void wire_len_data_encode_to_str(rrset_dump_params_t *p,
                                        encode_t            enc,
                                        const size_t        len_len,
                                        const bool          print_len,
                                        const char          *empty_str)
{
	CHECK_PRET

	size_t in_len;

	// First len_len bytes are data length.
	CHECK_INMAX(len_len)

	// Read data length.
	switch (len_len) {
	case 1:
		in_len = *(p->in);
		break;
	case 2:
		in_len = knot_wire_read_u16(p->in);
		break;
	case 4:
		in_len = knot_wire_read_u32(p->in);
		break;
	default:
		p->ret = -1;
		return;
	}

	// If required print data length.
	if (print_len == true) {
		switch (len_len) {
		case 1:
			wire_num8_to_str(p);
			break;
		case 2:
			wire_num16_to_str(p);
			break;
		case 4:
			wire_num32_to_str(p);
			break;
		}

		CHECK_PRET

		// If something follows, print one space character.
		if (in_len > 0 || *empty_str != '\0') {
			dump_string(p, " ");
			CHECK_PRET
		}
	} else {
		p->in += len_len;
		p->in_max -= len_len;
	}

	if (in_len > 0) {
		// Encode data directly to the output.
		int ret = enc(p->in, in_len, (uint8_t *)(p->out), p->out_max);
		CHECK_RET_POSITIVE
		p->out += ret;
		p->out_max -= ret;
		p->total += ret;

		STRING_TERMINATION

		// Fill in output.
		p->in += in_len;
		p->in_max -= in_len;
	} else if (*empty_str != '\0') {
		dump_string(p, empty_str);
		CHECK_PRET
	}
}

static void wire_data_omit(rrset_dump_params_t *p)
{
	CHECK_PRET

	const char *omit_message = "[omitted]";
	const size_t omlen = strlen(omit_message);

	if (p->out_max < omlen) {
		p->ret = -1;
		return;
	}

	memcpy(p->out, omit_message, omlen);
	p->out += omlen;
	p->out_max -= omlen;
	p->total += omlen;

	STRING_TERMINATION

	p->in += p->in_max;
	p->in_max = 0;
}

static void wire_dnskey_to_tag(rrset_dump_params_t *p)
{
	CHECK_PRET

	int key_pos = -4; // we expect that key flags, 3 and algorithm
	                  // have been already dumped

	uint16_t key_tag = 0;
	const dnssec_binary_t rdata_bin = {
		.data = (uint8_t *)(p->in + key_pos),
		.size = p->in_max - key_pos
	};
	dnssec_keytag(&rdata_bin, &key_tag);

	int ret = snprintf(p->out, p->out_max, "[id = %hu]", key_tag);
	CHECK_RET_OUTMAX_SNPRINTF

	p->in += p->in_max;
	p->in_max = 0;
	p->out += ret;
	p->out_max -= ret;
	p->total += ret;
}

static void wire_unknown_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	int    ret;
	size_t in_len = p->in_max;
	size_t out_len = 0;

	// Write unknown length header.
	if (in_len > 0) {
		ret = snprintf(p->out, p->out_max, "\\# %zu ", in_len);
	} else {
		ret = snprintf(p->out, p->out_max, "\\# 0");
	}
	CHECK_RET_OUTMAX_SNPRINTF
	out_len = ret;

	// Fill in output.
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;

	// Write hex data if any.
	if (in_len > 0) {
		// If wrap mode wrap line.
		if (p->style->wrap) {
			dump_string(p, BLOCK_INDENT);
			CHECK_PRET
		}

		wire_data_encode_to_str(p, &hex_encode, &hex_encode_alloc);
		CHECK_PRET
	}
}

static void wire_text_to_str(rrset_dump_params_t *p, bool quote,
                             unsigned with_header_len, bool alpn_mode)
{
	CHECK_PRET

	size_t in_len = 0;

	CHECK_INMAX(with_header_len)
	switch (with_header_len) {
	case 0:
		in_len = p->in_max;
		break;
	case 1:
		in_len = *(p->in);
		break;
	case 2:
		in_len = knot_wire_read_u16(p->in);
		break;
	default:
		assert(0);
	}
	p->in += with_header_len;
	p->in_max -= with_header_len;
	CHECK_INMAX(in_len)

	// Check if quotation can ever be disabled (parser protection fallback).
	if (!quote) {
		for (size_t i = 0; i < in_len; i++) {
			if (p->in[i] == ' ') { // Other WS characters are encoded.
				quote = true;
				break;
			}
		}
	}

	// Opening quotation.
	if (quote) {
		dump_string(p, "\"");
		CHECK_PRET
	}

	// Loop over all characters.
	for (size_t i = 0; i < in_len; i++) {
		uint8_t ch = p->in[i];

		if (is_print(ch)) {
			// For special character print leading slash.
			if (ch == '\\' || ch == '"') {
				dump_string(p, "\\");
				CHECK_PRET
			}
			if (alpn_mode && (ch == ',' || ch == '\\')) {
				dump_string(p, "\\\\");
				CHECK_PRET
			}

			// Print text character.
			if (p->out_max == 0) {
				p->ret = -1;
				return;
			}

			*p->out = ch;
			p->out++;
			p->out_max--;
			p->total++;
		} else {
			// Unprintable character encode via \ddd notation.
			int ret = snprintf(p->out, p->out_max,"\\%03u", ch);
			CHECK_RET_OUTMAX_SNPRINTF

			p->out += ret;
			p->out_max -= ret;
			p->total += ret;
		}
	}

	// Closing quotation.
	if (quote) {
		dump_string(p, "\"");
		CHECK_PRET
	}

	STRING_TERMINATION

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
}

static void wire_timestamp_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	uint32_t data;
	size_t   in_len = sizeof(data);
	size_t   out_len = 0;
	int      ret;

	CHECK_INMAX(in_len)

	FILL_IN_INPUT(data)

	time_t timestamp = ntohl(data);

	if (p->style->human_tmstamp) {
		struct tm result;
		// Write timestamp in YYYYMMDDhhmmss format.
		ret = strftime(p->out, p->out_max, "%Y%m%d%H%M%S",
		               gmtime_r(&timestamp, &result));
		CHECK_RET_POSITIVE
	} else {
		// Write timestamp only.
		ret = snprintf(p->out, p->out_max, "%u", ntohl(data));
		CHECK_RET_OUTMAX_SNPRINTF
	}
	out_len = ret;

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
}

static int time_to_human_str(char         *out,
                             const size_t out_len,
                             uint32_t     data)
{
	size_t   total_len = 0;
	uint32_t num;
	int      ret;

#define tths_process(unit_name, unit_size) \
	num = data / (unit_size); \
	if (num > 0) { \
		ret = snprintf(out + total_len, out_len - total_len, \
		               "%u%s", num, (unit_name)); \
		if (ret <= 0 || (size_t)ret >= out_len - total_len) { \
			return -1; \
		} \
		total_len += ret; \
		data -= num * (unit_size); \
	}

	tths_process("d", 86400);
	tths_process("h", 3600);
	tths_process("m", 60);
	tths_process("s", 1);

#undef tths_process

	return total_len > 0 ? total_len : -1;
}

static void wire_ttl_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	uint32_t data;
	size_t   in_len = sizeof(data);
	size_t   out_len = 0;
	int      ret;

	CHECK_INMAX(in_len)

	FILL_IN_INPUT(data)

	if (p->style->human_ttl) {
		// Write time in human readable format.
		ret = time_to_human_str(p->out, p->out_max, ntohl(data));
		CHECK_RET_POSITIVE
	} else {
		// Write timestamp only.
		ret = snprintf(p->out, p->out_max, "%u", ntohl(data));
		CHECK_RET_OUTMAX_SNPRINTF
	}
	out_len = ret;

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
}

static void wire_bitmap_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	int    ret;
	char   type[32];
	size_t i = 0;
	size_t in_len = p->in_max;
	size_t out_len = 0;

	// Loop over bitmap window array (can be empty).
	while (i < in_len) {
		// First byte is window number.
		uint8_t win = p->in[i++];

		// Check window length (length must follow).
		if (i >= in_len) {
			p->ret = -1;
			return;
		}

		// Second byte is window length.
		uint8_t bitmap_len = p->in[i++];

		// Check window length (len bytes must follow).
		if (i + bitmap_len > in_len) {
			p->ret = -1;
			return;
		}

		// Bitmap processing.
		for (size_t j = 0; j < (bitmap_len * 8); j++) {
			if ((p->in[i + j / 8] & (128 >> (j % 8))) != 0) {
				uint16_t type_num = win * 256 + j;

				ret = knot_rrtype_to_string(type_num, type, sizeof(type));
				CHECK_RET_POSITIVE

				// Print type name to type list.
				if (out_len > 0) {
					ret = snprintf(p->out, p->out_max,
					               " %s", type);
				} else {
					ret = snprintf(p->out, p->out_max,
					               "%s", type);
				}
				CHECK_RET_OUTMAX_SNPRINTF
				out_len += ret;
				p->out += ret;
				p->out_max -= ret;
			}
		}

		i += bitmap_len;
	}

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->total += out_len;
}

static void wire_dname_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	size_t in_len = knot_dname_size(p->in);
	size_t out_len = 0;

	CHECK_INMAX(in_len)

	// Write dname string.
	if (p->style->ascii_to_idn == NULL) {
		char *dname_str = knot_dname_to_str(p->out, p->in, p->out_max);
		if (dname_str == NULL) {
			p->ret = -1;
			return;
		}
		out_len = strlen(dname_str);
	} else {
		char *dname_str = knot_dname_to_str_alloc(p->in);
		p->style->ascii_to_idn(&dname_str);

		int ret = snprintf(p->out, p->out_max, "%s", dname_str);
		free(dname_str);
		CHECK_RET_OUTMAX_SNPRINTF
		out_len = ret;
	}

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
}

static void wire_apl_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	struct in_addr addr4;
	struct in6_addr addr6;
	int    ret;
	size_t out_len = 0;

	// Input check: family(2B) + prefix(1B) + afdlen(1B).
	CHECK_INMAX(4)

	// Read fixed size values.
	uint16_t family   = knot_wire_read_u16(p->in);
	uint8_t  prefix   = *(p->in + 2);
	uint8_t  negation = *(p->in + 3) >> 7;
	uint8_t  afdlen   = *(p->in + 3) & 0x7F;
	p->in += 4;
	p->in_max -= 4;

	// Write negation mark.
	if (negation != 0) {
		dump_string(p, "!");
		CHECK_PRET
	}

	// Write address family with colon.
	ret = snprintf(p->out, p->out_max, "%u:", family);
	CHECK_RET_OUTMAX_SNPRINTF
	p->out += ret;
	p->out_max -= ret;
	p->total += ret;

	// Write address.
	switch (family) {
	case 1:
		memset(&addr4, 0, sizeof(addr4));

		if (afdlen > sizeof(addr4.s_addr) || afdlen > p->in_max) {
			p->ret = -1;
			return;
		}

		if (memcpy(&(addr4.s_addr), p->in, afdlen) == NULL) {
			p->ret = -1;
			return;
		}

		// Write address.
		if (inet_ntop(AF_INET, &addr4, p->out, p->out_max) == NULL) {
			p->ret = -1;
			return;
		}
		out_len = strlen(p->out);

		break;
	case 2:
		memset(&addr6, 0, sizeof(addr6));

		if (afdlen > sizeof(addr6.s6_addr) || afdlen > p->in_max) {
			p->ret = -1;
			return;
		}

		if (memcpy(&(addr6.s6_addr), p->in, afdlen) == NULL) {
			p->ret = -1;
			return;
		}

		// Write address.
		if (inet_ntop(AF_INET6, &addr6, p->out, p->out_max) == NULL) {
			p->ret = -1;
			return;
		}
		out_len = strlen(p->out);

		break;
	default:
		p->ret = -1;
		return;
	}
	p->in += afdlen;
	p->in_max -= afdlen;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;

	// Write prefix length with forward slash.
	ret = snprintf(p->out, p->out_max, "/%u", prefix);
	CHECK_RET_OUTMAX_SNPRINTF
	p->out += ret;
	p->out_max -= ret;
	p->total += ret;
}

static void wire_loc_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	// Read values.
	wire_ctx_t wire = wire_ctx_init_const(p->in, p->in_max);
	uint8_t version = wire_ctx_read_u8(&wire);

	// Version check.
	if (version != 0) {
		wire_unknown_to_str(p);
		p->ret = -1;
		return;
	}

	// Continue to read values.
	uint8_t size_w = wire_ctx_read_u8(&wire);
	uint8_t hpre_w = wire_ctx_read_u8(&wire);
	uint8_t vpre_w = wire_ctx_read_u8(&wire);
	uint32_t lat_w = wire_ctx_read_u32(&wire);
	uint32_t lon_w = wire_ctx_read_u32(&wire);
	uint32_t alt_w = wire_ctx_read_u32(&wire);

	// Check if all reads are correct.
	if (wire.error != KNOT_EOK) {
		p->ret = -1;
		return;
	}

	p->in += wire_ctx_offset(&wire);
	p->in_max = wire_ctx_available(&wire);

	// Latitude calculation.
	char lat_mark;
	uint32_t lat;
	if (lat_w >= LOC_ZERO) {
		lat_mark = 'N';
		lat = lat_w - LOC_ZERO;
	} else {
		lat_mark = 'S';
		lat = LOC_ZERO - lat_w;
	}

	uint32_t d1 = lat / 3600000;
	uint32_t m1 = (lat - 3600000 * d1) / 60000;
	double s1 = 0.001 * (lat - 3600000 * d1 - 60000 * m1);

	// Longitude calculation.
	char lon_mark;
	uint32_t lon;
	if (lon_w >= LOC_ZERO) {
		lon_mark = 'E';
		lon = lon_w - LOC_ZERO;
	} else {
		lon_mark = 'W';
		lon = LOC_ZERO - lon_w;
	}

	uint32_t d2 = lon / 3600000;
	uint32_t m2 = (lon - 3600000 * d2) / 60000;
	double s2 = 0.001 * (lon - 3600000 * d2 - 60000 * m2);

	// Write latitude and longitude.
	int ret = snprintf(p->out, p->out_max, "%u %u %.*f %c  %u %u %.*f %c",
	                   d1, m1, (uint32_t)s1 != s1 ? 3 : 0, s1, lat_mark,
	                   d2, m2, (uint32_t)s2 != s2 ? 3 : 0, s2, lon_mark);
	CHECK_RET_OUTMAX_SNPRINTF
	p->out += ret;
	p->out_max -= ret;
	p->total += ret;

	// Altitude calculation.
	double alt = 0.01 * alt_w - 100000.0;

	// Compute mantissa and exponent for each size.
	uint8_t size_m = size_w >> 4;
	uint8_t size_e = size_w & 0xF;
	uint8_t hpre_m = hpre_w >> 4;
	uint8_t hpre_e = hpre_w & 0xF;
	uint8_t vpre_m = vpre_w >> 4;
	uint8_t vpre_e = vpre_w & 0xF;

	// Sizes check.
	if (size_m > 9 || size_e > 9 || hpre_m > 9 || hpre_e > 9 ||
	    vpre_m > 9 || vpre_e > 9) {
		p->ret = -1;
		return;
	}

	// Size and precisions calculation.
	double size = 0.01 * size_m * pow(10, size_e);
	double hpre = 0.01 * hpre_m * pow(10, hpre_e);
	double vpre = 0.01 * vpre_m * pow(10, vpre_e);

	// Write altitude and precisions.
	ret = snprintf(p->out, p->out_max, "  %.*fm  %.*fm %.*fm %.*fm",
	               (int32_t)alt != alt ? 2 : 0, alt,
	               (uint32_t)size != size ? 2 : 0, size,
	               (uint32_t)hpre != hpre ? 2 : 0, hpre,
	               (uint32_t)vpre != vpre ? 2 : 0, vpre);
	CHECK_RET_OUTMAX_SNPRINTF
	p->out += ret;
	p->out_max -= ret;
	p->total += ret;
}

static void wire_gateway_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	// Input check: type(1B) + algo(1B).
	CHECK_INMAX(2)

	uint8_t type = *p->in;
	uint8_t alg = *(p->in + 1);

	// Write gateway type.
	wire_num8_to_str(p);
	CHECK_PRET

	// Write space.
	dump_string(p, " ");
	CHECK_PRET

	// Write algorithm number.
	wire_num8_to_str(p);
	CHECK_PRET

	// Write space.
	dump_string(p, " ");
	CHECK_PRET

	// Write appropriate gateway.
	switch (type) {
	case 0:
		dump_string(p, ".");
		break;
	case 1:
		wire_ipv4_to_str(p);
		break;
	case 2:
		wire_ipv6_to_str(p);
		break;
	case 3:
		wire_dname_to_str(p);
		break;
	default:
		p->ret = -1;
	}
	CHECK_PRET

	if (alg > 0) {
		// If wrap mode wrap line.
		if (p->style->wrap) {
			dump_string(p, BLOCK_INDENT);
		} else {
			dump_string(p, " ");
		}
		CHECK_PRET

		// Write ipsec key.
		wire_data_encode_to_str(p, &knot_base64_encode, &knot_base64_encode_alloc);
		CHECK_PRET
	}
}

static void wire_l64_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	// Check input size (64-bit identifier).
	if (p->in_max != 8) {
		p->ret = -1;
		return;
	}

	// Write identifier (2-byte) labels separated with a colon.
	while (p->in_max > 0) {
		int ret = hex_encode(p->in, 2, (uint8_t *)(p->out), p->out_max);
		CHECK_RET_POSITIVE
		p->in += 2;
		p->in_max -= 2;
		p->out += ret;
		p->out_max -= ret;
		p->total += ret;

		// Write separation character.
		if (p->in_max > 0) {
			dump_string(p, ":");
			CHECK_PRET
		}
	}
}

static void wire_eui_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	CHECK_INMAX(2)

	// Write EUI hexadecimal pairs.
	while (p->in_max > 0) {
		int ret = hex_encode(p->in, 1, (uint8_t *)(p->out), p->out_max);
		CHECK_RET_POSITIVE
		p->in++;
		p->in_max--;
		p->out += ret;
		p->out_max -= ret;
		p->total += ret;

		// Write separation character.
		if (p->in_max > 0) {
			dump_string(p, "-");
			CHECK_PRET
		}
	}
}

static void wire_tsig_rcode_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	uint16_t data;
	size_t   in_len = sizeof(data);
	const char *rcode_str = "Unknown";

	CHECK_INMAX(in_len)

	// Fill in input data.
	data = knot_wire_read_u16(p->in);

	// Find RCODE name.
	const knot_lookup_t *rcode = NULL;
	rcode = knot_lookup_by_id(knot_tsig_rcode_names, data);
	if (rcode == NULL) {
		rcode = knot_lookup_by_id(knot_rcode_names, data);
	}
	if (rcode != NULL) {
		rcode_str = rcode->name;
	}

	// Dump RCODE name.
	dump_string(p, rcode_str);
	CHECK_PRET

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
}

static void wire_svcb_paramkey_to_str(rrset_dump_params_t *p)
{
	uint16_t param_key = knot_wire_read_u16(p->in);
	const knot_lookup_t *type = knot_lookup_by_id(knot_svcb_param_names, param_key);

	if (type != NULL) {
		dump_string(p, type->name);
		CHECK_PRET
		p->in += sizeof(param_key);
		p->in_max -= sizeof(param_key);
	} else {
		dump_string(p, "key");
		CHECK_PRET
		wire_num16_to_str(p);
		CHECK_PRET
	}
}

static void wire_value_list_to_str(rrset_dump_params_t *p,
                                   void (*list_item_dump_fcn)(rrset_dump_params_t *p),
                                   const uint8_t *expect_end)
{
	bool first = true;

	while (expect_end > p->in) {
		if (first) {
			first = false;
		} else {
			dump_string(p, ",");
			CHECK_PRET
		}

		list_item_dump_fcn(p);
		CHECK_PRET
	}
	if (expect_end != p->in) {
		p->ret = -1;
	}
}

static void wire_text_to_str1(rrset_dump_params_t *p)
{
	wire_text_to_str(p, false, 1, true);
}

static void wire_ech_to_base64(rrset_dump_params_t *p, unsigned ech_len)
{
	CHECK_INMAX(ech_len)

	int ret = knot_base64_encode(p->in, ech_len, (uint8_t *)(p->out), p->out_max);
	CHECK_RET_POSITIVE
	size_t out_len = ret;

	p->in += ech_len;
	p->in_max -= ech_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;

	STRING_TERMINATION
}

static void wire_svcparam_to_str(rrset_dump_params_t *p)
{
	CHECK_PRET

	CHECK_INMAX(4)

	// Pre-fetch key and length for later use.
	uint16_t key_type = knot_wire_read_u16(p->in);
	uint16_t val_len = knot_wire_read_u16(p->in + sizeof(key_type));

	wire_svcb_paramkey_to_str(p);

	p->in += sizeof(val_len);
	p->in_max -= sizeof(val_len);
	CHECK_INMAX(val_len)

	if (val_len > 0) {
		dump_string(p, "=");
		CHECK_PRET

		switch (key_type) {
		case KNOT_SVCB_PARAM_MANDATORY:
			wire_value_list_to_str(p, wire_svcb_paramkey_to_str, p->in + val_len);
			break;
		case KNOT_SVCB_PARAM_ALPN:
			wire_value_list_to_str(p, wire_text_to_str1, p->in + val_len);
			break;
		case KNOT_SVCB_PARAM_NDALPN:
			p->ret = -1; // must not have value
			break;
		case KNOT_SVCB_PARAM_PORT:
			if (val_len != sizeof(uint16_t)) {
				p->ret = -1;
			} else {
				wire_num16_to_str(p);
			}
			break;
		case KNOT_SVCB_PARAM_IPV4HINT:
			wire_value_list_to_str(p, wire_ipv4_to_str, p->in + val_len);
			break;
		case KNOT_SVCB_PARAM_ECH:
			wire_ech_to_base64(p, val_len);
			break;
		case KNOT_SVCB_PARAM_IPV6HINT:
			wire_value_list_to_str(p, wire_ipv6_to_str, p->in + val_len);
			break;
		default:
			p->in -= sizeof(val_len); // Rollback to where the string length resides.
			p->in_max += sizeof(val_len);
			wire_text_to_str(p, true, sizeof(val_len), false);
		}
	}
}

static size_t dnskey_len(const uint8_t *rdata,
                         const size_t  rdata_len)
{
	// Check for empty rdata and empty key.
	if (rdata_len <= 4) {
		return 0;
	}

	const uint8_t *key = rdata + 4;
	const size_t  len = rdata_len - 4;

	switch (rdata[3]) {
	case KNOT_DNSSEC_ALG_DSA:
	case KNOT_DNSSEC_ALG_DSA_NSEC3_SHA1:
		// RFC 2536, key size ~ bit-length of 'modulus' P.
		return (64 + 8 * key[0]) * 8;
	case KNOT_DNSSEC_ALG_RSAMD5:
	case KNOT_DNSSEC_ALG_RSASHA1:
	case KNOT_DNSSEC_ALG_RSASHA1_NSEC3_SHA1:
	case KNOT_DNSSEC_ALG_RSASHA256:
	case KNOT_DNSSEC_ALG_RSASHA512:
		// RFC 3110, key size ~ bit-length of 'modulus'.
		if (key[0] == 0) {
			if (len < 3) {
				return 0;
			}
			uint16_t exp;
			memcpy(&exp, key + 1, sizeof(uint16_t));
			return (len - 3 - ntohs(exp)) * 8;
		} else {
			return (len - 1 - key[0]) * 8;
		}
	case KNOT_DNSSEC_ALG_ECC_GOST:
		// RFC 5933, key size of GOST public keys MUST be 512 bits.
		return 512;
	case KNOT_DNSSEC_ALG_ECDSAP256SHA256:
		// RFC 6605.
		return 256;
	case KNOT_DNSSEC_ALG_ECDSAP384SHA384:
		// RFC 6605.
		return 384;
	case KNOT_DNSSEC_ALG_ED25519:
		// RFC 8080.
		return 256;
	case KNOT_DNSSEC_ALG_ED448:
		// RFC 8080.
		return 456;
	default:
		return 0;
	}
}

static int ber_to_oid(char *dst,
                      size_t dst_len,
                      const uint8_t *src,
                      const size_t src_len)
{
	assert(dst);
	assert(src);

	static const uint8_t longer_mask = (1 << 7);

	size_t len = src[0];
	if (len == 0 || len >= src_len || dst_len == 0) {
		return KNOT_EINVAL;
	}

	uint64_t node = 0UL;
	for (int i = 1; i <= len; ++i) {
		uint8_t longer_node = (src[i] & longer_mask);
		node <<= 7;
		node += (longer_node ^ src[i]);
		if (!longer_node) {
			int ret = snprintf(dst, dst_len, "%"PRIu64".", node);
			SNPRINTF_CHECK(ret, dst_len);
			dst += ret;
			dst_len -= ret;
			node = 0UL;
		}
	}
	*(dst - 1) = '\0';

	return KNOT_EOK;
}

static void dnskey_info(const uint8_t *rdata,
                        const size_t  rdata_len,
                        char          *out,
                        const size_t  out_len)
{
	if (rdata_len < 5) {
		return;
	}

	const uint8_t sep = *(rdata + 1) & 0x01;
	uint16_t      key_tag = 0;
	const size_t  key_len = dnskey_len(rdata, rdata_len);
	const uint8_t alg_id = rdata[3];
	char          alg_info[512] = "";

	const dnssec_binary_t rdata_bin = { .data = (uint8_t *)rdata,
	                                    .size = rdata_len };
	dnssec_keytag(&rdata_bin, &key_tag);

	const knot_lookup_t *alg = knot_lookup_by_id(knot_dnssec_alg_names, alg_id);

	switch (alg_id) {
	case KNOT_DNSSEC_ALG_DELETE:
	case KNOT_DNSSEC_ALG_INDIRECT:
		break;
	case KNOT_DNSSEC_ALG_PRIVATEOID:
		; char oid_str[sizeof(alg_info) - 3];
		if (ber_to_oid(oid_str, sizeof(oid_str), rdata + 4, rdata_len - 4) != KNOT_EOK ||
		    snprintf(alg_info, sizeof(alg_info), " (%s)", oid_str) <= 0) {
			alg_info[0] = '\0';
		}
		break;
	case KNOT_DNSSEC_ALG_PRIVATEDNS:
		; knot_dname_txt_storage_t alg_str;
		if (knot_dname_wire_check(rdata + 4, rdata + rdata_len, NULL) <= 0 ||
		    knot_dname_to_str(alg_str, rdata + 4, sizeof(alg_str)) == NULL ||
		    snprintf(alg_info, sizeof(alg_info), " (%s)", alg_str) <= 0) {
			alg_info[0] = '\0';
		}
		break;
	default:
		if (snprintf(alg_info, sizeof(alg_info), " (%zub)", key_len) <= 0) {
			alg_info[0] = '\0';
		}
		break;
	}

	int ret = snprintf(out, out_len, "%s, %s%s, id = %u",
	                   sep ? "KSK" : "ZSK",
	                   alg ? alg->name : "UNKNOWN",
	                   alg_info,
	                   key_tag);
	if (ret <= 0) {	// Truncated return is acceptable. Just check for errors.
		out[0] = '\0';
	}
}

#define DUMP_PARAMS	rrset_dump_params_t *const p
#define	DUMP_END	return (p->in_max == 0 ? (int)p->total : KNOT_EPARSEFAIL);

#define CHECK_RET(p)	if (p->ret < 0) return p->ret;

#define WRAP_INIT	dump_string(p, "(" BLOCK_INDENT); CHECK_RET(p);
#define WRAP_END	dump_string(p, BLOCK_INDENT ")"); CHECK_RET(p);
#define WRAP_LINE	dump_string(p, BLOCK_INDENT); CHECK_RET(p);

#define COMMENT(s)	if (p->style->verbose) { \
			    dump_string(p, " ; "); CHECK_RET(p); \
			    dump_string(p, s); CHECK_RET(p); \
			}

#define DUMP_SPACE	dump_string(p, " "); CHECK_RET(p);
#define DUMP_NUM8	wire_num8_to_str(p); CHECK_RET(p);
#define DUMP_NUM16	wire_num16_to_str(p); CHECK_RET(p);
#define DUMP_NUM32	wire_num32_to_str(p); CHECK_RET(p);
#define DUMP_NUM48	wire_num48_to_str(p); CHECK_RET(p);
#define DUMP_DNAME	wire_dname_to_str(p); CHECK_RET(p);
#define DUMP_TIME	wire_ttl_to_str(p); CHECK_RET(p);
#define DUMP_TIMESTAMP	wire_timestamp_to_str(p); CHECK_RET(p);
#define DUMP_IPV4	wire_ipv4_to_str(p); CHECK_RET(p);
#define DUMP_IPV6	wire_ipv6_to_str(p); CHECK_RET(p);
#define DUMP_TYPE	wire_type_to_str(p); CHECK_RET(p);
#define DUMP_HEX	wire_data_encode_to_str(p, &hex_encode, \
				&hex_encode_alloc); CHECK_RET(p);
#define DUMP_BASE64	wire_data_encode_to_str(p, &knot_base64_encode, \
				&knot_base64_encode_alloc); CHECK_RET(p);
#define DUMP_HASH	wire_len_data_encode_to_str(p, &knot_base32hex_encode, \
				1, false, ""); CHECK_RET(p);
#define DUMP_SALT	wire_len_data_encode_to_str(p, &hex_encode, \
				1, false, "-"); CHECK_RET(p);
#define DUMP_TSIG_DGST	wire_len_data_encode_to_str(p, &knot_base64_encode, \
				2, true, ""); CHECK_RET(p);
#define DUMP_TSIG_DATA	wire_len_data_encode_to_str(p, &num48_encode, \
				2, true, ""); CHECK_RET(p);
#define DUMP_OMIT	wire_data_omit(p); CHECK_RET(p);
#define DUMP_KEY_OMIT	wire_dnskey_to_tag(p); CHECK_RET(p);
#define DUMP_TEXT	wire_text_to_str(p, true,  1, false); CHECK_RET(p);
#define DUMP_LONG_TEXT	wire_text_to_str(p, true,  0, false); CHECK_RET(p);
#define DUMP_UNQUOTED	wire_text_to_str(p, false, 1, false); CHECK_RET(p);
#define DUMP_BITMAP	wire_bitmap_to_str(p); CHECK_RET(p);
#define DUMP_APL	wire_apl_to_str(p); CHECK_RET(p);
#define DUMP_LOC	wire_loc_to_str(p); CHECK_RET(p);
#define DUMP_GATEWAY	wire_gateway_to_str(p); CHECK_RET(p);
#define DUMP_L64	wire_l64_to_str(p); CHECK_RET(p);
#define DUMP_EUI	wire_eui_to_str(p); CHECK_RET(p);
#define DUMP_TSIG_RCODE	wire_tsig_rcode_to_str(p); CHECK_RET(p);
#define DUMP_SVCPARAM	wire_svcparam_to_str(p); CHECK_RET(p);
#define DUMP_UNKNOWN	wire_unknown_to_str(p); CHECK_RET(p);

static int dump_a(DUMP_PARAMS)
{
	DUMP_IPV4;

	DUMP_END;
}

static int dump_ns(DUMP_PARAMS)
{
	DUMP_DNAME;

	DUMP_END;
}

static int dump_soa(DUMP_PARAMS)
{
	if (p->style->wrap) {
		DUMP_DNAME; DUMP_SPACE;
		DUMP_DNAME; DUMP_SPACE; WRAP_INIT;
		DUMP_NUM32; COMMENT("serial"); WRAP_LINE;
		DUMP_TIME;  COMMENT("refresh"); WRAP_LINE;
		DUMP_TIME;  COMMENT("retry"); WRAP_LINE;
		DUMP_TIME;  COMMENT("expire"); WRAP_LINE;
		DUMP_TIME;  COMMENT("minimum"); WRAP_END;
	} else {
		DUMP_DNAME; DUMP_SPACE;
		DUMP_DNAME; DUMP_SPACE;
		DUMP_NUM32; DUMP_SPACE;
		DUMP_TIME;  DUMP_SPACE;
		DUMP_TIME;  DUMP_SPACE;
		DUMP_TIME;  DUMP_SPACE;
		DUMP_TIME;
	}

	DUMP_END;
}

static int dump_hinfo(DUMP_PARAMS)
{
	DUMP_TEXT; DUMP_SPACE;
	DUMP_TEXT;

	DUMP_END;
}

static int dump_minfo(DUMP_PARAMS)
{
	DUMP_DNAME; DUMP_SPACE;
	DUMP_DNAME;

	DUMP_END;
}

static int dump_mx(DUMP_PARAMS)
{
	DUMP_NUM16; DUMP_SPACE;
	DUMP_DNAME;

	DUMP_END;
}

static int dump_txt(DUMP_PARAMS)
{
	// First text string.
	DUMP_TEXT;

	// Other text strings if any.
	while (p->in_max > 0) {
		DUMP_SPACE; DUMP_TEXT;
	}

	DUMP_END;
}

static int dump_dnskey(DUMP_PARAMS)
{
	if (p->style->wrap) {
		char info[512] = "";
		dnskey_info(p->in, p->in_max, info, sizeof(info));

		DUMP_NUM16; DUMP_SPACE;
		DUMP_NUM8;  DUMP_SPACE;
		DUMP_NUM8;  DUMP_SPACE;
		if (p->style->hide_crypto) {
			DUMP_OMIT;
			WRAP_LINE;
		} else {
			WRAP_INIT;
			DUMP_BASE64;
			WRAP_END;
		}
		COMMENT(info);
	} else {
		DUMP_NUM16; DUMP_SPACE;
		DUMP_NUM8;  DUMP_SPACE;
		DUMP_NUM8;  DUMP_SPACE;
		if (p->style->hide_crypto) {
			DUMP_KEY_OMIT;
		} else {
			DUMP_BASE64;
		}
	}

	DUMP_END;
}

static int dump_aaaa(DUMP_PARAMS)
{
	DUMP_IPV6;

	DUMP_END;
}

static int dump_loc(DUMP_PARAMS)
{
	DUMP_LOC;

	DUMP_END;
}

static int dump_srv(DUMP_PARAMS)
{
	DUMP_NUM16; DUMP_SPACE;
	DUMP_NUM16; DUMP_SPACE;
	DUMP_NUM16; DUMP_SPACE;
	DUMP_DNAME;

	DUMP_END;
}

static int dump_naptr(DUMP_PARAMS)
{
	DUMP_NUM16; DUMP_SPACE;
	DUMP_NUM16; DUMP_SPACE;
	DUMP_TEXT;  DUMP_SPACE;
	DUMP_TEXT;  DUMP_SPACE;
	DUMP_TEXT;  DUMP_SPACE;
	DUMP_DNAME;

	DUMP_END;
}

static int dump_cert(DUMP_PARAMS)
{
	if (p->style->wrap) {
		DUMP_NUM16;  DUMP_SPACE;
		DUMP_NUM16;  DUMP_SPACE;
		DUMP_NUM8;   DUMP_SPACE; WRAP_INIT;
		DUMP_BASE64;
		WRAP_END;
	} else {
		DUMP_NUM16;  DUMP_SPACE;
		DUMP_NUM16;  DUMP_SPACE;
		DUMP_NUM8;   DUMP_SPACE;
		DUMP_BASE64;
	}

	DUMP_END;
}

static int dump_apl(DUMP_PARAMS)
{
	// Print list of APLs (empty list is allowed).
	while (p->in_max > 0) {
		if (p->total > 0) {
			DUMP_SPACE;
		}
		DUMP_APL;
	}

	DUMP_END;
}

static int dump_ds(DUMP_PARAMS)
{
	if (p->style->wrap) {
		DUMP_NUM16; DUMP_SPACE;
		DUMP_NUM8;  DUMP_SPACE;
		DUMP_NUM8;  DUMP_SPACE; WRAP_INIT;
		DUMP_HEX;
		WRAP_END;
	} else {
		DUMP_NUM16; DUMP_SPACE;
		DUMP_NUM8;  DUMP_SPACE;
		DUMP_NUM8;  DUMP_SPACE;
		DUMP_HEX;
	}

	DUMP_END;
}

static int dump_sshfp(DUMP_PARAMS)
{
	if (p->style->wrap) {
		DUMP_NUM8; DUMP_SPACE;
		DUMP_NUM8; DUMP_SPACE; WRAP_INIT;
		DUMP_HEX;
		WRAP_END;
	} else {
		DUMP_NUM8; DUMP_SPACE;
		DUMP_NUM8; DUMP_SPACE;
		DUMP_HEX;
	}

	DUMP_END;
}

static int dump_ipseckey(DUMP_PARAMS)
{
	if (p->style->wrap) {
		DUMP_NUM8; DUMP_SPACE; WRAP_INIT;
		DUMP_GATEWAY;
		WRAP_END;
	} else {
		DUMP_NUM8; DUMP_SPACE;
		DUMP_GATEWAY;
	}

	DUMP_END;
}

static int dump_rrsig(DUMP_PARAMS)
{
	DUMP_TYPE;   DUMP_SPACE;
	DUMP_NUM8;   DUMP_SPACE;
	DUMP_NUM8;   DUMP_SPACE;
	DUMP_NUM32;  DUMP_SPACE;
	DUMP_TIMESTAMP; DUMP_SPACE;
	if (p->style->wrap) {
		WRAP_INIT;
	}
	DUMP_TIMESTAMP; DUMP_SPACE;
	DUMP_NUM16;  DUMP_SPACE;
	DUMP_DNAME;  DUMP_SPACE;
	if (p->style->wrap) {
		WRAP_LINE;
	}
	if (p->style->hide_crypto) {
		DUMP_OMIT;
	} else {
		DUMP_BASE64;
	}
	if (p->style->wrap) {
		WRAP_END;
	}
	DUMP_END;
}

static int dump_nsec(DUMP_PARAMS)
{
	DUMP_DNAME; DUMP_SPACE;
	DUMP_BITMAP;

	DUMP_END;
}

static int dump_dhcid(DUMP_PARAMS)
{
	if (p->style->wrap) {
		WRAP_INIT;
		DUMP_BASE64;
		WRAP_END;
	} else {
		DUMP_BASE64;
	}

	DUMP_END;
}

static int dump_nsec3(DUMP_PARAMS)
{
	if (p->style->wrap) {
		DUMP_NUM8;   DUMP_SPACE;
		DUMP_NUM8;   DUMP_SPACE;
		DUMP_NUM16;  DUMP_SPACE;
		DUMP_SALT;   DUMP_SPACE; WRAP_INIT;
		DUMP_HASH;   DUMP_SPACE; WRAP_LINE;
		DUMP_BITMAP;
		WRAP_END;
	} else {
		DUMP_NUM8;  DUMP_SPACE;
		DUMP_NUM8;  DUMP_SPACE;
		DUMP_NUM16; DUMP_SPACE;
		DUMP_SALT;  DUMP_SPACE;
		DUMP_HASH;  DUMP_SPACE;
		DUMP_BITMAP;
	}

	DUMP_END;
}

static int dump_nsec3param(DUMP_PARAMS)
{
	DUMP_NUM8;  DUMP_SPACE;
	DUMP_NUM8;  DUMP_SPACE;
	DUMP_NUM16; DUMP_SPACE;
	DUMP_SALT;

	DUMP_END;
}

static int dump_tlsa(DUMP_PARAMS)
{
	if (p->style->wrap) {
		DUMP_NUM8; DUMP_SPACE;
		DUMP_NUM8; DUMP_SPACE;
		DUMP_NUM8; DUMP_SPACE; WRAP_INIT;
		DUMP_HEX;
		WRAP_END;
	} else {
		DUMP_NUM8; DUMP_SPACE;
		DUMP_NUM8; DUMP_SPACE;
		DUMP_NUM8; DUMP_SPACE;
		DUMP_HEX;
	}

	DUMP_END;
}

static int dump_csync(DUMP_PARAMS)
{
	DUMP_NUM32; DUMP_SPACE;
	DUMP_NUM16; DUMP_SPACE;
	DUMP_BITMAP;

	DUMP_END;
}

static int dump_zonemd(DUMP_PARAMS)
{
	if (p->style->wrap) {
		DUMP_NUM32; DUMP_SPACE;
		DUMP_NUM8;  DUMP_SPACE;
		DUMP_NUM8;  DUMP_SPACE; WRAP_INIT;
		DUMP_HEX;
		WRAP_END;
	} else {
		DUMP_NUM32; DUMP_SPACE;
		DUMP_NUM8;  DUMP_SPACE;
		DUMP_NUM8;  DUMP_SPACE;
		DUMP_HEX;
	}

	DUMP_END;
}

static int dump_l64(DUMP_PARAMS)
{
	DUMP_NUM16; DUMP_SPACE;
	DUMP_L64;

	DUMP_END;
}

static int dump_l32(DUMP_PARAMS)
{
	DUMP_NUM16; DUMP_SPACE;
	DUMP_IPV4;

	DUMP_END;
}

static int dump_eui(DUMP_PARAMS)
{
	DUMP_EUI;

	DUMP_END;
}

static int dump_tsig(DUMP_PARAMS)
{
	if (p->style->wrap) {
		DUMP_DNAME; DUMP_SPACE;
		DUMP_NUM48; DUMP_SPACE;
		DUMP_NUM16; DUMP_SPACE; WRAP_INIT;
		DUMP_TSIG_DGST; DUMP_SPACE; WRAP_LINE;
		DUMP_NUM16; DUMP_SPACE;
		DUMP_TSIG_RCODE; DUMP_SPACE;
		DUMP_TSIG_DATA;
		WRAP_END;
	} else {
		DUMP_DNAME; DUMP_SPACE;
		DUMP_NUM48; DUMP_SPACE;
		DUMP_NUM16; DUMP_SPACE;
		DUMP_TSIG_DGST; DUMP_SPACE;
		DUMP_NUM16; DUMP_SPACE;
		DUMP_TSIG_RCODE; DUMP_SPACE;
		DUMP_TSIG_DATA;
	}

	DUMP_END;
}

static int dump_uri(DUMP_PARAMS)
{
	DUMP_NUM16;     DUMP_SPACE;
	DUMP_NUM16;     DUMP_SPACE;
	DUMP_LONG_TEXT; DUMP_SPACE;

	DUMP_END;
}

static int dump_caa(DUMP_PARAMS)
{
	DUMP_NUM8;      DUMP_SPACE;
	DUMP_UNQUOTED;  DUMP_SPACE;
	DUMP_LONG_TEXT; DUMP_SPACE;

	DUMP_END;
}

static int dump_svcb(DUMP_PARAMS)
{
	DUMP_NUM16; DUMP_SPACE;
	DUMP_DNAME; DUMP_SPACE;
	if (p->style->wrap) {
		WRAP_INIT;
		if (p->in_max > 0) {
			DUMP_SVCPARAM; DUMP_SPACE;
		}
		while (p->in_max > 0) {
			WRAP_LINE; DUMP_SVCPARAM; DUMP_SPACE;
		}
		WRAP_END;
	} else {
		while (p->in_max > 0) {
			DUMP_SVCPARAM; DUMP_SPACE;
		}
	}

	DUMP_END;
}

static int dump_unknown(DUMP_PARAMS)
{
	if (p->style->wrap) {
		WRAP_INIT;
		DUMP_UNKNOWN;
		WRAP_END;
	} else {
		DUMP_UNKNOWN;
	}

	DUMP_END;
}

static int txt_dump_data(rrset_dump_params_t *p, uint16_t type)
{
	switch (type) {
		case KNOT_RRTYPE_A:
			return dump_a(p);
		case KNOT_RRTYPE_NS:
		case KNOT_RRTYPE_CNAME:
		case KNOT_RRTYPE_PTR:
		case KNOT_RRTYPE_DNAME:
			return dump_ns(p);
		case KNOT_RRTYPE_SOA:
			return dump_soa(p);
		case KNOT_RRTYPE_HINFO:
			return dump_hinfo(p);
		case KNOT_RRTYPE_MINFO:
		case KNOT_RRTYPE_RP:
			return dump_minfo(p);
		case KNOT_RRTYPE_MX:
		case KNOT_RRTYPE_AFSDB:
		case KNOT_RRTYPE_RT:
		case KNOT_RRTYPE_KX:
		case KNOT_RRTYPE_LP:
			return dump_mx(p);
		case KNOT_RRTYPE_TXT:
		case KNOT_RRTYPE_SPF:
			return dump_txt(p);
		case KNOT_RRTYPE_KEY:
		case KNOT_RRTYPE_DNSKEY:
		case KNOT_RRTYPE_CDNSKEY:
			return dump_dnskey(p);
		case KNOT_RRTYPE_AAAA:
			return dump_aaaa(p);
		case KNOT_RRTYPE_LOC:
			return dump_loc(p);
		case KNOT_RRTYPE_SRV:
			return dump_srv(p);
		case KNOT_RRTYPE_NAPTR:
			return dump_naptr(p);
		case KNOT_RRTYPE_CERT:
			return dump_cert(p);
		case KNOT_RRTYPE_APL:
			return dump_apl(p);
		case KNOT_RRTYPE_DS:
		case KNOT_RRTYPE_CDS:
			return dump_ds(p);
		case KNOT_RRTYPE_SSHFP:
			return dump_sshfp(p);
		case KNOT_RRTYPE_IPSECKEY:
			return dump_ipseckey(p);
		case KNOT_RRTYPE_RRSIG:
			return dump_rrsig(p);
		case KNOT_RRTYPE_NSEC:
			return dump_nsec(p);
		case KNOT_RRTYPE_DHCID:
		case KNOT_RRTYPE_OPENPGPKEY:
			return dump_dhcid(p);
		case KNOT_RRTYPE_NSEC3:
			return dump_nsec3(p);
		case KNOT_RRTYPE_NSEC3PARAM:
			return dump_nsec3param(p);
		case KNOT_RRTYPE_TLSA:
		case KNOT_RRTYPE_SMIMEA:
			return dump_tlsa(p);
		case KNOT_RRTYPE_CSYNC:
			return dump_csync(p);
		case KNOT_RRTYPE_ZONEMD:
			return dump_zonemd(p);
		case KNOT_RRTYPE_NID:
		case KNOT_RRTYPE_L64:
			return dump_l64(p);
		case KNOT_RRTYPE_L32:
			return dump_l32(p);
		case KNOT_RRTYPE_EUI48:
		case KNOT_RRTYPE_EUI64:
			return dump_eui(p);
		case KNOT_RRTYPE_TSIG:
			return dump_tsig(p);
		case KNOT_RRTYPE_URI:
			return dump_uri(p);
		case KNOT_RRTYPE_CAA:
			return dump_caa(p);
		case KNOT_RRTYPE_SVCB:
		case KNOT_RRTYPE_HTTPS:
			return dump_svcb(p);
		default:
			return dump_unknown(p);
	}
}

_public_
int knot_rrset_txt_dump_data(const knot_rrset_t      *rrset,
                             const size_t            pos,
                             char                    *dst,
                             const size_t            maxlen,
                             const knot_dump_style_t *style)
{
	if (rrset == NULL || dst == NULL || style == NULL) {
		return KNOT_EINVAL;
	}

	knot_rdata_t *rr_data = knot_rdataset_at(&rrset->rrs, pos);
	if (rr_data == NULL) {
		return KNOT_EINVAL; /* bad pos or rrset->rrs */
	}

	uint8_t *data = rr_data->data;
	uint16_t data_len = rr_data->len;

	rrset_dump_params_t p = {
		.style = style,
		.in = data,
		.in_max = data_len,
		.out = dst,
		.out_max = maxlen,
		.total = 0,
		.ret = 0
	};

	int ret;

	// Allow empty rdata with the CH class (knsupdate).
	if (data_len == 0 && rrset->rclass != KNOT_CLASS_IN) {
		ret = 0;
	} else if (style->generic) {
		ret = dump_unknown(&p);
	} else {
		ret = txt_dump_data(&p, rrset->type);
	}

	// Terminate the string just in case.
	if (ret < 0 || ret >= maxlen) {
		return KNOT_ESPACE;
	}
	dst[ret] = '\0';

	return ret;
}

_public_
int knot_rrset_txt_dump_header(const knot_rrset_t      *rrset,
                               const uint32_t          ttl,
                               char                    *dst,
                               const size_t            maxlen,
                               const knot_dump_style_t *style)
{
	if (rrset == NULL || dst == NULL || style == NULL) {
		return KNOT_EINVAL;
	}

	size_t len = 0;
	char   buf[32];
	int    ret;

	// Dump rrset owner.
	char *name = knot_dname_to_str_alloc(rrset->owner);
	if (style->ascii_to_idn != NULL) {
		style->ascii_to_idn(&name);
	}
	char sep = strlen(name) < 4 * TAB_WIDTH ? '\t' : ' ';
	ret = snprintf(dst + len, maxlen - len, "%-20s%c", name, sep);
	free(name);
	SNPRINTF_CHECK(ret, maxlen - len);
	len += ret;

	// Set white space separation character.
	sep = style->wrap ? ' ' : '\t';

	// Dump rrset ttl.
	if (style->show_ttl) {
		if (style->empty_ttl) {
			ret = snprintf(dst + len, maxlen - len, "%c", sep);
		} else if (style->human_ttl) {
			// Create human readable ttl string.
			if (time_to_human_str(buf, sizeof(buf), ttl) < 0) {
				return KNOT_ESPACE;
			}
			ret = snprintf(dst + len, maxlen - len, "%s%c",
			               buf, sep);
		} else {
			ret = snprintf(dst + len, maxlen - len, "%u%c", ttl, sep);
		}
		SNPRINTF_CHECK(ret, maxlen - len);
		len += ret;
	}

	// Dump rrset class.
	if (style->show_class) {
		if (knot_rrclass_to_string(rrset->rclass, buf, sizeof(buf)) < 0) {
			return KNOT_ESPACE;
		}
		ret = snprintf(dst + len, maxlen - len, "%-2s%c", buf, sep);
		SNPRINTF_CHECK(ret, maxlen - len);
		len += ret;
	}

	// Dump rrset type.
	if (style->generic) {
		if (snprintf(buf, sizeof(buf), "TYPE%u", rrset->type) < 0) {
			return KNOT_ESPACE;
		}
	} else if (knot_rrtype_to_string(rrset->type, buf, sizeof(buf)) < 0) {
		return KNOT_ESPACE;
	}
	if (rrset->rrs.count > 0) {
		ret = snprintf(dst + len, maxlen - len, "%s%c", buf, sep);
	} else {
		ret = snprintf(dst + len, maxlen - len, "%s", buf);
	}
	SNPRINTF_CHECK(ret, maxlen - len);
	len += ret;

	return len;
}

static int rrset_txt_dump(const knot_rrset_t      *rrset,
                          char                    *dst,
                          const size_t            maxlen,
                          const knot_dump_style_t *style)
{
	if (rrset == NULL || dst == NULL || style == NULL) {
		return KNOT_EINVAL;
	}

	size_t len = 0;
	size_t color_len = (style->color != NULL ? strlen(style->color) : 0);
	size_t reset_len = (style->color != NULL ? strlen(COL_RST(true)) : 0);

	dst[0] = '\0';

	// Loop over rdata in rrset.
	uint16_t rr_count = rrset->rrs.count;
	knot_rdata_t *rr = rrset->rrs.rdata;
	for (uint16_t i = 0; i < rr_count; i++) {
		// Put color prefix before every record.
		if (color_len > 0) {
			if (len >= maxlen - color_len) {
				return KNOT_ESPACE;
			}
			memcpy(dst + len, style->color, color_len);
			len += color_len;
		}

		// Dump rdata owner, class, ttl and type.
		uint32_t ttl = ((style->original_ttl && rrset->type == KNOT_RRTYPE_RRSIG) ?
		                knot_rrsig_original_ttl(rr) : rrset->ttl);

		int ret = knot_rrset_txt_dump_header(rrset, ttl, dst + len,
		                                     maxlen - len, style);
		if (ret < 0) {
			return KNOT_ESPACE;
		}
		len += ret;

		// Dump rdata as such.
		ret = knot_rrset_txt_dump_data(rrset, i, dst + len,
		                               maxlen - len, style);
		if (ret < 0) {
			return KNOT_ESPACE;
		}
		len += ret;

		// Reset the color.
		if (reset_len > 0) {
			if (len >= maxlen - reset_len) {
				return KNOT_ESPACE;
			}
			memcpy(dst + len, COL_RST(true), reset_len);
			len += reset_len;
		}

		// Terminate line.
		if (len >= maxlen - 1) {
			return KNOT_ESPACE;
		}
		dst[len++] = '\n';
		dst[len] = '\0';

		rr = knot_rdataset_next(rr);
	}

	return len;
}

_public_
int knot_rrset_txt_dump(const knot_rrset_t      *rrset,
                        char                    **dst,
                        size_t                  *dst_size,
                        const knot_dump_style_t *style)
{
	if (dst == NULL || dst_size == NULL) {
		return KNOT_EINVAL;
	}

	while (1) {
		int ret = rrset_txt_dump(rrset, *dst, *dst_size, style);
		if (ret != KNOT_ESPACE) {
			return ret;
		}

		size_t new_dst_size = 2 * (*dst_size);
		if (new_dst_size > RRSET_DUMP_LIMIT) {
			return KNOT_ESPACE;
		}

		char * new_dst = malloc(new_dst_size);
		if (new_dst == NULL) {
			return KNOT_ENOMEM;
		}

		free(*dst);
		*dst = new_dst;
		*dst_size = new_dst_size;
	}
}
