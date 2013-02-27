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

#include "libknot/rrset-dump.h"

#include <stdlib.h>			// free
#include <stdbool.h>			// bool
#include <string.h>			// memcpy
#include <time.h>			// strftime
#include <ctype.h>			// isprint
#include <arpa/inet.h>			// ntohs
#include <sys/socket.h>			// AF_INET (BSD)
#include <netinet/in.h>			// in_addr (BSD)

#include "common/errcode.h"		// KNOT_EOK
#include "common/base64.h"		// base64
#include "common/base32hex.h"		// base32hex
#include "common/descriptor_new.h"	// KNOT_RRTYPE

#define BLOCK_WIDTH		40
#define BLOCK_INDENT		"\n\t\t\t\t"
#define BLOCK_INDENT_LEN	5

inline static uint32_t write_indent(char *out) {
	// Write padding block.
	memcpy(out, &BLOCK_INDENT, BLOCK_INDENT_LEN);
	return BLOCK_INDENT_LEN;
}

static int32_t wire_num8_to_str(const uint8_t  *in,
                                char           *out,
                                const uint32_t out_len)
{
	uint8_t data = *in;
	int32_t ret;

	// Write number.
	ret = snprintf(out, out_len, "%u", data);

	// Check output length.
	if (ret <= 0 || ret >= out_len) {
		return -1;
	}

	return ret;
}

static int32_t wire_num16_to_str(const uint8_t  *in,
                                 char           *out,
                                 const uint32_t out_len)
{
	uint16_t data;
	int32_t  ret;

	// Copy input data correctly.
	if (memcpy(&data, in, sizeof(data)) == NULL) {
		return -1;
	}

	// Write number.
	ret = snprintf(out, out_len, "%u", ntohs(data));

	// Check output length.
	if (ret <= 0 || ret >= out_len) {
		return -1;
	}

	return ret;
}

static int32_t wire_num32_to_str(const uint8_t  *in,
                                 char           *out,
                                 const uint32_t out_len)
{
	uint32_t data;
	int32_t  ret;

	// Copy input data correctly.
	if (memcpy(&data, in, sizeof(data)) == NULL) {
		return -1;
	}

	// Write number.
	ret = snprintf(out, out_len, "%u", ntohl(data));

	// Check output length.
	if (ret <= 0 || ret >= out_len) {
		return -1;
	}

	return ret;
}

static int32_t wire_ipv4_to_str(const uint8_t  *in,
                                char           *out,
                                const uint32_t out_len)
{
	struct in_addr addr4;

	// Fill address structure.
	if (memcpy(&(addr4.s_addr), in, sizeof(addr4.s_addr)) == NULL) {
		return -1;
	}

	// Write address.
	if (inet_ntop(AF_INET, &addr4, out, out_len) == NULL) {
		return -1;
	}

	return strlen(out);
}

static int32_t wire_ipv6_to_str(const uint8_t  *in,
                                char           *out,
                                const uint32_t out_len)
{
	struct in6_addr addr6;

	// Fill address structure.
	if (memcpy(&(addr6.s6_addr), in, sizeof(addr6.s6_addr)) == NULL) {
		return -1;
	}

	// Write address.
	if (inet_ntop(AF_INET6, &addr6, out, out_len) == NULL) {
		return -1;
	}

	return strlen(out);
}

static int32_t wire_type_to_str(const uint8_t  *in,
                                char           *out,
                                const uint32_t out_len)
{
	uint16_t data;
	int32_t  ret;
	char     type[32];

	// Copy input data correctly.
	if (memcpy(&data, in, sizeof(data)) == NULL) {
		return -1;
	}

	// Write record type name.
	if (knot_rrtype_to_string(ntohs(data), type, sizeof(type)) <= 0) {
		return -1;
	}

	ret = snprintf(out, out_len, "%s", type);

	// Check output length.
	if (ret <= 0 || ret >= out_len) {
		return -1;
	}

	return ret;
}

static int32_t wire_base64_to_str(const uint8_t  *in,
                                  const uint32_t in_len,
                                  char           *out,
                                  const uint32_t out_len,
                                  const bool     wrap)
{
	int32_t  ret;
	uint32_t total_len = 0;

	// One-line vs multi-line mode.
	if (wrap == false) {
		// Encode data directly to the output.
		ret = base64_encode(in, in_len, (uint8_t *)out, out_len);

		// Check output.
		if (ret <= 0) {
			return -1;
		}

		total_len = ret;
	} else {
		int32_t src_begin, src_len;
		char    *buf;

		// Encode data to the temporary buffer.
		ret = base64_encode_alloc(in, in_len, (uint8_t **)&buf);

		// Check output and output buffer for additional characters.
		if (ret <= 0 ||
		    //               2 ~ 1 final indent + 1 int rounding.
		    out_len < ret + (2 + ret / BLOCK_WIDTH) * BLOCK_INDENT_LEN)
		{
			return -1;
		}

		// Loop which wraps base64 block in more lines.
		for (src_begin = 0; src_begin < ret; src_begin += BLOCK_WIDTH) {
			// Write indent block.
			total_len += write_indent(out + total_len);

			// Compute block length (the last one can be shorter).
			src_len = (ret - src_begin) < BLOCK_WIDTH ?
			          (ret - src_begin) : BLOCK_WIDTH;

			// Write data block.
			memcpy(out + total_len, buf + src_begin, src_len);
			total_len += src_len;
		}

		// Write trailing indent block.
		total_len += write_indent(out + total_len);

		// Destroy temporary buffer.
		free(buf);
	}

	// String termination.
	if (out_len > total_len) {
		out[total_len] = '\0';
	} else {
		return -1;
	}

	return total_len;
}

static int32_t wire_base32hex_to_str(const uint8_t  *in,
                                     const uint32_t in_len,
                                     char           *out,
                                     const uint32_t out_len,
                                     const bool     wrap)
{
	int32_t  ret;
	uint32_t total_len = 0;

	// One-line vs multi-line mode.
	if (wrap == false) {
		// Encode data directly to the output.
		ret = base32hex_encode(in, in_len, (uint8_t *)out, out_len);

		// Check output.
		if (ret <= 0) {
			return -1;
		}

		total_len = ret;
	} else {
		int32_t src_begin, src_len;
		char    *buf;

		// Encode data to the temporary buffer.
		ret = base32hex_encode_alloc(in, in_len, (uint8_t **)&buf);

		// Check output and output buffer for additional characters.
		if (ret <= 0 ||
		    //               2 ~ 1 final indent + 1 int rounding.
		    out_len < ret + (2 + ret / BLOCK_WIDTH) * BLOCK_INDENT_LEN)
		{
			return -1;
		}

		// Loop which wraps base32hex block in more lines.
		for (src_begin = 0; src_begin < ret; src_begin += BLOCK_WIDTH) {
			// Write indent block.
			total_len += write_indent(out + total_len);

			// Compute block length (the last one can be shorter).
			src_len = (ret - src_begin) < BLOCK_WIDTH ?
			          (ret - src_begin) : BLOCK_WIDTH;

			// Write data block.
			memcpy(out + total_len, buf + src_begin, src_len);
			total_len += src_len;
		}

		// Write trailing indent block.
		total_len += write_indent(out + total_len);

		// Destroy temporary buffer.
		free(buf);
	}

	// String termination.
	if (out_len > total_len) {
		out[total_len] = '\0';
	} else {
		return -1;
	}

	return total_len;
}

static void hex_dump(const uint8_t *in, const uint32_t in_len, char *out)
{
	static const char hex[] = "0123456789ABCDEF";

	uint32_t i;

	for (i = 0; i < in_len; i++) {
		out[2 * i]     = hex[in[i] / 16];
		out[2 * i + 1] = hex[in[i] % 16];
	}
}

static int32_t wire_hex_to_str(const uint8_t  *in,
                               const uint32_t in_len,
                               char           *out,
                               const uint32_t out_len,
                               const bool     wrap)
{
	uint32_t total_len = 0;

	// One-line vs multi-line mode.
	if (wrap == false) {
		// Check output (including termination).
		if (out_len <= 2 * in_len) {
			return -1;
		}

		// Encode data directly to the output.
		hex_dump(in, in_len, out);

		total_len = 2 * in_len;
	} else {
		int32_t src_begin, src_len;

		// Check output buffer (including termination).
		//           = ~ '\0'    2 ~ 1 final indent + 1 int rounding.
		if (out_len <= in_len + (2 + (2 * in_len) / BLOCK_WIDTH) *
		              BLOCK_INDENT_LEN)
		{
			return -1;
		}

		// Loop which wraps hex block in more lines.
		for (src_begin = 0; src_begin < in_len;
		     src_begin += BLOCK_WIDTH / 2)
		{
			// Write indent block.
			total_len += write_indent(out + total_len);

			// Compute block length (the last one can be shorter).
			src_len = (in_len - src_begin) < (BLOCK_WIDTH / 2) ?
			          (in_len - src_begin) : (BLOCK_WIDTH / 2);

			// Write data block.
			hex_dump(in + src_begin, src_len, out + total_len);
			total_len += 2 * src_len;
		}

		// Write trailing indent block.
		total_len += write_indent(out + total_len);
	}

	// String termination.
	out[total_len] = '\0';

	return total_len;
}

static int32_t wire_text_to_str(const uint8_t  *in,
                                const uint32_t in_len,
                                char           *out,
                                const uint32_t out_len)
{
	char     ch;
	uint32_t i, total_len = 0;

	// Check length of the output buffer (+ 2x'"' + 1x'\0').
	if (out_len < in_len + 3) {
		return -1;
	}

	// Opening quoatition.
	out[total_len++] = '"';

	// Loop over all characters.
	for (i = 0; i < in_len; i++) {
		ch = (char)in[i];

		if (isprint(ch) != 0) {
			// For special chars print leading slash.
			if (ch == '\\' || ch == '"') {
				out[total_len++] = '\\';
			}

			out[total_len++] = ch;
		} else {
			// Check output buffer length for additional space.
			if (out_len <= total_len + 5) {
				return -1;
			}

			// Unprintable chars encode via \ddd notation..
			sprintf(out + total_len, "\\%03u", ch);
			total_len += 4;
		}
	}

	// Closing quoatition.
	out[total_len++] = '"';
	out[total_len] = '\0';

	return total_len;
}

static int32_t wire_timestamp_to_str(const uint8_t  *in,
                                     char           *out,
                                     const uint32_t out_len)
{
	uint32_t  data;
	int32_t   ret;
	time_t    timestamp;

	// Copy input data correctly.
	if (memcpy(&data, in, sizeof(data)) == NULL) {
		return -1;
	}

	// Convert number from network to host byte order.
	timestamp = ntohl(data);

	// Write formated timestamp.
	ret = strftime(out, out_len, "%Y%m%d%H%M%S", gmtime(&timestamp));

	// Check output length.
	if (ret <= 0) {
		return -1;
	}

	return ret;
}

static int32_t time_to_human_str(uint32_t       data,
                                 char           *out,
                                 const uint32_t out_len)
{
	uint32_t  num, total_len = 0;
	int32_t   ret;

	// Process days.
	num = data / 86400;
	if (num > 0) {
		ret = snprintf(out + total_len, out_len - total_len,
		               "%ud", num);

		if (ret <= 0 || ret >= out_len - total_len) {
			return -1;
		}

		total_len += ret;
		data -= num * 86400;
	}

	// Process hours.
	num = data / 3600;
	if (num > 0) {
		ret = snprintf(out + total_len, out_len - total_len,
		               "%uh", num);

		if (ret <= 0 || ret >= out_len - total_len) {
			return -1;
		}

		total_len += ret;
		data -= num * 3600;
	}

	// Process minutes.
	num = data / 60;
	if (num > 0) {
		ret = snprintf(out + total_len, out_len - total_len,
		               "%um", num);

		if (ret <= 0 || ret >= out_len - total_len) {
			return -1;
		}

		total_len += ret;
		data -= num * 60;
	}

	// Process seconds.
	num = data;
	if (num > 0) {
		ret = snprintf(out + total_len, out_len - total_len,
		               "%us", num);

		if (ret <= 0 || ret >= out_len - total_len) {
			return -1;
		}

		total_len += ret;
	}

	return total_len;
}

static int32_t wire_time_to_human_str(const uint8_t  *in,
                                      char           *out,
                                      const uint32_t out_len)
{
	uint32_t  data;

	// Copy input data correctly.
	if (memcpy(&data, in, sizeof(data)) == NULL) {
		return -1;
	}

	// Convert number from network to host byte order.
	data = ntohl(data);

	return time_to_human_str(data, out, out_len);
}

static int32_t wire_bitmap_to_str(const uint8_t  *in,
                                  const uint32_t in_len,
                                  char           *out,
                                  const uint32_t out_len)
{
	uint32_t i = 0, j, total_len = 0;
	uint16_t type_num;
	uint8_t  win, bitmap_len;
	char     type[32];

	// Loop over bitmap window array (can be empty).
	while (i < in_len) {
		// First byte is window number.
		win = in[i++];

		// Check window length (len must follow).
		if (i >= in_len) {
			return -1;
		}

		// Second byte is window length.
		bitmap_len = in[i++];

		// Check window length (len bytes must follow).
		if (i + bitmap_len > in_len) {
			return -1;
		}

		// Bitmap processing.
		for (j = 0; j < (bitmap_len * 8); j++) {
			if ((in[i + j / 8] & (128 >> (j % 8))) != 0) {
				type_num = win * 256 + j;

				if (knot_rrtype_to_string(type_num, type,
				                          sizeof(type)) <= 0) {
					return -1;
				}

				printf("%s ", type);
			}
		}

		i += bitmap_len;
	}

	return total_len;
}

static int32_t dname_to_str(const uint8_t  *in,
                            char           *out,
                            const uint32_t out_len)
{
	knot_dname_t *dname;
	memcpy(&dname, in, sizeof(knot_dname_t *));

	char *dname_str = knot_dname_to_str(dname);

	int ret = snprintf(out, out_len, "%s", dname_str);

	free(dname_str);

	if (ret < 0 || ret >= out_len) {
		return -1;
	}

	return ret;
}

static int dump_rdata_a(const uint8_t *data, const size_t len, char *dst,
                        const size_t maxlen)
{
	return wire_ipv4_to_str(data, dst, maxlen);
}

static int dump_rdata_ns(const uint8_t *data, const size_t len, char *dst,
                         const size_t maxlen)
{

	return dname_to_str(data, dst, maxlen);
}

static int dump_rdata_aaaa(const uint8_t *data, const size_t len, char *dst,
                           const size_t maxlen)
{
	return wire_ipv6_to_str(data, dst, maxlen);
}

int knot_rrset_txt_dump_data(const knot_rrset_t *rrset, const size_t pos,
                             char *dst, const size_t maxlen)
{
	if (rrset == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

	const uint8_t *data = knot_rrset_get_rdata(rrset, pos);
	size_t        data_len = rrset_rdata_item_size(rrset, pos);

	int ret = 0;

	switch (knot_rrset_type(rrset)) {
		case KNOT_RRTYPE_A:
			ret = dump_rdata_a(data, data_len, dst, maxlen);
			break;
		case KNOT_RRTYPE_NS:
			ret = dump_rdata_ns(data, data_len, dst, maxlen);
			break;
		case KNOT_RRTYPE_CNAME:
			break;
		case KNOT_RRTYPE_SOA:
			break;
		case KNOT_RRTYPE_PTR:
			break;
		case KNOT_RRTYPE_HINFO:
			break;
		case KNOT_RRTYPE_MINFO:
			break;
		case KNOT_RRTYPE_MX:
			break;
		case KNOT_RRTYPE_TXT:
			break;
		case KNOT_RRTYPE_RP:
			break;
		case KNOT_RRTYPE_AFSDB:
			break;
		case KNOT_RRTYPE_RT:
			break;
		case KNOT_RRTYPE_KEY:
			break;
		case KNOT_RRTYPE_AAAA:
			ret = dump_rdata_aaaa(data, data_len, dst, maxlen);
			break;
		case KNOT_RRTYPE_LOC:
			break;
		case KNOT_RRTYPE_SRV:
			break;
		case KNOT_RRTYPE_NAPTR:
			break;
		case KNOT_RRTYPE_KX:
			break;
		case KNOT_RRTYPE_CERT:
			break;
		case KNOT_RRTYPE_DNAME:
			break;
		case KNOT_RRTYPE_APL:
			break;
		case KNOT_RRTYPE_DS:
			break;
		case KNOT_RRTYPE_SSHFP:
			break;
		case KNOT_RRTYPE_IPSECKEY:
			break;
		case KNOT_RRTYPE_RRSIG:
			break;
		case KNOT_RRTYPE_NSEC:
			break;
		case KNOT_RRTYPE_DNSKEY:
			break;
		case KNOT_RRTYPE_DHCID:
			break;
		case KNOT_RRTYPE_NSEC3:
			break;
		case KNOT_RRTYPE_NSEC3PARAM:
			break;
		case KNOT_RRTYPE_TLSA:
			break;
		case KNOT_RRTYPE_SPF:
			break;
		default:
			break;
	}

	return ret;
}

int knot_rrset_txt_dump_header(const knot_rrset_t *rrset, char *dst,
                               const size_t maxlen)
{
	if (rrset == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

	size_t len = 0;
	char   buf[32];
	int    ret;

	// Dump rrset owner.
	char *name = knot_dname_to_str(rrset->owner);
	ret = snprintf(dst + len, maxlen - len, "%-20s\t", name);
	free(name);
	if (ret < 0 || ret >= maxlen - len) {
		return KNOT_ESPACE;
	}
	len += ret;

	// Dump rrset ttl.
	if (1) {	
		ret = snprintf(dst + len, maxlen - len, "%6u\t", rrset->ttl);
	} else {
		ret = snprintf(dst + len, maxlen - len, "     \t");
	}
	if (ret < 0 || ret >= maxlen - len) {
		return KNOT_ESPACE;
	}
	len += ret;

	// Dump rrset class.
	if (1) {
		if (knot_rrclass_to_string(rrset->rclass, buf, sizeof(buf)) < 0)
		{
			return KNOT_ESPACE;
		}
		ret = snprintf(dst + len, maxlen - len, "%-2s\t", buf);
	} else {
		ret = snprintf(dst + len, maxlen - len, "  \t");
	}
	if (ret < 0 || ret >= maxlen - len) {
		return KNOT_ESPACE;
	}
	len += ret;

	// Dump rrset type.
	if (knot_rrtype_to_string(rrset->type, buf, sizeof(buf)) < 0) {
		return KNOT_ESPACE;
	}
	ret = snprintf(dst + len, maxlen - len, "%-5s\t", buf);
	if (ret < 0 || ret >= maxlen - len) {
		return KNOT_ESPACE;
	}
	len += ret;
	
	return len;
}

int knot_rrset_txt_dump(const knot_rrset_t *rrset, char *dst, const size_t maxlen)
{
	if (rrset == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

	size_t len = 0;
	int    ret;

	// Loop over rdata in rrset.
	for (size_t i = 0; i < rrset->rdata_count; i++) {
		// Dump rdata owner, class, ttl and type.
		ret = knot_rrset_txt_dump_header(rrset, dst + len, maxlen - len);
		if (ret < 0) {
			return KNOT_ESPACE;
		}
		len += ret;

		// Dump rdata as such.
		ret = knot_rrset_txt_dump_data(rrset, i, dst + len, maxlen - len);
		if (ret < 0) {
			return KNOT_ESPACE;
		}
		len += ret;

		// Terminate line.
		if (len >= maxlen) {
			return KNOT_ESPACE;
		}
		dst[len++] = '\n';
		dst[len] = '\0';
	}

	// Dump RRSIG records if any via recursion call.
	if (rrset->rrsigs != NULL) {
		ret = knot_rrset_txt_dump(rrset->rrsigs, dst + len, maxlen - len);
		if (ret < 0) {
			return KNOT_ESPACE;
		}
		len += ret;
	}

	return len;
}
