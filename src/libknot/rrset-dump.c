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

typedef struct {
	uint8_t *in;
	size_t  in_max;
	char    *out;
	size_t  out_max;
	size_t  total;
	int     ret;
} rrset_dump_params_t;

static void dump_string(rrset_dump_params_t *p, const char *str)
{
	size_t in_len = strlen(str);

	p->ret = -1;

	// Check input size.
	if (in_len > p->in_max) {
		return;
	}

	// Copy string including termination '\0'!
	if (memcpy(p->out, str, in_len + 1) == NULL) {
		return;
	}

	// Fill in output.
	p->out += in_len;
	p->out_max -= in_len;
	p->total += in_len;
	p->ret = 0;
}

static void wire_num8_to_str(rrset_dump_params_t *p)
{
	uint8_t data = *(p->in);
	size_t  in_len = sizeof(data);
	size_t  out_len = 0;

	p->ret = -1;

	// Check input size.
	if (in_len > p->in_max) {
		return;
	}

	// Write number.
	int ret = snprintf(p->out, p->out_max, "%u", data);
	if (ret <= 0 || ret >= p->out_max) {
		return;
	}
	out_len = ret;

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
	p->ret = 0;
}

static void wire_num16_to_str(rrset_dump_params_t *p)
{
	uint16_t data;
	size_t   in_len = sizeof(data);
	size_t   out_len = 0;

	p->ret = -1;

	// Check input size.
	if (in_len > p->in_max) {
		return;
	}

	// Fill in input data.
	if (memcpy(&data, p->in, in_len) == NULL) {
		return;
	}

	// Write number.
	int ret = snprintf(p->out, p->out_max, "%u", ntohs(data));
	if (ret <= 0 || ret >= p->out_max) {
		return;
	}
	out_len = ret;

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
	p->ret = 0;
}

static void wire_num32_to_str(rrset_dump_params_t *p)
{
	uint32_t data;
	size_t   in_len = sizeof(data);
	size_t   out_len = 0;

	p->ret = -1;

	// Check input size.
	if (in_len > p->in_max) {
		return;
	}

	// Fill in input data.
	if (memcpy(&data, p->in, in_len) == NULL) {
		return;
	}

	// Write number.
	int ret = snprintf(p->out, p->out_max, "%u", ntohl(data));
	if (ret <= 0 || ret >= p->out_max) {
		return;
	}
	out_len = ret;

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
	p->ret = 0;
}

static void wire_ipv4_to_str(rrset_dump_params_t *p)
{
	struct in_addr addr4;
	size_t in_len = sizeof(addr4.s_addr);
	size_t out_len = 0;

	p->ret = -1;

	// Check input size.
	if (in_len > p->in_max) {
		return;
	}

	// Fill in input data.
	if (memcpy(&(addr4.s_addr), p->in, in_len) == NULL) {
		return;
	}

	// Write address.
	if (inet_ntop(AF_INET, &addr4, p->out, p->out_max) == NULL) {
		return;
	}
	out_len = strlen(p->out);

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
	p->ret = 0;
}

static void wire_ipv6_to_str(rrset_dump_params_t *p)
{
	struct in6_addr addr6;
	size_t in_len = sizeof(addr6.s6_addr);
	size_t out_len = 0;

	p->ret = -1;

	// Check input size.
	if (in_len > p->in_max) {
		return;
	}

	// Fill in input data.
	if (memcpy(&(addr6.s6_addr), p->in, in_len) == NULL) {
		return;
	}

	// Write address.
	if (inet_ntop(AF_INET6, &addr6, p->out, p->out_max) == NULL) {
		return;
	}
	out_len = strlen(p->out);

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
	p->ret = 0;
}

static void wire_type_to_str(rrset_dump_params_t *p)
{
	char     type[32];
	uint16_t data;
	size_t   in_len = sizeof(data);
	size_t   out_len = 0;

	p->ret = -1;

	// Check input size.
	if (in_len > p->in_max) {
		return;
	}

	// Fill in input data.
	if (memcpy(&data, p->in, in_len) == NULL) {
		return;
	}

	// Get record type name string.
	if (knot_rrtype_to_string(ntohs(data), type, sizeof(type)) <= 0) {
		return;
	}

	// Write string.
	int ret = snprintf(p->out, p->out_max, "%s", type);
	if (ret <= 0 || ret >= p->out_max) {
		return;
	}
	out_len = ret;

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
	p->ret = 0;
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

typedef int (*encode_t)(const uint8_t *in, const uint32_t in_len,
                        uint8_t *out, const uint32_t out_len);

typedef int (*encode_alloc_t)(const uint8_t *in, const uint32_t in_len,
                              uint8_t **out);

static void wire_data_encode_to_str(rrset_dump_params_t *p,
                                    encode_t enc, encode_alloc_t enc_alloc)
{
	int    ret;
	size_t in_len = p->in_max;

	p->ret = -1;

	// One-line vs multi-line mode.
	if (false) {
		// Encode data directly to the output.
		ret = enc(p->in, in_len, (uint8_t *)(p->out), p->out_max);
		if (ret <= 0) {
			return;
		}
		size_t out_len = ret;

		p->out += out_len;
		p->out_max -= out_len;
		p->total += out_len;
	} else {
		int  src_begin, src_len;
		char *buf;

		// Encode data to the temporary buffer.
		ret = enc_alloc(p->in, in_len, (uint8_t **)&buf);
		if (ret <= 0) {
			return;
		}

		// Loop which wraps base64 block in more lines.
		for (src_begin = 0; src_begin < ret; src_begin += BLOCK_WIDTH) {
			// Write indent block.
			dump_string(p, BLOCK_INDENT);
			if (p->ret != 0) {
				free(buf);
				return;
			}

			// Compute block length (the last one can be shorter).
			src_len = (ret - src_begin) < BLOCK_WIDTH ?
			          (ret - src_begin) : BLOCK_WIDTH;

			if (src_len > p->out_max) {
				free(buf);
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

	// String termination.
	if (p->out_max > 0) {
		p->out = '\0';
	} else {
		return;
	}

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->ret = 0;
}

static void wire_text_to_str(rrset_dump_params_t *p)
{
	// First byte is string length.
	size_t in_len = *(p->in);
	p->in++;
	p->in_max--;

	p->ret = -1;

	// Check if the given length makes sense.
	if (in_len > p->in_max) {
		return;
	}

	// Opening quoatition.
	dump_string(p, "\"");
	if (p->ret != 0) {
		return;
	}

	// Loop over all characters.
	for (size_t i = 0; i < in_len; i++) {
		char ch = (char)(p->in)[i];

		if (isprint(ch) != 0) {
			// For special character print leading slash.
			if (ch == '\\' || ch == '"') {
				if (p->out_max == 0) {
					return;
				}

				*p->out = '\\';
				p->out++;
				p->out_max--;
				p->total++;
			}

			// Print text character.
			if (p->out_max == 0) {
				return;
			}

			*p->out = ch;
			p->out++;
			p->out_max--;
			p->total++;
		} else {
			// Unprintable character encode via \ddd notation.
			int ret = snprintf(p->out, p->out_max,"\\%03u", ch);
			if (ret <= 0 || ret >= p->out_max) {
				return;
			}

			p->out += ret;
			p->out_max -= ret;
			p->total += ret;
		}
	}

	// Closing quoatition.
	dump_string(p, "\"");
	if (p->ret != 0) {
		return;
	}

	// String termination.
	if (p->out_max > 0) {
		*p->out = '\0';
	} else {
		return;
	}

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->ret = 0;
}

static int wire_timestamp_to_str(const uint8_t *in,
                                 char          *out,
                                 const size_t  out_len)
{
	size_t data;
	time_t timestamp;
	int   ret;

	// Copy input data correctly.
	if (memcpy(&data, in, sizeof(data)) == NULL) {
		return -1;
	}

	// Convert number from network to host byte order.
	timestamp = ntohl(data);

	// Write formated timestamp.
	ret = strftime(out, out_len, "%Y%m%d%H%M%S", gmtime(&timestamp));
	if (ret <= 0) {
		return -1;
	}

	return ret;
}

static int time_to_human_str(uint32_t     data,
                             char         *out,
                             const size_t out_len)
{
	size_t   total_len = 0;
	uint32_t num;
	int      ret;

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

static int wire_time_to_human_str(const uint8_t *in,
                                  char          *out,
                                  const size_t  out_len)
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

static int wire_bitmap_to_str(const uint8_t *in,
                              const size_t  in_len,
                              char          *out,
                              const size_t  out_len)
{
	size_t i = 0, j, total_len = 0;
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

static void wire_dname_to_str(rrset_dump_params_t *p)
{
	knot_dname_t *dname;
	size_t in_len = sizeof(knot_dname_t *);
	size_t out_len = 0;

	p->ret = -1;

	// Check input size.
	if (in_len > p->in_max) {
		return;
	}

	// Fill in input data.
	if (memcpy(&dname, p->in, in_len) == NULL) {
		return;
	}

	// Write dname string.
	char *dname_str = knot_dname_to_str(dname);
	int ret = snprintf(p->out, p->out_max, "%s", dname_str);
	free(dname_str);
	if (ret < 0 || ret >= p->out_max) {
		return;
	}
	out_len = ret;

	// Fill in output.
	p->in += in_len;
	p->in_max -= in_len;
	p->out += out_len;
	p->out_max -= out_len;
	p->total += out_len;
	p->ret = 0;
}

#define DUMP_PARAMS	uint8_t *in, const size_t in_len, \
			char *out, const size_t out_max
#define DUMP_INIT	rrset_dump_params_t p = { in, in_len, out, out_max }
#define	DUMP_END	return p.total

#define CHECK_RET(p)	if (p.ret != 0) return -1

#define DUMP_SPACE	dump_string(&p, " "); CHECK_RET(p);
#define DUMP_NUM8	wire_num8_to_str(&p); CHECK_RET(p);
#define DUMP_NUM16	wire_num16_to_str(&p); CHECK_RET(p);
#define DUMP_NUM32	wire_num32_to_str(&p); CHECK_RET(p);
#define DUMP_DNAME	wire_dname_to_str(&p); CHECK_RET(p);
#define DUMP_IPV4	wire_ipv4_to_str(&p); CHECK_RET(p);
#define DUMP_IPV6	wire_ipv6_to_str(&p); CHECK_RET(p);
#define DUMP_TYPE	wire_type_to_str(&p); CHECK_RET(p);
#define DUMP_HEX	{ wire_data_encode_to_str(&p, &hex_encode, \
				&hex_encode_alloc); CHECK_RET(p); }
#define DUMP_BASE64	{ wire_data_encode_to_str(&p, &base64_encode, \
				&base64_encode_alloc); CHECK_RET(p); }
#define DUMP_BASE32HEX	{ wire_data_encode_to_str(&p, &base64_encode, \
				&base64_encode_alloc); CHECK_RET(p); }
#define DUMP_TEXT	wire_text_to_str(&p); CHECK_RET(p);

static int dump_a(DUMP_PARAMS)
{
	DUMP_INIT;

	DUMP_IPV4;

	DUMP_END;
}

static int dump_ns(DUMP_PARAMS)
{
	DUMP_INIT;

	DUMP_DNAME;

	DUMP_END;
}

static int dump_soa(DUMP_PARAMS)
{
	DUMP_INIT;

	DUMP_DNAME; DUMP_SPACE;
	DUMP_DNAME; DUMP_SPACE;
	DUMP_NUM32; DUMP_SPACE;
	DUMP_NUM32; DUMP_SPACE;
	DUMP_NUM32; DUMP_SPACE;
	DUMP_NUM32;

	DUMP_END;
}

static int dump_hinfo(DUMP_PARAMS)
{
	DUMP_INIT;

	DUMP_TEXT; DUMP_SPACE;
	DUMP_TEXT;

	DUMP_END;
}

static int dump_mx(DUMP_PARAMS)
{
	DUMP_INIT;

	DUMP_NUM16; DUMP_SPACE;
	DUMP_DNAME;

	DUMP_END;
}

static int dump_aaaa(DUMP_PARAMS)
{
	DUMP_INIT;

	DUMP_IPV6;

	DUMP_END;
}

static int dump_rrsig(DUMP_PARAMS)
{
	DUMP_INIT;

	DUMP_TYPE; DUMP_SPACE;
	DUMP_NUM8; DUMP_SPACE;
	DUMP_NUM8; DUMP_SPACE;
	DUMP_NUM32; DUMP_SPACE;
	DUMP_NUM32; DUMP_SPACE;
	DUMP_NUM32; DUMP_SPACE;
	DUMP_NUM16; DUMP_SPACE;
	DUMP_DNAME; DUMP_SPACE;
	DUMP_BASE64;

	DUMP_END;
}

int knot_rrset_txt_dump_data(const knot_rrset_t *rrset,
                             const size_t       pos,
                             char               *dst,
                             const size_t       maxlen)
{
	if (rrset == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t *data = knot_rrset_get_rdata(rrset, pos);
	size_t  data_len = rrset_rdata_item_size(rrset, pos);

	int ret = 0;

	switch (knot_rrset_type(rrset)) {
		case KNOT_RRTYPE_A:
			ret = dump_a(data, data_len, dst, maxlen);
			break;
		case KNOT_RRTYPE_NS:
		case KNOT_RRTYPE_CNAME:
		case KNOT_RRTYPE_PTR:
		case KNOT_RRTYPE_DNAME:
			ret = dump_ns(data, data_len, dst, maxlen);
			break;
		case KNOT_RRTYPE_SOA:
			ret = dump_soa(data, data_len, dst, maxlen);
			break;
		case KNOT_RRTYPE_HINFO:
			ret = dump_hinfo(data, data_len, dst, maxlen);
			break;
		case KNOT_RRTYPE_MINFO:
		case KNOT_RRTYPE_RP:
			break;
		case KNOT_RRTYPE_MX:
		case KNOT_RRTYPE_AFSDB:
		case KNOT_RRTYPE_RT:
		case KNOT_RRTYPE_KX:
			ret = dump_mx(data, data_len, dst, maxlen);
			break;
		case KNOT_RRTYPE_TXT:
		case KNOT_RRTYPE_SPF:
			break;
		case KNOT_RRTYPE_KEY:
		case KNOT_RRTYPE_DNSKEY:
			break;
		case KNOT_RRTYPE_AAAA:
			ret = dump_aaaa(data, data_len, dst, maxlen);
			break;
		case KNOT_RRTYPE_LOC:
			break;
		case KNOT_RRTYPE_SRV:
			break;
		case KNOT_RRTYPE_NAPTR:
			break;
		case KNOT_RRTYPE_CERT:
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
			ret = dump_rrsig(data, data_len, dst, maxlen);
			break;
		case KNOT_RRTYPE_NSEC:
			break;
		case KNOT_RRTYPE_DHCID:
			break;
		case KNOT_RRTYPE_NSEC3:
			break;
		case KNOT_RRTYPE_NSEC3PARAM:
			break;
		case KNOT_RRTYPE_TLSA:
			break;
		default:
			break;
	}

	return ret;
}

int knot_rrset_txt_dump_header(const knot_rrset_t *rrset,
                               char               *dst,
                               const size_t       maxlen)
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
//		ret = snprintf(dst + len, maxlen - len, "%6u\t", rrset->ttl);
		ret = time_to_human_str(rrset->ttl, dst + len, maxlen - len);
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

int knot_rrset_txt_dump(const knot_rrset_t *rrset,
                        char               *dst,
                        const size_t       maxlen)
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
