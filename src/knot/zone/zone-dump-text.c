/*!
 * \file zone-dump-text.c
 *
 * \author modifications (non-buffer implementation, zone-specific functions)
 *         by Jan Kadlec <jan.kadlec@nic.cz>,
 *         conversion functions by NLnet Labs,
 *         Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *         b64ntop by ISC.
 */

/*
 * Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>

#include <ctype.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "libknot/libknot.h"
#include "knot/other/error.h"
#include "libknot/common.h"
#include "common/skip-list.h"
#include "common/base32hex.h"

/*!< \todo #1683 Find all maximum lengths to be used in strcnat. */

enum uint_max_length {
	U8_MAX_STR_LEN = 4, U16_MAX_STR_LEN = 6,
	U32_MAX_STR_LEN = 11, MAX_RR_TYPE_LEN = 20,
	MAX_NSEC_BIT_STR_LEN = 4096,
	};

#define APL_NEGATION_MASK      0x80U
#define APL_LENGTH_MASK	       (~APL_NEGATION_MASK)

/* RFC 4025 - codes for different types that IPSECKEY can hold. */
#define IPSECKEY_NOGATEWAY 0
#define IPSECKEY_IP4 1
#define IPSECKEY_IP6 2
#define IPSECKEY_DNAME 3

/* Following copyrights are only valid for b64_ntop function */
/*
 * Copyright (c) 1996, 1998 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Portions Copyright (c) 1995 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * To the extent it has a right to do so, IBM grants an immunity from suit
 * under its patents, if any, for the use, sale or manufacture of products to
 * the extent that such products are used for performing Domain Name System
 * dynamic updates in TCP/IP networks by means of the Software.  No immunity is
 * granted for any product per se or for any other function of any product.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define Assert(Cond) if (!(Cond)) abort()

static const char Base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char Pad64 = '=';

/* (From RFC1521 and draft-ietf-dnssec-secext-03.txt)
   The following encoding technique is taken from RFC 1521 by Borenstein
   and Freed.  It is reproduced here in a slightly edited form for
   convenience.

   A 65-character subset of US-ASCII is used, enabling 6 bits to be
   represented per printable character. (The extra 65th character, "=",
   is used to signify a special processing function.)

   The encoding process represents 24-bit groups of input bits as output
   strings of 4 encoded characters. Proceeding from left to right, a
   24-bit input group is formed by concatenating 3 8-bit input groups.
   These 24 bits are then treated as 4 concatenated 6-bit groups, each
   of which is translated into a single digit in the base64 alphabet.

   Each 6-bit group is used as an index into an array of 64 printable
   characters. The character referenced by the index is placed in the
   output string.

                         Table 1: The Base64 Alphabet

      Value Encoding  Value Encoding  Value Encoding  Value Encoding
          0 A            17 R            34 i            51 z
          1 B            18 S            35 j            52 0
          2 C            19 T            36 k            53 1
          3 D            20 U            37 l            54 2
          4 E            21 V            38 m            55 3
          5 F            22 W            39 n            56 4
          6 G            23 X            40 o            57 5
          7 H            24 Y            41 p            58 6
          8 I            25 Z            42 q            59 7
          9 J            26 a            43 r            60 8
         10 K            27 b            44 s            61 9
         11 L            28 c            45 t            62 +
         12 M            29 d            46 u            63 /
         13 N            30 e            47 v
         14 O            31 f            48 w         (pad) =
         15 P            32 g            49 x
         16 Q            33 h            50 y

   Special processing is performed if fewer than 24 bits are available
   at the end of the data being encoded.  A full encoding quantum is
   always completed at the end of a quantity.  When fewer than 24 input
   bits are available in an input group, zero bits are added (on the
   right) to form an integral number of 6-bit groups.  Padding at the
   end of the data is performed using the '=' character.

   Since all base64 input is an integral number of octets, only the
         -------------------------------------------------
   following cases can arise:

       (1) the final quantum of encoding input is an integral
           multiple of 24 bits; here, the final unit of encoded
	   output will be an integral multiple of 4 characters
	   with no "=" padding,
       (2) the final quantum of encoding input is exactly 8 bits;
           here, the final unit of encoded output will be two
	   characters followed by two "=" padding characters, or
       (3) the final quantum of encoding input is exactly 16 bits;
           here, the final unit of encoded output will be three
	   characters followed by one "=" padding character.
   */

int b64_ntop(uint8_t const *src, size_t srclength, char *target,
	     size_t targsize) {
	size_t datalength = 0;
	uint8_t input[3];
	uint8_t output[4];
	size_t i;

	while (2 < srclength) {
		input[0] = *src++;
		input[1] = *src++;
		input[2] = *src++;
		srclength -= 3;

		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
		output[3] = input[2] & 0x3f;
		Assert(output[0] < 64);
		Assert(output[1] < 64);
		Assert(output[2] < 64);
		Assert(output[3] < 64);

		if (datalength + 4 > targsize)
			return (-1);
		target[datalength++] = Base64[output[0]];
		target[datalength++] = Base64[output[1]];
		target[datalength++] = Base64[output[2]];
		target[datalength++] = Base64[output[3]];
	}

	/* Now we worry about padding. */
	if (0 != srclength) {
		/* Get what's left. */
		input[0] = input[1] = input[2] = '\0';
		for (i = 0; i < srclength; i++)
			input[i] = *src++;

		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
		Assert(output[0] < 64);
		Assert(output[1] < 64);
		Assert(output[2] < 64);

		if (datalength + 4 > targsize)
			return (-1);
		target[datalength++] = Base64[output[0]];
		target[datalength++] = Base64[output[1]];
		if (srclength == 1)
			target[datalength++] = Pad64;
		else
			target[datalength++] = Base64[output[2]];
		target[datalength++] = Pad64;
	}
	if (datalength >= targsize)
		return (-1);
	target[datalength] = '\0';	/* Returned value doesn't count \0. */
	return (datalength);
}

/* Taken from RFC 4398, section 2.1.  */
knot_lookup_table_t knot_dns_certificate_types[] = {
/*	0		Reserved */
	{ 1, "PKIX" },	/* X.509 as per PKIX */
	{ 2, "SPKI" },	/* SPKI cert */
	{ 3, "PGP" },	/* OpenPGP packet */
	{ 4, "IPKIX" },	/* The URL of an X.509 data object */
	{ 5, "ISPKI" },	/* The URL of an SPKI certificate */
	{ 6, "IPGP" },	/* The fingerprint and URL of an OpenPGP packet */
	{ 7, "ACPKIX" },	/* Attribute Certificate */
	{ 8, "IACPKIX" },	/* The URL of an Attribute Certificate */
	{ 253, "URI" },	/* URI private */
	{ 254, "OID" },	/* OID private */
/*	255 		Reserved */
/* 	256-65279	Available for IANA assignment */
/*	65280-65534	Experimental */
/*	65535		Reserved */
	{ 0, NULL }
};

/* Taken from RFC 2535, section 7.  */
knot_lookup_table_t knot_dns_algorithms[] = {
	{ 1, "RSAMD5" },	/* RFC 2537 */
	{ 2, "DH" },		/* RFC 2539 */
	{ 3, "DSA" },		/* RFC 2536 */
	{ 4, "ECC" },
	{ 5, "RSASHA1" },	/* RFC 3110 */
	{ 252, "INDIRECT" },
	{ 253, "PRIVATEDNS" },
	{ 254, "PRIVATEOID" },
	{ 0, NULL }
};

static int get_bit(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	return bits[index / 8] & (1 << (7 - index % 8));
}

static inline uint8_t * rdata_item_data(knot_rdata_item_t item)
{
	return (uint8_t *)(item.raw_data + 1);
}

static inline uint16_t rdata_item_size(knot_rdata_item_t item)
{
	return item.raw_data[0];
}

static char *rdata_dname_to_string(knot_rdata_item_t item)
{
	return knot_dname_to_str(item.dname);
}

static char *rdata_binary_dname_to_string(knot_rdata_item_t item)
{
	if (item.raw_data == NULL) {
		return NULL;
	}
	
	if (item.raw_data[0] == 0) {
		return NULL;
	}
	
	/* Create new dname frow raw data - probably the easiest way. */
	knot_dname_t *dname = knot_dname_new_from_wire((uint8_t *)(item.raw_data + 1),
	                                               item.raw_data[0], NULL);
	if (dname == NULL) {
		return NULL;
	}
	
	/* Create string. */
	char *str = knot_dname_to_str(dname);
	knot_dname_free(&dname);
	
	return str;
}

static char *rdata_dns_name_to_string(knot_rdata_item_t item)
{
	return knot_dname_to_str(item.dname);
}

static char *rdata_txt_data_to_string(const uint8_t *data)
{
	uint8_t length = data[0];
	size_t i = 0;
	if (length == 0) {
		return NULL;
	}

	/*
	 * 3 because: opening '"', closing '"', and \0 at the end.
	 * Times 2 because string can be all "double chars".
	 */
	size_t current_length = sizeof(char) * (length * 2 + 4);
	char *ret = malloc(current_length);
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	memset(ret, 0,  current_length);

	strncat(ret, "\"", 2);

	for (i = 1; i <= length; i++) {
		char ch = (char) data[i];
		if (isprint((int)ch)) {
			if (ch == '"' || ch == '\\') {
				strncat(ret, "\"", 2);
			}
				char tmp_str[2];
				tmp_str[0] = ch;
				tmp_str[1] = '\0';
				strncat(ret, tmp_str, 2);
		} else {
			strncat(ret, "\\", 2);
			char tmp_str[2];
			tmp_str[0] = ch - '0';
			tmp_str[1] = '\0';
			strncat(ret, tmp_str, 2);
		}
	}
	strncat(ret, "\"", 2);

	return ret;
}

static char *rdata_text_to_string(knot_rdata_item_t item)
{
	uint16_t size = item.raw_data[0];
	/* 
	 * Times two because they can all be one char long
	 * and then it would be as much chars as spaces (and one final space).
	 */
	size_t txt_size = size * 2 + 1;
	/* + 1 ... space for (hypothetical) last \0. */
	char *ret = malloc(txt_size + 1);
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	memset(ret, 0, sizeof(char) * size);
	const uint8_t *data = (uint8_t *)(item.raw_data +  1);
	size_t read_count = 0;
	size_t tmp_str_current_length = 0; // Will be used with strncat.
	while (read_count < size) {
		assert(read_count <= size);
		char *txt = rdata_txt_data_to_string(data + read_count);
		if (txt == NULL) {
			free(ret);
			return NULL;
		}
		/*
		 * We can trust this strlen, as 
		 * it is created in internal function.
		 */
		read_count += strlen(txt) - 1;
		/* Create delimiter. */
		char del[2];
		del[0] = ' ';
		del[1] = '\0';
		
		/* We can only write to the remainder of string. */
		strncat(ret, txt, txt_size - tmp_str_current_length);
		/* Increase length of tmp string. */
		tmp_str_current_length += strlen(txt);
		strncat(ret, del, txt_size - tmp_str_current_length);
		/* Increase length of tmp string by 1 ... space. */
		tmp_str_current_length += + 1;
		free(txt);
	}

	return ret;
}

static char *rdata_byte_to_string(knot_rdata_item_t item)
{
	assert(item.raw_data[0] == 1);
	uint8_t data = *((uint8_t *)(item.raw_data + 1));
	char *ret = malloc(sizeof(char) * U8_MAX_STR_LEN);
	snprintf(ret, U8_MAX_STR_LEN, "%d", (char) data);
	return ret;
}

static char *rdata_short_to_string(knot_rdata_item_t item)
{
	uint16_t data = knot_wire_read_u16(rdata_item_data(item));
	char *ret = malloc(sizeof(char) * U16_MAX_STR_LEN);
	snprintf(ret, U16_MAX_STR_LEN, "%u", data);
	/* XXX Use proper macros - see response tests*/
	/* XXX check return value, return NULL on failure */
	return ret;
}

static char *rdata_long_to_string(knot_rdata_item_t item)
{
	uint32_t data = knot_wire_read_u32(rdata_item_data(item));
	char *ret = malloc(sizeof(char) * U32_MAX_STR_LEN);
	/* u should be enough */
	snprintf(ret, U32_MAX_STR_LEN, "%u", data);
	return ret;
}

static char *rdata_a_to_string(knot_rdata_item_t item)
{
	/* 200 seems like a little too much */
	char *ret = malloc(sizeof(char) * 200);
	if (inet_ntop(AF_INET, rdata_item_data(item), ret, 200)) {
		return ret;
	} else {
		return NULL;
	}
}

static char *rdata_aaaa_to_string(knot_rdata_item_t item)
{
	char *ret = malloc(sizeof(char) * 200);
	if (inet_ntop(AF_INET6, rdata_item_data(item), ret, 200)) {
		return ret;
	} else {
		return NULL;
	}
}

static char *rdata_rrtype_to_string(knot_rdata_item_t item)
{
	uint16_t type = knot_wire_read_u16(rdata_item_data(item));
	const char *tmp = knot_rrtype_to_string(type);
	char *ret = malloc(sizeof(char) * MAX_RR_TYPE_LEN);
	strncpy(ret, tmp, MAX_RR_TYPE_LEN);
	return ret;
}

static char *rdata_algorithm_to_string(knot_rdata_item_t item)
{
	uint8_t id = *rdata_item_data(item);
	char *ret = malloc(sizeof(char) * MAX_RR_TYPE_LEN);
	knot_lookup_table_t *alg
		= knot_lookup_by_id(knot_dns_algorithms, id);
	if (alg) {
		strncpy(ret, alg->name, MAX_RR_TYPE_LEN);
	} else {
		snprintf(ret, U8_MAX_STR_LEN, "%u", id);
	}

	return ret;
}

static char *rdata_certificate_type_to_string(knot_rdata_item_t item)
{
	uint16_t id = knot_wire_read_u16(rdata_item_data(item));
	char *ret = malloc(sizeof(char) * MAX_RR_TYPE_LEN);
	knot_lookup_table_t *type
		= knot_lookup_by_id(knot_dns_certificate_types, id);
	if (type) {
		strncpy(ret, type->name, MAX_RR_TYPE_LEN);
	} else {
		snprintf(ret, U16_MAX_STR_LEN, "%u", id);
	}

	return ret;
}

static char *rdata_period_to_string(knot_rdata_item_t item)
{
	/* uint32 but read 16 XXX */
	uint32_t period = knot_wire_read_u32(rdata_item_data(item));
	char *ret = malloc(sizeof(char) * U32_MAX_STR_LEN);
	snprintf(ret, U32_MAX_STR_LEN, "%u", period);
	return ret;
}

static char *rdata_time_to_string(knot_rdata_item_t item)
{
	time_t time = (time_t) knot_wire_read_u32(rdata_item_data(item));
	struct tm tm_conv;
	if (gmtime_r(&time, &tm_conv) == 0) {
		return 0;
	}
	char *ret = malloc(sizeof(char) * 15);
	if (strftime(ret, 15, "%Y%m%d%H%M%S", &tm_conv)) {
		return ret;
	} else {
		free(ret);
		return 0;
	}
}

static char *rdata_base32_to_string(knot_rdata_item_t item)
{
	int length;
	size_t size = rdata_item_size(item);
	if (size == 0) {
		char *ret = malloc(sizeof(char) * 2);
		ret[0] = '-';
		ret[1] = '\0';
		return ret;
	}

	size -= 1; // remove length byte from count
	char *ret = NULL;
	length = base32hex_encode_alloc((char *)rdata_item_data(item) + 1,
	                                size, &ret);
	if (length > 0) {
		return ret;
	} else {
		free(ret);
		return NULL;
	}
}

/*!< \todo Replace with function from .../common after release. */
static char *rdata_base64_to_string(knot_rdata_item_t item)
{
	int length;
	size_t size = rdata_item_size(item);
	char *ret = malloc((sizeof(char) * 2 * size) + 1 * sizeof(char));
	length = b64_ntop(rdata_item_data(item), size,
			  ret, (sizeof(char)) * (size * 2 + 1));
	if (length > 0) {
		return ret;
	} else {
		free(ret);
		return NULL;
	}
}

static char *knot_hex_to_string(const uint8_t *data, size_t size)
{
	static const char hexdigits[] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
	};
	size_t i;

	char *ret = malloc(sizeof(char) * (size * 2 + 1));

	for (i = 0; i < size * 2; i += 2) {
		uint8_t octet = *data++;
		ret[i] = hexdigits [octet >> 4];
		ret[i + 1] = hexdigits [octet & 0x0f];
	}

	ret[i] = '\0';

	return ret;
}

char *rdata_hex_to_string(knot_rdata_item_t item)
{
	return knot_hex_to_string(rdata_item_data(item), rdata_item_size(item));
}

char *rdata_hexlen_to_string(knot_rdata_item_t item)
{
	if(rdata_item_size(item) <= 1) {
		// NSEC3 salt hex can be empty
		char *ret = malloc(sizeof(char) * 2);
		ret[0] = '-';
		ret[1] = '\0';
		return ret;
	} else {
		return knot_hex_to_string(rdata_item_data(item) + 1,
		                          rdata_item_size(item) - 1);
	}
}

char *rdata_nsap_to_string(knot_rdata_item_t item)
{
	char *ret = malloc(sizeof(char) * ((rdata_item_size(item) * 2) + 7));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	memset(ret, 0, sizeof(char) * ((rdata_item_size(item) * 2) + 7));

	/* String is already terminated. */
	memcpy(ret, "0x", strlen("0x"));
	char *converted = knot_hex_to_string(rdata_item_data(item),
	                                     rdata_item_size(item));
	if (converted == NULL) {
		return NULL;
	}

	strncat(ret, converted, rdata_item_size(item) * 2 + 1);
	free(converted);
	return ret;
}

char *rdata_apl_to_string(knot_rdata_item_t item)
{
	uint8_t *data = rdata_item_data(item);
	size_t read = 0;
	char *pos = malloc(sizeof(char) * MAX_NSEC_BIT_STR_LEN);
	if (pos == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	memset(pos, 0, MAX_NSEC_BIT_STR_LEN);
	
	char *ret_base = pos;
	
	while (read < rdata_item_size(item)) {
		uint16_t address_family = knot_wire_read_u16(data);
		uint8_t prefix = data[2];
		uint8_t length = data[3];
		int negated = length & APL_NEGATION_MASK;
		int af = -1;

		length &= APL_LENGTH_MASK;
		switch (address_family) {
			case 1: af = AF_INET; break;
			case 2: af = AF_INET6; break;
		}

		if (af != -1) {
			char text_address[1024];
			memset(text_address, 0, sizeof(text_address));
			uint8_t address[128];
			memset(address, 0, sizeof(address));
			memcpy(address, data + 4, length);
			/* Only valid data should be present here. */
			assert((data + 4) - rdata_item_data(item) <= rdata_item_size(item));
			/* Move pointer at the end of already written data. */
			pos = ret_base + strlen(ret_base);
			if (inet_ntop(af, address,
				      text_address,
				      sizeof(text_address))) {
				snprintf(pos, sizeof(text_address) +
					 U32_MAX_STR_LEN * 2,
					 "%s%d:%s/%d%s",
					 negated ? "!" : "",
					 (int) address_family,
					 text_address,
					 (int) prefix,
					 /* Last item should not have trailing space. */
					 (read + 4 + length < rdata_item_size(item))
					 ? " " : "");
			}
		}

		data += 4 + length;
		read += 4 + length;
	}

	return ret_base;
}

char *rdata_services_to_string(knot_rdata_item_t item)
{
	uint8_t *data = rdata_item_data(item);
	uint8_t protocol_number = data[0];
	ssize_t bitmap_size = rdata_item_size(item) - 1;
	uint8_t *bitmap = data + 1;
	struct protoent *proto = getprotobynumber(protocol_number);

	char *ret = malloc(sizeof(char) * MAX_NSEC_BIT_STR_LEN);

	memset(ret, 0, MAX_NSEC_BIT_STR_LEN);

	if (proto) {
		int i;

		strncpy(ret, proto->p_name, strlen(proto->p_name));
		strncat(ret, " ", 2);

		for (i = 0; i < bitmap_size * 8; ++i) {
			if (get_bit(bitmap, i)) {
				struct servent *service =
					getservbyport((int)htons(i),
						      proto->p_name);
				if (service) {
					strncat(ret, service->s_name,
					        strlen(service->s_name));
					strncat(ret, " ", 2);
				} else {
					char tmp[U32_MAX_STR_LEN];
					snprintf(tmp, U32_MAX_STR_LEN,
						 "%d ", i);
					strncat(ret, tmp, U32_MAX_STR_LEN);
				}
			}
		}
	}

	return ret;
}

char *rdata_ipsecgateway_to_string(knot_rdata_item_t item,
                                   const knot_rrset_t *rrset)
{
	const knot_rdata_item_t *gateway_type_item =
		knot_rdata_item(knot_rrset_rdata(rrset), 1);
	if (gateway_type_item == NULL) {
		return NULL;
	}
	/* First two bytes store length. */
	int gateway_type = ((uint8_t *)(gateway_type_item->raw_data))[2];
	switch(gateway_type) {
	case IPSECKEY_NOGATEWAY: {
		char *ret = malloc(sizeof(char) * 4);
		if (ret == NULL) {
			ERR_ALLOC_FAILED;
			return NULL;
		}
		memset(ret, 0, sizeof(char) * 4);
		memcpy(ret, "\".\"", 4);
		return ret;
	}
	case IPSECKEY_IP4:
		return rdata_a_to_string(item);
	case IPSECKEY_IP6:
		return rdata_aaaa_to_string(item);
	case IPSECKEY_DNAME:
		return rdata_binary_dname_to_string(item);
	default:
		return NULL;
	}

	/* Flow *should* not get here. */
	return NULL;
}

char *rdata_nxt_to_string(knot_rdata_item_t item)
{
	size_t i;
	uint8_t *bitmap = rdata_item_data(item);
	size_t bitmap_size = rdata_item_size(item);

	char *ret = malloc(sizeof(char) * MAX_NSEC_BIT_STR_LEN);

	memset(ret, 0, MAX_NSEC_BIT_STR_LEN);

	for (i = 0; i < bitmap_size * 8; ++i) {
		if (get_bit(bitmap, i)) {
			strncat(ret, knot_rrtype_to_string(i),
			       MAX_RR_TYPE_LEN);
				strncat(ret, " ", 2);
		}
	}

	return ret;
}


char *rdata_nsec_to_string(knot_rdata_item_t item)
{
	char *ret = malloc(sizeof(char) * MAX_NSEC_BIT_STR_LEN);
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	memset(ret, 0, MAX_NSEC_BIT_STR_LEN);
	uint8_t *data = rdata_item_data(item);

	int increment = 0;
	for (int i = 0; i < rdata_item_size(item); i += increment) {
		increment = 0;
		uint8_t window = data[i];
		increment++;

		uint8_t bitmap_size = data[i + increment];
		increment++;

		uint8_t *bitmap = malloc(sizeof(uint8_t) * bitmap_size);

		memcpy(bitmap, data + i + increment,
		       bitmap_size);

		increment += bitmap_size;

		for (int j = 0; j < bitmap_size * 8; j++) {
			if (get_bit(bitmap, j)) {
				strncat(ret,
				       knot_rrtype_to_string(j +
							       window * 256),
				        MAX_RR_TYPE_LEN);
				strncat(ret, " ", 2);
			}
		}

		free(bitmap);
	}

	return ret;
}

char *rdata_unknown_to_string(knot_rdata_item_t item)
{
 	uint16_t size = rdata_item_size(item);
	char *ret =
		malloc(sizeof(char) * (2 * rdata_item_size(item) +
				       strlen("\\# ") + U16_MAX_STR_LEN + 1));
	if (ret == NULL) {
		return NULL;
	}
	memcpy(ret, "\\# \0", strlen("\\# \0"));
	snprintf(ret + strlen("\\# "),
	         strlen("\\# ") + U16_MAX_STR_LEN + 1, "%lu ",
		 (unsigned long) size);
	char *converted = knot_hex_to_string(rdata_item_data(item), size);
	strncat(ret, converted, size * 2 + 1);
	free(converted);
	return ret;
}

char *rdata_loc_to_string(knot_rdata_item_t item)
{
	return rdata_unknown_to_string(item);
}

typedef char * (*item_to_string_t)(knot_rdata_item_t);

static item_to_string_t item_to_string_table[KNOT_RDATA_ZF_UNKNOWN + 1] = {
	rdata_dname_to_string,
	rdata_dns_name_to_string,
	rdata_text_to_string,
	rdata_byte_to_string,
	rdata_short_to_string,
	rdata_long_to_string,
	rdata_a_to_string,
	rdata_aaaa_to_string,
	rdata_rrtype_to_string,
	rdata_algorithm_to_string,
	rdata_certificate_type_to_string,
	rdata_period_to_string,
	rdata_time_to_string,
	rdata_base64_to_string,
	rdata_base32_to_string,
	rdata_hex_to_string,
	rdata_hexlen_to_string,
	rdata_nsap_to_string,
	rdata_apl_to_string,
	NULL, //rdata_ipsecgateway_to_string,
	rdata_services_to_string,
	rdata_nxt_to_string,
	rdata_nsec_to_string,
	rdata_loc_to_string,
	rdata_unknown_to_string
};

char *rdata_item_to_string(knot_rdata_zoneformat_t type,
                           knot_rdata_item_t item)
{
	return item_to_string_table[type](item);
}

int rdata_dump_text(const knot_rdata_t *rdata, uint16_t type, FILE *f,
                     const knot_rrset_t *rrset)
{
	if (rdata == NULL || rrset == NULL) {
		return KNOT_EBADARG;
	}
	
	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(type);
	char *item_str = NULL;
	assert(rdata->count <= desc->length);
	for (int i = 0; i < rdata->count; i++) {
		/* Workaround for IPSec gateway. */
		if (desc->zoneformat[i] == KNOT_RDATA_ZF_IPSECGATEWAY) {
			item_str = rdata_ipsecgateway_to_string(rdata->items[i],
			                                        rrset);
		} else {
			item_str = rdata_item_to_string(desc->zoneformat[i],
						rdata->items[i]);
		}
		if (item_str == NULL) {
			item_str =
				rdata_item_to_string(KNOT_RDATA_ZF_UNKNOWN,
						     rdata->items[i]);
		}

		if (item_str == NULL) {
			/* Fatal error. */
			return KNOTD_ERROR;
		}

		if (i != rdata->count - 1) {
			fprintf(f, "%s ", item_str);
		} else {
			fprintf(f, "%s", item_str);
		}

		free(item_str);
	}
	fprintf(f, "\n");

	return KNOTD_EOK;
}

void dump_rrset_header(const knot_rrset_t *rrset, FILE *f)
{
	char *name = knot_dname_to_str(rrset->owner);
	fprintf(f, "%-20s ",  name);
	free(name);
	fprintf(f, "%-5u ", rrset->ttl);
	fprintf(f, "%-2s ", knot_rrclass_to_string(rrset->rclass));
	fprintf(f, "%-5s ",  knot_rrtype_to_string(rrset->type));
}

int rrsig_set_dump_text(knot_rrset_t *rrsig, FILE *f)
{
	dump_rrset_header(rrsig, f);
	knot_rdata_t *tmp = rrsig->rdata;

	while (tmp->next != rrsig->rdata) {
		int ret = rdata_dump_text(tmp, KNOT_RRTYPE_RRSIG, f, rrsig);
		if (ret != KNOTD_EOK) {
			return KNOTD_ERROR;
		}

		dump_rrset_header(rrsig, f);
		tmp = tmp->next;
	}

	int ret = rdata_dump_text(tmp, KNOT_RRTYPE_RRSIG, f, rrsig);
	if (ret != KNOTD_EOK) {
		return KNOTD_ERROR;
	}

	return KNOTD_EOK;
}


int rrset_dump_text(const knot_rrset_t *rrset, FILE *f)
{
	if (rrset->rdata != NULL) { // No sense in dumping empty RR
		dump_rrset_header(rrset, f);

		knot_rdata_t *tmp = rrset->rdata;

		while (tmp->next != rrset->rdata) {
			int ret = rdata_dump_text(tmp, rrset->type, f, rrset);
			if (ret != KNOTD_EOK) {
				return ret;
			}
			dump_rrset_header(rrset, f);
			tmp = tmp->next;
		}

		rdata_dump_text(tmp, rrset->type, f, rrset);
	}

	knot_rrset_t *rrsig_set = rrset->rrsigs;
	if (rrsig_set != NULL) {
		rrsig_set_dump_text(rrsig_set, f);
	}

	return KNOTD_EOK;
}

struct dump_param {
	FILE *f;
	const knot_dname_t *origin;
};

int apex_node_dump_text(knot_node_t *node, FILE *f)
{
	knot_rrset_t dummy_rrset;
	dummy_rrset.type = KNOT_RRTYPE_SOA;
	knot_rrset_t *tmp_rrset =
		(knot_rrset_t *)gen_tree_find(node->rrset_tree,
		                                &dummy_rrset);
	assert(tmp_rrset);
	int ret = rrset_dump_text(tmp_rrset, f);
	if (ret != KNOTD_EOK) {
		return ret;
	}

	const knot_rrset_t **rrsets =
		knot_node_rrsets(node);

	for (int i = 0; i < node->rrset_count; i++) {
		if (rrsets[i]->type != KNOT_RRTYPE_SOA) {
			ret = rrset_dump_text(rrsets[i], f);
			if (ret != KNOTD_EOK) {
				return ret;
			}
		}
	}

	free(rrsets);

	return KNOTD_EOK;
}

void node_dump_text(knot_node_t *node, void *data)
{
	struct dump_param *param;
	param = (struct dump_param *)data;
	FILE *f = param->f;
	const knot_dname_t *origin = param->origin;

	/* pointers should do in this case */
	if (node->owner == origin) {
		apex_node_dump_text(node, f);
		return;
	}

	const knot_rrset_t **rrsets =
		knot_node_rrsets(node);

	for (int i = 0; i < node->rrset_count; i++) {
		rrset_dump_text(rrsets[i], f);
	}

	free(rrsets);
}

int zone_dump_text(knot_zone_contents_t *zone, FILE *f)
{
	if (f == NULL) {
		return KNOT_EBADARG;
	}

	fprintf(f, ";Dumped using %s v. %s\n", PACKAGE_NAME, PACKAGE_VERSION);

	struct dump_param param;
	param.f = f;
	assert(zone->apex != NULL && zone->apex->owner != NULL);
	param.origin = knot_node_owner(knot_zone_contents_apex(zone));
	knot_zone_contents_tree_apply_inorder(zone, node_dump_text, &param);
	knot_zone_contents_nsec3_apply_inorder(zone, node_dump_text, &param);

	return KNOT_EOK;
}
