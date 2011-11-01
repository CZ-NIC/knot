/*!
 * \file parser-util.h
 *
 * \author NLnet Labs
 *         Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *         See LICENSE for the license.
 *         Modification by CZ.NIC, z.s.p.o.
 *
 * \brief Zone compiler utility functions.
 *
 * \addtogroup zoneparser
 * @{
 */
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

#ifndef _KNOTD_PARSER_UTIL_H_
#define _KNOTD_PARSER_UTIL_H_

#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>

#include "zcompile/zcompile.h"
#include "libknot/util/descriptor.h"

int inet_pton4(const char *src, uint8_t *dst);
int inet_pton6(const char *src, uint8_t *dst);
//int my_b32_pton(const char *src, uint8_t *target, size_t tsize);
const char *inet_ntop4(const u_char *src, char *dst, size_t size);
const char *inet_ntop6(const u_char *src, char *dst, size_t size);
int inet_pton(int af, const char *src, void *dst);
void b64_initialize_rmap();
int b64_pton_do(char const *src, uint8_t *target, size_t targsize);
int b64_pton_len(char const *src);
int b64_pton(char const *src, uint8_t *target, size_t targsize);
void set_bit(uint8_t bits[], size_t index);
uint32_t strtoserial(const char *nptr, const char **endptr);
void write_uint32(void *dst, uint32_t data);
uint32_t strtottl(const char *nptr, const char **endptr);
time_t mktime_from_utc(const struct tm *tm);

/*!< Conversions from text to wire. */
/*!
 * \brief Converts hex text format to wireformat.
 *
 * \param hex String to be converted.
 * \param len Length of string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_hex(const char *hex, size_t len);

/*!
 * \brief Converts hex text format with length to wireformat.
 *
 * \param hex String to be converted/.
 * \param len Length of string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_hex_length(const char *hex, size_t len);

/*!
 * \brief Converts time string to wireformat.
 *
 * \param time Time string to be converted.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_time(const char *time);
/*!
 * \brief Converts a protocol and a list of service port numbers
 * (separated by spaces) in the rdata to wireformat
 *
 * \param protostr Protocol string.
 * \param servicestr Service string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_services(const char *protostr, char *servicestr);

/*!
 * \brief Converts serial to wireformat.
 *
 * \param serialstr Serial string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_serial(const char *serialstr);
/*!
 * \brief Converts period to wireformat.
 *
 * \param periodstr Period string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_period(const char *periodstr);

/*!
 * \brief Converts short int to wireformat.
 *
 * \param text String containing short int.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_short(const char *text);

/*!
 * \brief Converts long int to wireformat.
 *
 * \param text String containing long int.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_long(const char *text);

/*!
 * \brief Converts byte to wireformat.
 *
 * \param text String containing byte.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_byte(const char *text);

/*!
 * \brief Converts A rdata string to wireformat.
 *
 * \param text String containing A rdata.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_a(const char *text);

/*!
 * \brief Converts AAAA rdata string to wireformat.
 *
 * \param text String containing AAAA rdata.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_aaaa(const char *text);

/*!
 * \brief Converts text string to wireformat.
 *
 * \param text Text string.
 * \param len Length of string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_text(const char *text, size_t len);

/*!
 * \brief Converts domain name string to wireformat.
 *
 * \param name Domain name string.
 * \param len Length of string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_dns_name(const uint8_t* name, size_t len);

/*!
 * \brief Converts base32 encoded string to wireformat.
 * TODO consider replacing with our implementation.
 *
 * \param b32 Base32 encoded string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_b32(const char *b32);

/*!
 * \brief Converts base64 encoded string to wireformat.
 * TODO consider replacing with our implementation.
 *
 * \param b64 Base64 encoded string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_b64(const char *b64);

/*!
 * \brief Converts RR type string to wireformat.
 *
 * \param rr RR type string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_rrtype(const char *rr);

/*!
 * \brief Converts NXT string to wireformat.
 *
 * \param nxtbits NXT string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_nxt(uint8_t *nxtbits);

/*!
 * \brief Converts NSEC bitmap to wireformat.
 *
 * \param nsecbits[][] NSEC bits.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_nsec(uint8_t nsecbits[NSEC_WINDOW_COUNT]
					   [NSEC_WINDOW_BITS_SIZE]);
/*!
 * \brief Converts LOC string to wireformat.
 *
 * \param str LOC string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_loc(char *str);

/*!
 * \brief Converts algorithm string to wireformat.
 *
 * \param algstr Algorithm string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_algorithm(const char *algstr);

/*!
 * \brief Converts certificate type string to wireformat.
 *
 * \param typestr Certificate type mnemonic string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_certificate_type(const char *typestr);

/*!
 * \brief Converts APL data to wireformat.
 *
 * \param str APL data string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_apl_rdata(char *str);

/*!
 * \brief Parses unknown rdata.
 *
 * \param type Type of data.
 * \param wireformat Wireformat of data.
 *
 * \return Converted wireformat.
 */
void parse_unknown_rdata(uint16_t type, uint16_t *wireformat);

/*!
 * \brief Converts TTL string to int.
 *
 * \param ttlstr String
 * \param error Error code.
 *
 * \return Converted wireformat.
 */
uint32_t zparser_ttl2int(const char *ttlstr, int* error);

/*!
 * \brief Adds wireformat to temporary list of rdata items.
 *
 * \param data Wireformat to be added.
 */
void zadd_rdata_wireformat(uint16_t *data);

/*!
 * \brief Adds TXT wireformat to temporary list of rdata items.
 *
 * \param data Wireformat to be added.
 * \param first This is first text to be added.
 */
void zadd_rdata_txt_wireformat(uint16_t *data, int first);

/*!
 * \brief Cleans after using zadd_rdata_txt_wireformat().
 */
void zadd_rdata_txt_clean_wireformat();

/*!
 * \brief Adds domain name to temporary list of rdata items.
 *
 * \param domain Domain name to be added.
 */
void zadd_rdata_domain(knot_dname_t *domain);

/*!
 * \brief Sets bit in NSEC bitmap.
 *
 * \param bits[][] NSEC bitmaps.
 * \param index Index on which bit is to be set.
 */
void set_bitnsec(uint8_t bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
		 uint16_t index);

/*!
 * \brief Allocate and init wireformat.
 *
 * \param data Data to be copied into newly created wireformat.
 * \param size Size of data.
 *
 * \return Allocated wireformat.
 */
uint16_t *alloc_rdata_init(const void *data, size_t size);
uint16_t rrsig_type_covered(knot_rrset_t *rrset);


#endif /* _KNOTD_PARSER_UTIL_H_ */

/*! @} */
