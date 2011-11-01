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
#endif /* _KNOTD_PARSER_UTIL_H_ */

/*! @} */
