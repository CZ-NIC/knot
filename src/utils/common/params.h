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
/*!
 * \file host_params.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief Common utils parameters processing.
 *
 * \addtogroup knot_utils
 * @{
 */

#ifndef _UTILS__PARAMS_H_
#define _UTILS__PARAMS_H_

#include <stdbool.h>			// bool
#include <stdint.h>			// uint16_t

#include "common/lists.h"		// node
#include "libknot/tsig.h"

#define DEFAULT_IPV4_NAME	"127.0.0.1"
#define DEFAULT_IPV6_NAME	"::1"
#define DEFAULT_DNS_PORT	"53"
#define DEFAULT_UDP_SIZE	512
#define MAX_PACKET_SIZE		65535

#define SEP_CHARS		"\n\t "

typedef enum {
	IP_ALL,
	IP_4,
	IP_6
} ip_version_t;

typedef enum {
	PROTO_ALL,
	PROTO_TCP,
	PROTO_UDP
} protocol_t;

typedef enum {
	/*!< Classic queries in list. */
	OPERATION_QUERY,
	/*!< Query for NS and all authoritative SOA records. */
	OPERATION_LIST_SOA,
	/*!< Default mode for nsupdate. */
	OPERATION_UPDATE,
} operation_t;

typedef enum {
	/*!< Short dig output. */
	FORMAT_DIG,
	/*!< Brief host output. */
	FORMAT_HOST,
	/*!< Brief nsupdate output. */
	FORMAT_NSUPDATE,
	/*!< Verbose output (same for host and dig). */
	FORMAT_VERBOSE,
	/*!< Verbose multiline output. */
	FORMAT_MULTILINE,
} format_t;

/*! \brief Structure containing parameters. */
typedef struct {
	/*!< List of nameservers to query to. */
	list		servers;
	/*!< Operation mode. */
	operation_t	operation;
	/*!< Version of ip protocol to use. */
	ip_version_t	ip;
	/*!< Type (TCP, UDP) protocol to use. */
	protocol_t	protocol;
	/*!< Default class number. */
	uint16_t	class_num;
	/*!< Default type number (16unsigned + -1 uninitialized). */
	int32_t		type_num;
	/*!< Default TTL. */
	uint32_t	ttl;
	/*!< Default SOA serial for XFR (32unsigned + -1 uninitialized). */
	int64_t		xfr_serial;
	/*!< UDP buffer size. */
	uint32_t	udp_size;
	/*!< Number of UDP retries. */
	uint32_t	retries;
	/*!< Wait for network response in seconds (-1 means forever). */
	int32_t		wait;
	/*!< Stop quering if servfail. */
	bool		servfail_stop;
	/*!< Output format. */
	format_t	format;
	/*!< TSIG key used. */
	knot_key_t	key;
	/*!< Implementation specific data. */
	void*		d;
} params_t;

int parse_class(const char *rclass, uint16_t *class_num);

int parse_type(const char *rtype, int32_t *type_num, int64_t *ixfr_serial);

char* get_reverse_name(const char *name);

char* get_fqd_name(const char *name);

void params_flag_ipv4(params_t *params);

void params_flag_ipv6(params_t *params);

void params_flag_servfail(params_t *params);

void params_flag_nowait(params_t *params);

void params_flag_tcp(params_t *params);

void params_flag_verbose(params_t *params);

int params_parse_interval(const char *value, int32_t *dst);

int params_parse_num(const char *value, uint32_t *dst);

int params_parse_tsig(const char *value, knot_key_t *key);

int params_parse_keyfile(const char *filename, knot_key_t *key);

#endif // _UTILS__PARAMS_H_

/*! @} */
