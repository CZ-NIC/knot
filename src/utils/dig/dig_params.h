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
 * \file dig_params.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief dig command line parameters.
 *
 * \addtogroup knot_utils
 * @{
 */

#ifndef _DIG__DIG_PARAMS_H_
#define _DIG__DIG_PARAMS_H_

#include <stdbool.h>			// bool

#include "utils/common/params.h"	// protocol_t
#include "utils/common/exec.h"		// sign_context_t

#define KDIG_VERSION "kdig, version " PACKAGE_VERSION "\n"

/*! \brief Operation mode of dig. */
typedef enum {
	/*!< Standard 1-message query/reply. */
	OPERATION_QUERY,
	/*!< Zone transfer (AXFR or IXFR). */
	OPERATION_XFR,
	/*!< Query for NS and all authoritative SOA records. */
	OPERATION_LIST_SOA
} operation_t;

/*! \brief DNS header and EDNS flags. */
typedef struct {
	/*!< Authoritative answer flag. */
	bool	aa_flag;
	/*!< Truncated flag. */
	bool	tc_flag;
	/*!< Recursion desired flag. */
	bool	rd_flag;
	/*!< Recursion available flag. */
	bool	ra_flag;
	/*!< Z flag. */
	bool	z_flag;
	/*!< Authenticated data flag. */
	bool	ad_flag;
	/*!< Checking disabled flag. */
	bool	cd_flag;
	/*!< DNSSEC OK flag. */
	bool	do_flag;
} flags_t;

/*! \brief Basic parameters for DNS query. */
typedef struct {
	/*!< List node (for list container). */
	node_t		n;
	/*!< Name to query on. */
	char		*owner;
	/*!< List of nameservers to query to. */
	list_t		servers;
	/*!< Local interface (optional). */
	srv_info_t	*local;
	/*!< Operation mode. */
	operation_t	operation;
	/*!< Version of ip protocol to use. */
	ip_t		ip;
	/*!< Protocol type (TCP, UDP) to use. */
	protocol_t	protocol;
	/*!< Port/service to connect to. */
	char		*port;
	/*!< UDP buffer size (16unsigned + -1 uninitialized). */
	int32_t		udp_size;
	/*!< Number of UDP retries. */
	uint32_t	retries;
	/*!< Wait for network response in seconds (-1 means forever). */
	int32_t		wait;
	/*!< Ignore truncated response. */
	bool		ignore_tc;
	/*!< Stop quering if servfail. */
	bool		servfail_stop;
	/*!< Class number (16unsigned + -1 uninitialized). */
	int32_t		class_num;
	/*!< Type number (16unsigned + -1 uninitialized). */
	int32_t		type_num;
	/*!< SOA serial for XFR. */
	uint32_t	xfr_serial;
	/*!< Header flags. */
	flags_t		flags;
	/*!< Output settings. */
	style_t		style;
	/*!< Query for NSID. */
	bool		nsid;
	/*!< EDNS version (8unsigned + -1 uninitialized). */
	int16_t		edns;
	/*!< Key parameters. */
	knot_key_params_t key_params;
	/*!< Context for operations with signatures. */
	sign_context_t	sign_ctx;
} query_t;

/*! \brief Settings for dig. */
typedef struct {
	/*!< Stop processing - just pring help, version,... */
	bool	stop;
	/*!< List of DNS queries to process. */
	list_t	queries;
	/*!< Default settings for queries. */
	query_t	*config;
} dig_params_t;

query_t* query_create(const char *owner, const query_t *config);
void query_free(query_t *query);
void complete_queries(list_t *queries, const query_t *conf);

int dig_init(dig_params_t *params);
int dig_parse(dig_params_t *params, int argc, char *argv[]);
void dig_clean(dig_params_t *params);

#endif // _DIG__DIG_PARAMS_H_

/*! @} */
