/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <stdbool.h>

#include "utils/common/params.h"
#include "utils/common/exec.h"
#include "utils/common/https.h"
#include "utils/common/quic.h"
#include "utils/common/sign.h"
#include "libknot/libknot.h"
#include "contrib/sockaddr.h"

#if USE_DNSTAP
# include "contrib/dnstap/reader.h"
# include "contrib/dnstap/writer.h"
#endif // USE_DNSTAP

/*! \brief Operation mode of kdig. */
typedef enum {
	/*!< Standard 1-message query/reply. */
	OPERATION_QUERY,
	/*!< Zone transfer (AXFR or IXFR). */
	OPERATION_XFR,
	/*!< Dump dnstap file. */
	OPERATION_LIST_DNSTAP,
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
typedef struct query query_t; // Forward declaration due to configuration.
struct query {
	/*!< List node (for list container). */
	node_t		n;
	/*!< Reference to global config. */
	const query_t	*conf;
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
	/*!< Use TCP Fast Open. */
	bool		fastopen;
	/*!< Keep TCP connection open. */
	bool		keepopen;
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
	/*!< Class number (16unsigned + -1 uninitialized). */
	int32_t		class_num;
	/*!< Type number (16unsigned + -1 uninitialized). */
	int32_t		type_num;
	/*!< SOA serial for IXFR and NOTIFY (32unsigned + -1 uninitialized). */
	int64_t		serial;
	/*!< NOTIFY query. */
	bool		notify;
	/*!< Header flags. */
	flags_t		flags;
	/*!< Output settings. */
	style_t		style;
	/*!< IDN conversion. */
	bool		idn;
	/*!< Query for NSID. */
	bool		nsid;
	/*!< EDNS version (8unsigned + -1 uninitialized). */
	int16_t		edns;
	/*!< EDNS client cookie. */
	knot_edns_cookie_t cc;
	/*!< EDNS server cookie. */
	knot_edns_cookie_t sc;
	/*!< Repeat query after BADCOOKIE. */
	int		badcookie;
	/*!< EDNS0 padding (16unsigned + -1 ~ uninitialized, -2 ~ default, -3 ~ none). */
	int32_t		padding;
	/*!< Query alignment with EDNS0 padding (0 ~ uninitialized). */
	uint16_t	alignment;
	/*!< TLS parameters. */
	tls_params_t	tls;
	/*!< HTTPS parameters. */
	https_params_t	https;
	/*!< QUIC parameters. */
	quic_params_t quic;
	/*!< Transaction signature. */
	knot_tsig_key_t	tsig_key;
	/*!< EDNS client subnet. */
	knot_edns_client_subnet_t subnet;
	/*!< Lits of custom EDNS options. */
	list_t		edns_opts;
#if USE_DNSTAP
	/*!< Context for dnstap reader input. */
	dt_reader_t	*dt_reader;
	/*!< Context for dnstap writer output. */
	dt_writer_t	*dt_writer;
#endif // USE_DNSTAP
};

/*! \brief EDNS option data. */
typedef struct {
	/*! List node (for list container). */
	node_t	n;
	/*!< OPTION-CODE field. */
	uint16_t code;
	/*!< OPTION-LENGTH field. */
	uint16_t length;
	/*!< OPTION-DATA field. */
	uint8_t *data;
} ednsopt_t;

/*! \brief Settings for kdig. */
typedef struct {
	/*!< Stop processing - just print help, version,... */
	bool	stop;
	/*!< List of DNS queries to process. */
	list_t	queries;
	/*!< Default settings for queries. */
	query_t	*config;
} kdig_params_t;

query_t *query_create(const char *owner, const query_t *config);
void query_free(query_t *query);
void complete_queries(list_t *queries, const query_t *conf);

ednsopt_t *ednsopt_create(uint16_t code, uint16_t length, uint8_t *data);
ednsopt_t *ednsopt_dup(const ednsopt_t *opt);
void ednsopt_free(ednsopt_t *opt);

void ednsopt_list_init(list_t *list);
void ednsopt_list_deinit(list_t *list);
int ednsopt_list_dup(list_t *dst, const list_t *src);
bool ednsopt_list_empty(const list_t *list);

int kdig_init(kdig_params_t *params);
int kdig_parse(kdig_params_t *params, int argc, char *argv[]);
void kdig_clean(kdig_params_t *params);
