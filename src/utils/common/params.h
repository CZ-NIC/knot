/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "libknot/libknot.h"
#include "contrib/string.h"
#include "contrib/ucw/lists.h"

#define DEFAULT_IPV4_NAME	"127.0.0.1"
#define DEFAULT_IPV6_NAME	"::1"
#define DEFAULT_DNS_PORT	"53"
#define DEFAULT_DNS_HTTPS_PORT	"443"
#define DEFAULT_DNS_QUIC_PORT	"853"
#define DEFAULT_DNS_TLS_PORT	"853"
#define DEFAULT_UDP_SIZE	512
#define DEFAULT_EDNS_SIZE	1232
#define MAX_PACKET_SIZE		65535

#define SEP_CHARS		"\n\t "

/*! \brief Variants of IP protocol. */
typedef enum {
	IP_ALL,
	IP_4,
	IP_6
} ip_t;

/*! \brief Variants of transport protocol. */
typedef enum {
	PROTO_ALL,
	PROTO_TCP,
	PROTO_UDP
} protocol_t;

/*! \brief Variants of output type. */
typedef enum {
	/*!< Verbose output (same for host and dig). */
	FORMAT_FULL,
	/*!< Short dig output. */
	FORMAT_DIG,
	/*!< Brief host output. */
	FORMAT_HOST,
	/*!< Brief nsupdate output. */
	FORMAT_NSUPDATE,
	/*!< Machine readable JSON format (RFC 8427). */
	FORMAT_JSON
} format_t;

/*! \brief Text output settings. */
typedef struct {
	/*!< Output format. */
	format_t	format;

	/*!< Style of rrset dump. */
	knot_dump_style_t	style;

	/*!< Show query packet. */
	bool	show_query;
	/*!< Show header info. */
	bool	show_header;
	/*!< Show section name. */
	bool	show_section;
	/*!< Show EDNS pseudosection. */
	bool	show_edns;
	/*!< Show unknown EDNS options in printable format. */
	bool	show_edns_opt_text;
	/*!< Show QUERY/ZONE section. */
	bool	show_question;
	/*!< Show ANSWER/PREREQ section. */
	bool	show_answer;
	/*!< Show UPDATE/AUTHORITY section. */
	bool	show_authority;
	/*!< Show ADDITIONAL section. */
	bool	show_additional;
	/*!< Show TSIG pseudosection. */
	bool	show_tsig;
	/*!< Show footer info. */
	bool	show_footer;
	/*!< Display EDNS in Presentation format. */
	bool	present_edns;

	/*!< KHOST - Hide CNAME record in answer (duplicity reduction). */
	bool	hide_cname;
} style_t;

/*! \brief Parameter handler. */
typedef int (*param_handle_f)(const char *arg, void *params);

/*! \brief Parameter argument type. */
typedef enum {
	ARG_NONE,
	ARG_REQUIRED,
	ARG_OPTIONAL
} arg_t;

/*! \brief Parameter specification. */
typedef struct {
	const char     *name;
	arg_t          arg;
	param_handle_f handler;
} param_t;

inline static void print_version(const char *prog_name, bool verbose)
{
	if (prog_name != NULL) {
		printf("%s, ", prog_name);
	}
	printf("Knot DNS %s\n", PACKAGE_VERSION);
	if (verbose) {
		printf("\n%s\n", configure_summary);
	}
}

/*!
 * \brief Transforms localized IDN string to ASCII punycode.
 *
 * \param idn_name	IDN name to transform.
 *
 * \retval NULL		if transformation fails.
 * \retval string	if ok.
 */
char *name_from_idn(const char *idn_name);

/*!
 * \brief Transforms ASCII punycode to localized IDN string.
 *
 * If an error occurs or IDN support is missing, this function does nothing.
 *
 * \param name	ASCII name to transform and replace with IDN name.
 */
void name_to_idn(char **name);

/*!
 * \brief Find the best parameter match in table based on prefix equality.
 *
 * \param str		Parameter name to look up.
 * \param str_len	Parameter name length.
 * \param tbl		Parameter table.
 * \param unique	Indication if output is unique result.
 *
 * \retval >=0		looked up parameter position in \a tbl.
 * \retval err		if error.
 */
int best_param(const char *str, const size_t str_len, const param_t *tbl,
               bool *unique);

char *get_reverse_name(const char *name);

char *get_fqd_name(const char *name);

int params_parse_class(const char *value, uint16_t *rclass);

int params_parse_type(const char *value, uint16_t *rtype, int64_t *serial,
                      bool *notify);

int params_parse_server(const char *value, list_t *servers, const char *def_port);

int params_parse_wait(const char *value, int32_t *dst);
