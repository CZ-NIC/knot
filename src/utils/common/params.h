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

#include <stdint.h>			// uint16_t
#include <limits.h>			// INT_MAX
#include <stdbool.h>			// bool

#include "libknot/libknot.h"
#include "common/lists.h"		// list

#define DEFAULT_IPV4_NAME	"127.0.0.1"
#define DEFAULT_IPV6_NAME	"::1"
#define DEFAULT_DNS_PORT	"53"
#define DEFAULT_UDP_SIZE	512
#define DEFAULT_EDNS_SIZE	4096
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
	FORMAT_NSUPDATE
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
	/*!< Show EDNS info. */
	bool	show_edns;
	/*!< Show QUERY/ZONE section. */
	bool	show_question;
	/*!< Show ANSWER/PREREQ section. */
	bool	show_answer;
	/*!< Show UPDATE/AUTHORITY section. */
	bool	show_authority;
	/*!< Show ADDITIONAL section. */
	bool	show_additional;
	/*!< Show footer info. */
	bool	show_footer;

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

/*!
 * \brief Transforms localized IDN string to ASCII punycode.
 *
 * \param idn_name	IDN name to transform.
 *
 * \retval NULL		if transformation fails.
 * \retval string	if ok.
 */
char* name_from_idn(const char *idn_name);

/*!
 * \brief Transforms ASCII punycode to localized IDN string.
 *
 * If an error occures or IDN support is missing, this function does nothing.
 *
 * \param idn_name	ASCII name to transform and replace with IDN name.
 */
void name_to_idn(char **name);

int best_param(const char *str, const size_t str_len, const param_t *tbl,
               bool *unique);

char* get_reverse_name(const char *name);

char* get_fqd_name(const char *name);

int params_parse_class(const char *value, uint16_t *rclass);

int params_parse_type(const char *value, uint16_t *rtype, uint32_t *xfr_serial);

int params_parse_server(const char *value, list_t *servers, const char *def_port);

int params_parse_wait(const char *value, int32_t *dst);

int params_parse_num(const char *value, uint32_t *dst);

int params_parse_tsig(const char *value, knot_key_params_t *key_params);

int params_parse_keyfile(const char *value, knot_key_params_t *key_params);

#endif // _UTILS__PARAMS_H_

/*! @} */
