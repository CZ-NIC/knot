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
 * \file knsupdate_params.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief knsupdate command line parameters.
 *
 * \addtogroup knot_utils
 * @{
 */

#pragma once

#include <stdint.h>

#include "utils/common/netio.h"
#include "utils/common/params.h"
#include "utils/common/sign.h"
#include "libknot/libknot.h"
#include "libzscanner/scanner.h"
#include "contrib/ucw/lists.h"

/*! \brief knsupdate-specific params data. */
typedef struct {
	/*!< Stop processing - just print help, version,... */
	bool		stop;
	/*!< List of files with query data. */
	list_t		qfiles;
	/*!< List of nameservers to query to. */
	srv_info_t	*server;
	/*!< Local interface (optional). */
	srv_info_t	*srcif;
	/*!< Version of ip protocol to use. */
	ip_t		ip;
	/*!< Type (TCP, UDP) protocol to use. */
	protocol_t	protocol;
	/*!< Default class number. */
	uint16_t	class_num;
	/*!< Default type number. */
	uint16_t	type_num;
	/*!< Default TTL. */
	uint32_t	ttl;
	/*!< Number of UDP retries. */
	uint32_t	retries;
	/*!< Wait for network response in seconds (-1 means forever). */
	int32_t		wait;
	/*!< Current zone. */
	char		*zone;
	/*!< RR parser. */
	zs_scanner_t	parser;
	/*!< Current packet. */
	knot_pkt_t	*query;
	/*!< Current response. */
	knot_pkt_t	*answer;
	/*< Lists of RRSets. */
	list_t		update_list, prereq_list;
	/*!< Transaction signature context. */
	knot_tsig_key_t tsig_key;
	/*!< Default output settings. */
	style_t		style;
	/*!< Memory context. */
	knot_mm_t	mm;
} knsupdate_params_t;

int knsupdate_parse(knsupdate_params_t *params, int argc, char *argv[]);
int knsupdate_set_ttl(knsupdate_params_t *params, const uint32_t ttl);
int knsupdate_set_origin(knsupdate_params_t *params, const char *origin);
void knsupdate_clean(knsupdate_params_t *params);
void knsupdate_reset(knsupdate_params_t *params);

/*! @} */
