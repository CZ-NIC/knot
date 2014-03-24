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
 * \file nsupdate_params.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief nsupdate command line parameters.
 *
 * \addtogroup knot_utils
 * @{
 */

#ifndef _NSUPDATE__NSUPDATE_PARAMS_H_
#define _NSUPDATE__NSUPDATE_PARAMS_H_

#include <stdint.h>

#include "libknot/libknot.h"
#include "common/lists.h"		// list
#include "zscanner/zscanner.h"		// scanner_t
#include "utils/common/netio.h"		// server_t
#include "utils/common/params.h"	// protocol_t
#include "libknot/dnssec/key.h"		// knot_key_params_t

#define KNSUPDATE_VERSION "knsupdate, version " PACKAGE_VERSION "\n"

/*! Parser init string. */
#define PARSER_INIT_STR "$ORIGIN %s\n$TTL %u\n"

/*! \brief nsupdate-specific params data. */
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
	scanner_t	*rrp;
	/*!< Current packet. */
	knot_packet_t	*pkt;
	/*!< Current response. */
	knot_packet_t	*resp;
	/*!< Buffer for response. */
	uint8_t		rwire[MAX_PACKET_SIZE];
	/*!< Key parameters. */
	knot_key_params_t key_params;
	/*!< Default output settings. */
	style_t		style;
} nsupdate_params_t;

int nsupdate_parse(nsupdate_params_t *params, int argc, char *argv[]);
int nsupdate_set_ttl(nsupdate_params_t *params, const uint32_t ttl);
int nsupdate_set_origin(nsupdate_params_t *params, const char *origin);
void nsupdate_clean(nsupdate_params_t *params);

#endif // _NSUPDATE__NSUPDATE_PARAMS_H_

/*! @} */
