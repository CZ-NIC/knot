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

#ifndef _NSUPDATE_PARAMS_H_
#define _NSUPDATE_PARAMS_H_

#include <stdbool.h>
#include <stdint.h>

#include "common/lists.h"		// list
#include "utils/common/params.h"	// protocol_t
#include "libknot/packet/query.h"
#include "zscanner/scanner.h"

/* nsupdate-specific params data */
typedef struct nsupdate_params_t {
	/*!< List of files with query data. */
	list		qfiles;
	/*!< Default port. */
	unsigned	port;
	/*!< Default address. */
	char		*addr;
	/*!< Current zone. */
	char		*zone;
	/*!< RR parser. */
	scanner_t	*rrp;
	/*!< Current packet. */
	knot_packet_t	*pkt;
} nsupdate_params_t;
#define NSUP_PARAM(p) ((nsupdate_params_t*)p->d)

int nsupdate_params_parse(params_t *params, int argc, char *argv[]);
void nsupdate_params_clean(params_t *params);

#endif // _NSUPDATE_PARAMS_H_

/*! @} */
