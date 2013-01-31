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

#include "utils/common/params.h"	// params_t

typedef struct {

} options_t;

/*! \brief Structure containing basic parameters for DNS query. */
typedef struct {
	/*!< List node (for list container). */
	node		n;
	/*!< Name to query on. */
	char		*qname;
	/*!< Class number (16unsigned + -1 uninitialized). */
	int32_t		qclass;
	/*!< Type number (16unsigned + -1 uninitialized). */
	int32_t		qtype;
	/*!< SOA serial for XFR. */
	uint32_t	xfr_serial;
} query_t;

/*! \brief dig-specific params data. */
typedef struct {
	/*!< List of DNS queries to process. */
	list		queries;
	/*!< Recursion desiredflag. */
	bool		rd_flag;
} dig_params_t;
#define DIG_PARAM(p) ((dig_params_t*)p->d)

query_t* query_create(const char    *qname,
                      const int32_t qtype,
                      const int32_t qclass);
void query_free(query_t *query);

int dig_parse(params_t *params, int argc, char *argv[]);
void dig_clean(params_t *params);

void dig_params_flag_norecurse(params_t *params);

#endif // _DIG__DIG_PARAMS_H_

/*! @} */
