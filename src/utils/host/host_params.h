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
 * \brief Host command line parameters.
 *
 * \addtogroup knot_utils
 * @{
 */

#ifndef _HOST__HOST_PARAMS_H_
#define _HOST__HOST_PARAMS_H_

#include <stdbool.h>
#include <stdint.h>

#include "common/lists.h"		// list
#include "utils/common/params.h"	// protocol_t

#define DEFAULT_WAIT_INTERVAL	1

/*! \brief Types of host operation mode. */
typedef enum {
	/*!< Classic query for name-class-type. */
	HOST_MODE_DEFAULT,
	/*!< Query for NS and all authoritative SOA records. */
	HOST_MODE_LIST_SERIALS,
} host_mode_t;

/*! \brief Structure containing parameters for host. */
typedef struct {
	/*!< List of nameservers to query to. */
	list		servers;
	/*!< List of DNS queries to process. */
	list		queries;

	/*!< Operation mode. */
	host_mode_t	mode;
	/*!< Version of ip protocol to use. */
	ip_version_t	ip;
	/*!< Type (TCP, UDP) protocol to use. */
	protocol_t	protocol;
	/*!< Default class number. */
	uint16_t	class_num;
	/*!< Default type number (16unsigned + -1 uninitialized). */
	int32_t		type_num;
	/*!< SOA serial for IXFR query (32unsigned + -1 uninitialized). */
	int64_t		ixfr_serial;
	/*!< Use recursion. */
	bool		recursion;
	/*!< UDP buffer size. */
	uint32_t	udp_size;
	/*!< Number of UDP retries. */
	uint32_t	retries;
	/*!< Wait for reply in seconds (-1 means forever). */
	int32_t		wait;
	/*!< Stop quering if servfail. */
	bool		servfail_stop;
	/*!< Verbose mode. */
	bool		verbose;
} host_params_t;

int host_params_parse(host_params_t *params, int argc, char *argv[]);

void host_params_clean(host_params_t *params);

#endif // _HOST__HOST_PARAMS_H_

/*! @} */
