/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file
 *
 * \brief IXFR processing.
 *
 * \addtogroup query_processing
 * @{
 */

#pragma once

#include "knot/nameserver/process_query.h"
#include "knot/nameserver/xfr.h"
#include "knot/query/query.h"
#include "libknot/packet/pkt.h"

/*! \brief IXFR-in processing states. */
enum ixfr_state {
	IXFR_INVALID = 0,
	IXFR_START,      /* IXFR-in starting, expecting final SOA. */
	IXFR_SOA_DEL,    /* Expecting starting SOA. */
	IXFR_SOA_ADD,    /* Expecting ending SOA. */
	IXFR_DEL,        /* Expecting RR to delete. */
	IXFR_ADD,        /* Expecting RR to add. */
	IXFR_DONE        /* Processing done, IXFR-in complete. */
};

/*! \brief Extended structure for IXFR-in/IXFR-out processing. */
struct ixfr_proc {
	/* Processing state. */
	struct xfr_proc proc;
	enum ixfr_state state;

	/* Changes to be sent. */
	list_t changesets;

	/* Currenty processed changeset. */
	knot_rrset_t cur_rr;
	changeset_iter_t cur;
	const knot_rrset_t *soa_from;
	const knot_rrset_t *soa_to;

	/* Processing context. */
	struct query_data *qdata;
	knot_mm_t *mm;
};

/*!
 * \brief IXFR query processing module.
 *
 * \retval PRODUCE if it has an answer, but not yet finished.
 * \retval FAIL if it encountered an error.
 * \retval DONE if finished.
 */
int ixfr_process_query(knot_pkt_t *pkt, struct query_data *qdata);

/*! @} */
