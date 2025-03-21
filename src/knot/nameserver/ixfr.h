/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/journal/journal_read.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/xfr.h"
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
	bool in_remove_section;

	/* Changes to be sent. */
	journal_read_t *journal_ctx;

	/* Currently processed RRSet. */
	knot_rrset_t cur_rr;

	/* Processing context. */
	knotd_qdata_t *qdata;
	knot_mm_t *mm;
	uint32_t soa_from;
	uint32_t soa_to;
	uint32_t soa_last;
};

/*!
 * \brief IXFR query processing module.
 */
knot_layer_state_t ixfr_process_query(knot_pkt_t *pkt, knotd_qdata_t *qdata);
