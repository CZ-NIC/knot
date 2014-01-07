/*!
 * \file ns_proc_query.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Query processor.
 *
 * \addtogroup query_processing
 * @{
 */
/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifndef _KNOT_NS_PROC_QUERY_H_
#define _KNOT_NS_PROC_QUERY_H_

#include "libknot/nameserver/name-server.h"
#include "common/acl.h"

/* Query processing module implementation. */
extern const ns_proc_module_t _ns_proc_query;
#define NS_PROC_QUERY (&_ns_proc_query)
#define NS_PROC_QUERY_ID 1

/* Query processing flags. */
enum ns_proc_query_flag {
	NS_QUERY_NO_AXFR   = NS_PROCFLAG << 1, /* Don't process AXFR */
	NS_QUERY_NO_IXFR   = NS_PROCFLAG << 2, /* Don't process IXFR */
	NS_QUERY_RATELIMIT = NS_PROCFLAG << 3  /* Apply rate limits. */
};

/* Module load parameters. */
struct ns_proc_query_param {
	sockaddr_t query_source;
};

/* Per-query data. */
struct query_data {
	uint16_t rcode;
	uint16_t rcode_tsig;
	knot_pkt_t *pkt;
	const knot_zone_t *zone; /*!< Associated zone. */
	const knot_node_t *node, *encloser, *previous;
	const knot_dname_t *name;
	uint8_t orig_qname[KNOT_DNAME_MAXLEN];
	list_t wildcards;
	ns_sign_context_t sign;
	struct ns_proc_query_param *param;
	mm_ctx_t *mm;
	void *ext;
};

/* Visited wildcard node list. */
struct wildcard_hit {
	node_t n;
	const knot_node_t *node;
	const knot_dname_t *sname;
};

int ns_proc_query_begin(ns_proc_context_t *ctx, void *module_param);
int ns_proc_query_reset(ns_proc_context_t *ctx);
int ns_proc_query_finish(ns_proc_context_t *ctx);
int ns_proc_query_in(knot_pkt_t *pkt, ns_proc_context_t *ctx);
int ns_proc_query_out(knot_pkt_t *pkt, ns_proc_context_t *ctx);
int ns_proc_query_err(knot_pkt_t *pkt, ns_proc_context_t *ctx);

bool ns_proc_query_acl_check(acl_t *acl, struct query_data *qdata);
int ns_proc_query_verify(struct query_data *qdata);
int ns_proc_query_sign_response(knot_pkt_t *pkt, struct query_data *qdata);

#endif /* _KNOT_NS_PROC_QUERY_H_ */

/*! @} */
