/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "contrib/time.h"
#include "contrib/ucw/lists.h"
#include "knot/nameserver/log.h"
#include "knot/nameserver/process_query.h"
#include "knot/zone/contents.h"
#include "libknot/packet/pkt.h"

struct xfr_stats {
	unsigned messages;
	unsigned bytes;
	struct timespec begin;
	struct timespec end;
};

void xfr_stats_begin(struct xfr_stats *stats);
void xfr_stats_add(struct xfr_stats *stats, unsigned bytes);
void xfr_stats_end(struct xfr_stats *stats);

static inline
void xfr_log_finished(const knot_dname_t *zone, log_operation_t op,
                      log_direction_t dir, const struct sockaddr_storage *remote,
                      knotd_query_proto_t proto, const knot_dname_t *key_name,
                      const char *serial_log, const struct xfr_stats *stats)
{
	ns_log(LOG_INFO, zone, op, dir, remote, proto, false, key_name,
	       "%sfinished,%s %0.2f seconds, %u messages, %u bytes",
	       (proto == KNOTD_QUERY_PROTO_QUIC && dir == LOG_DIRECTION_OUT ? "buffering " : ""),
	       serial_log, time_diff_ms(&stats->begin, &stats->end) / 1000.0,
	       stats->messages, stats->bytes);
}

/*!
 * \brief Generic transfer processing state.
 */
struct xfr_proc {
	list_t nodes;               //!< Items to process (ptrnode_t).
	zone_contents_t *contents;  //!< Processed zone.
	struct xfr_stats stats;     //!< Packet transfer statistics.
};

/*!
 * \brief Generic transfer processing.
 *
 * \return KNOT_EOK or an error
 */
typedef int (*xfr_put_cb)(knot_pkt_t *pkt, const void *item, struct xfr_proc *xfer);

/*!
 * \brief Put all items from xfr_proc.nodes to packet using a callback function.
 *
 * \note qdata->extra->ext points to struct xfr_proc* (this is xfer-specific context)
 */
int xfr_process_list(knot_pkt_t *pkt, xfr_put_cb put, knotd_qdata_t *qdata);
