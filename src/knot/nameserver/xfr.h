/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
void xfr_log_finished(const knot_dname_t *zone, enum log_operation op,
                      enum log_direction dir, const struct sockaddr *remote,
                      const struct xfr_stats *stats)
{
	ns_log(LOG_INFO, zone, op, dir, remote,
	       "finished, %0.2f seconds, %u messages, %u bytes",
	       time_diff_ms(&stats->begin, &stats->end) / 1000.0,
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
