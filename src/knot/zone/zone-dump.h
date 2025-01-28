/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#ifdef ENABLE_REDIS
#include <hiredis/hiredis.h>
#endif

#include "knot/zone/skip.h"
#include "knot/zone/zone.h"

/*!
 * \brief Dumps given zone to text file.
 *
 * \param zone      Zone to be saved.
 * \param skip      RRRTypes to be skipped.
 * \param file      File to write to.
 * \param comments  Add separating comments indicator.
 * \param color     Optional color control sequence.
 *
 * \retval KNOT_EOK on success.
 * \retval < 0 if error.
 */
int zone_dump_text(zone_contents_t *zone, zone_skip_t *skip, FILE *file, bool comments, const char *color);
#ifdef ENABLE_REDIS
int zone_dump_rdb(zone_contents_t *zone, redisContext *rdb);
#endif
