/*!
 * \file compr.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Name compression API.
 *
 * \addtogroup libknot
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

#ifndef _KNOT_COMPR_H_
#define _KNOT_COMPR_H_

#include "libknot/packet/wire.h"

enum {
	COMPR_HINT_NONE = 0,
	COMPR_HINT_NOCOMP  = 1,
	COMPR_HINT_QNAME = KNOT_WIRE_HEADER_SIZE
};

enum {
	COMPR_HINT_OWNER = 0,
	COMPR_HINT_RDATA = 1,
	COMPR_HINT_COUNT = 4
};

typedef struct {
	uint16_t pos;
	uint16_t flags;
	uint16_t compress_ptr[COMPR_HINT_COUNT];
} knot_rrinfo_t;

/*!
 * \brief Holds information about compressed domain names in packet.
 *
 * Used only to pass information between functions.
 *
 */
typedef struct knot_compr {
	uint8_t *wire;
	size_t wire_pos;
	knot_rrinfo_t *rrinfo;
	struct {
		uint16_t pos;
		uint8_t labels;
	} suffix;
} knot_compr_t;

static inline uint16_t knot_pkt_compr_hint(const knot_rrinfo_t *info, uint16_t hint_id)
{
	if (hint_id < COMPR_HINT_COUNT) {
		return info->compress_ptr[hint_id];
	} else {
		return COMPR_HINT_NONE;
	}
}

static inline void knot_pkt_compr_hint_set(knot_rrinfo_t *info, uint16_t hint_id, uint16_t val)
{
	if (hint_id < COMPR_HINT_COUNT && val < KNOT_WIRE_PTR_MAX) {
		info->compress_ptr[hint_id] = val;
	}
}

#endif /* _KNOT_COMPR_H_ */

/*! @} */
