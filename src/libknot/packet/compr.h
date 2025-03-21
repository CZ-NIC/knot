/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief Name compression API.
 *
 * \addtogroup pkt
 * @{
 */

#pragma once

#include <stdint.h>

#include "libknot/packet/wire.h"

/*! \brief Compression hint type. */
enum knot_compr_hint {
	KNOT_COMPR_HINT_NONE    = 0, /* No hint. */
	KNOT_COMPR_HINT_NOCOMP  = 1, /* Don't compress. */
	KNOT_COMPR_HINT_QNAME   = KNOT_WIRE_HEADER_SIZE /* Name is QNAME. */
};

/*! \brief Compression hint array offsets. */
enum knot_compr_offset {
	KNOT_COMPR_HINT_OWNER = 0,  /* First element in the array is RR owner. */
	KNOT_COMPR_HINT_RDATA = 1,  /* First name in RDATA is at offset 1. */
	KNOT_COMPR_HINT_COUNT = 16  /* Maximum number of stored hints per-RR. */
};

/*
 * \note A little bit about how compression hints work.
 *
 * We're storing a RRSet say 'abcd. CNAME [0]net. [1]com.' (owner=abcd. 2 RRs).
 * The owner 'abcd.' is same for both RRs, we put it at the offset 0 in rrinfo.compress_ptr
 * The names 'net.' and 'com.' are in the RDATA, therefore go to offsets 1 and 2.
 * Now this is useful when solving additionals for example, because we can scan
 * rrinfo for this RRSet and we know that 'net.' name is at the hint 1 and that leads
 * to packet position N. With that, we just put the pointer in without any calculation.
 * This is also useful for positive answers, where we know the RRSet owner is always QNAME.
 * All in all, we just remember the positions of written domain names.
 */

/*! \brief Additional information about RRSet position and compression hints. */
typedef struct {
	uint16_t pos;   /* RRSet position in the packet. */
	uint16_t flags; /* RRSet flags. */
	uint16_t compress_ptr[KNOT_COMPR_HINT_COUNT]; /* Array of compr. ptr hints. */
} knot_rrinfo_t;

/*!
 * \brief Name compression context.
 */
typedef struct knot_compr {
	uint8_t *wire;          /* Packet wireformat. */
	knot_rrinfo_t *rrinfo;  /* Hints for current RRSet. */
	struct {
		uint16_t pos;   /* Position of current suffix. */
		uint8_t labels; /* Label count of the suffix. */
	} suffix;
} knot_compr_t;

/*!
 * \brief Retrieve compression hint from given offset.
 */
static inline uint16_t knot_compr_hint(const knot_rrinfo_t *info, uint16_t hint_id)
{
	if (hint_id < KNOT_COMPR_HINT_COUNT) {
		return info->compress_ptr[hint_id];
	} else {
		return KNOT_COMPR_HINT_NONE;
	}
}

/*!
 * \brief Store compression hint for given offset.
 */
static inline void knot_compr_hint_set(knot_rrinfo_t *info, uint16_t hint_id,
                                       uint16_t val, uint16_t len)
{
	if ((hint_id < KNOT_COMPR_HINT_COUNT) && (val + len < KNOT_WIRE_PTR_MAX)) {
		info->compress_ptr[hint_id] = val;
	}
}

/*! @} */
