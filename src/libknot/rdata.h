/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief API for manipulating rdata.
 *
 * \addtogroup rr
 * @{
 */

#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*!< \brief Maximum rdata length. */
#define KNOT_RDATA_MAXLEN 65535

/*!
 * \brief Structure holding single rdata payload.
 */
typedef struct {
	uint16_t len;
	uint8_t data[];
} knot_rdata_t;


/*!
 * \brief Dummy fixed-sized compatible structure for static initialization in simple cases.
 */
typedef struct {
	uint16_t len;
	uint8_t data[254];
} knot_rdata254_t;

/*!
 * \brief Inits rdata structure.
 *
 * \param rdata  Rdata structure to be initialized. At least knot_rdata_size bytes
 *               must fit into it!
 * \param len    Rdata length.
 * \param data   Rdata itself.
 */
inline static void knot_rdata_init(knot_rdata_t *rdata, uint16_t len, const uint8_t *data)
{
	assert(rdata);
	rdata->len = len;
	if (rdata->len > 0) {
		assert(data);
		memcpy(rdata->data, data, len);
		if (len & 1) { // Initialize possible padding to mute analytical tools.
			rdata->data[len] = 0;
		}
	}
}

/*!
 * \brief Returns actual size of the rdata structure for given rdata length.
 *
 * \param len  Rdata length.
 *
 * \return Actual structure size.
 */
inline static size_t knot_rdata_size(uint16_t len)
{
	return sizeof(uint16_t) + len + (len & 1);
}

/*!
 * \brief Canonical comparison of two rdata structures.
 *
 * \param rdata1  First rdata to compare.
 * \param rdata2  Second rdata to compare.
 *
 * \retval = 0 if rdata1 == rdata2.
 * \retval < 0 if rdata1 <  rdata2.
 * \retval > 0 if rdata1 >  rdata2.
 */
inline static int knot_rdata_cmp(const knot_rdata_t *rdata1, const knot_rdata_t *rdata2)
{
	assert(rdata1);
	assert(rdata2);

	size_t common_len = (rdata1->len <= rdata2->len) ? rdata1->len : rdata2->len;

	int cmp = memcmp(rdata1->data, rdata2->data, common_len);
	if (cmp == 0 && rdata1->len != rdata2->len) {
		cmp = rdata1->len < rdata2->len ? -1 : 1;
	}
	return cmp;
}

/*!
 * \brief Converts rdata into canonical format.
 *
 * Rdata domain names are converted only for types listed in RFC 4034,
 * Section 6.2, except for NSEC (updated by RFC 6840, Section 5.1) and
 * A6 (not supported).
 *
 * \warning This function expects either empty rdata or full, not malformed
 *          rdata. If malformed rdata is passed to this function, memory errors
 *          may occur.
 *
 * \param rdata  Rdata to convert.
 * \param type   Rdata type.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_rdata_to_canonical(knot_rdata_t *rdata, uint16_t type);

/*! @} */
