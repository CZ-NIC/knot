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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file
 *
 * \brief API for manipulating rdata.
 *
 * \addtogroup libknot
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
 * \brief Inits rdata structure.
 *
 * \param buf   Rdata structure to be initialized. At least knot_rdata_size bytes
 *              must fit into it!
 * \param len   Rdata length.
 * \param data  Rdata itself.
 */
inline static void knot_rdata_init(knot_rdata_t *rdata, uint16_t len, const uint8_t *data)
{
	assert(rdata);
	rdata->len = len;
	memcpy(rdata->data, data, len);
}

/*!
 * \brief Returns RDATA size of single RR.
 *
 * \param rr  RR whose size we want.
 * \return RR size.
 */
inline static uint16_t knot_rdata_rdlen(const knot_rdata_t *rr)
{
	assert(rr);
	return rr->len;
}

/*!
 * \brief Sets size for given RR.
 *
 * \param rr   RR whose size we want to set.
 * \param len  Size to be set.
 */
inline static void knot_rdata_set_rdlen(knot_rdata_t *rr, uint16_t len)
{
	assert(rr);
	rr->len = len;
}

/*!
 * \brief Returns pointer to RR data.
 *
 * \param rr  RR whose data we want.
 * \return RR data pointer.
 */
inline static uint8_t *knot_rdata_data(const knot_rdata_t *rr)
{
	assert(rr);
	return (uint8_t *)rr->data;
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

/*! @} */
