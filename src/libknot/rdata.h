/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief API for manipulating RRs.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/* ---------------------------- Single RR ----------------------------------- */

/*!< \brief Maximum rdata data size. */
#define MAX_RDLENGTH 65535

/*!
 * \brief knot_rdata_t Array holding single RR payload, i.e. TTL, RDLENGTH and RDATA.
 */
typedef uint8_t knot_rdata_t;

/* ------------------------------- Init ------------------------------------- */

/*!
 * \brief Inits knot_rdata_t structure - the structure has to be created using
 *        knot_rdata_array_size.
 */
void knot_rdata_init(knot_rdata_t *rdata,
                     uint16_t rdlen, const uint8_t *data, uint32_t ttl);

/* ------------------------- RR getters/setters ----------------------------- */

/*!
 * \brief Returns RDATA size of single RR.
 * \param rr  RR whose size we want.
 * \return  RR size.
 */
uint16_t knot_rdata_rdlen(const knot_rdata_t *rr);

/*!
 * \brief Sets size for given RR.
 * \param rr    RR whose size we want to set.
 * \param size  Size to be set.
 */
void knot_rdata_set_rdlen(knot_rdata_t *rr, uint16_t size);

/*!
 * \brief Returns TTL of single RR.
 * \param rr  RR whose TTL we want.
 * \return  RR TTL.
 */
uint32_t knot_rdata_ttl(const knot_rdata_t *rr);

/*!
 * \brief Sets TTL for given RR.
 * \param rr   RR whose TTL we want to set.
 * \param ttl  TTL to be set.
 */
void knot_rdata_set_ttl(knot_rdata_t *rr, uint32_t ttl);

/*!
 * \brief Returns pointer to RR data.
 * \param rr  RR whose data we want.
 * \return RR data pointer.
 */
uint8_t *knot_rdata_data(const knot_rdata_t *rr);

/* ----------------------------- RR misc ------------------------------------ */

/*!
 * \brief Returns actual size of RR structure for given RDATA size.
 * \param size  RDATA size.
 * \return Actual structure size.
 */
size_t knot_rdata_array_size(uint16_t size);

/*!
 * \brief Canonical comparison of two RRs. Both RRs *must* exist.
 *        TTLs are *not* compared.
 * \param rr1  First RR to compare.
 * \param rr2  Second RR to compare.
 * \retval 0 if rr1 == rr2.
 * \retval < 0 if rr1 < rr2.
 * \retval > 0 if rr1 > rr2.
 */
int knot_rdata_cmp(const knot_rdata_t *rr1, const knot_rdata_t *rr2);

/*! @} */
