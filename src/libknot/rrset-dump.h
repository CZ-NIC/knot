/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/*!
 * \file
 *
 * \brief RRset text dump facility.
 *
 * \addtogroup rr
 * @{
 */

#pragma once

#include <stdbool.h>

#include "libknot/rrset.h"

/*! \brief Text output settings. */
typedef struct {
	/*!< Wrap long records. */
	bool	wrap;
	/*!< Show class. */
	bool	show_class;
	/*!< Show TTL. */
	bool	show_ttl;
	/*!< Print extra information. */
	bool	verbose;
	/*!< Print RRSIG original TTL instead of rrset TTL. */
	bool	original_ttl;
	/*!< Show empty TTL value (keep indentation). */
	bool	empty_ttl;
	/*!< Format TTL as DHMS. */
	bool	human_ttl;
	/*!< Format timestamp as YYYYMMDDHHmmSS. */
	bool	human_timestamp;
	/*!< Force generic data representation. */
	bool	generic;
	/*!< Hide binary parts of RRSIGs and DNSKEYs. */
	bool	hide_crypto;
	/*!< ASCII string to IDN string transformation callback. */
	void (*ascii_to_idn)(char **name);
	/*!< Optional color control sequence which is put before every output line.
	 *   Not compatible with wrap. */
	const char *color;
} knot_dump_style_t;

/*! \brief Default dump style. */
extern const knot_dump_style_t KNOT_DUMP_STYLE_DEFAULT;

/*!
 * \brief Dumps rrset header.
 *
 * \param rrset		RRset to dump.
 * \param ttl		TTL to dump.
 * \param dst		Output buffer.
 * \param maxlen	Output buffer size.
 * \param style		Output style.
 *
 * \retval output length	if success.
 * \retval < 0			if error.
 */
int knot_rrset_txt_dump_header(const knot_rrset_t      *rrset,
                               const uint32_t          ttl,
                               char                    *dst,
                               const size_t            maxlen,
                               const knot_dump_style_t *style);

/*!
 * \brief Dumps rrset data.
 *
 * \param rrset		RRset to dump.
 * \param pos		Position of the record to dump.
 * \param dst		Output buffer.
 * \param maxlen	Output buffer size.
 * \param style		Output style.
 *
 * \retval output length	if success.
 * \retval < 0			if error.
 */
int knot_rrset_txt_dump_data(const knot_rrset_t      *rrset,
                             const size_t            pos,
                             char                    *dst,
                             const size_t            maxlen,
                             const knot_dump_style_t *style);

/*!
 * \brief Dumps rrset, re-allocates dst to double (4x, 8x, ...) if too small.
 *
 * \param rrset		RRset to dump.
 * \param dst		Output buffer.
 * \param dst_size	Output buffer size (changed if *dst re-allocated).
 * \param style		Output style.
 *
 * \retval output length	if success.
 * \retval < 0			if error.
 */
int knot_rrset_txt_dump(const knot_rrset_t      *rrset,
                        char                    **dst,
                        size_t                  *dst_size,
                        const knot_dump_style_t *style);

/*! @} */
