/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief Tools for Yparser format creation.
 *
 * \addtogroup yparser
 * @{
 */

#pragma once

#include "libknot/yparser/ypscheme.h"

/*!
 * Formats key0 item.
 *
 * \param[in] item Scheme item to format.
 * \param[in] data Data to format.
 * \param[in] data_len Data length.
 * \param[out] out Output buffer.
 * \param[in, out] out_len Output buffer length, output length.
 * \param[in] style Value style.
 * \param[in] first_value First value indication (multivalued support).
 * \param[in] last_value Last value indication (multivalued support).
 *
 * \return Error code, KNOT_EOK if success.
 */
int yp_format_key0(
	const yp_item_t *item,
	const uint8_t *data,
	size_t data_len,
	char *out,
	size_t out_len,
	yp_style_t style,
	bool first_value,
	bool last_value
);

/*!
 * Formats identifier item.
 *
 * \param[in] item Scheme item to format.
 * \param[in] data Data to format.
 * \param[in] data_len Data length.
 * \param[out] out Output buffer.
 * \param[in, out] out_len Output buffer length, output length.
 * \param[in] style Value style.
 *
 * \return Error code, KNOT_EOK if success.
 */
int yp_format_id(
	const yp_item_t *item,
	const uint8_t *data,
	size_t data_len,
	char *out,
	size_t out_len,
	yp_style_t style
);

/*!
 * Formats key1 item.
 *
 * \param[in] item Scheme item to format.
 * \param[in] data Data to format.
 * \param[in] data_len Data length.
 * \param[out] out Output buffer.
 * \param[in, out] out_len Output buffer length, output length.
 * \param[in] style Value style.
 * \param[in] first_value First value indication (multivalued support).
 * \param[in] last_value Last value indication (multivalued support).
 *
 * \return Error code, KNOT_EOK if success.
 */
int yp_format_key1(
	const yp_item_t *item,
	const uint8_t *data,
	size_t data_len,
	char *out,
	size_t out_len,
	yp_style_t style,
	bool first_value,
	bool last_value
);

/*! @} */
