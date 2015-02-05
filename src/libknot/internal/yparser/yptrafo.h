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
 * Value transformations for Yparser.
 *
 * \addtogroup yparser
 *
 * @{
 */

#pragma once

#include "libknot/internal/yparser/ypscheme.h"
#include "libknot/internal/endian.h"
#include "libknot/dname.h"

/*!
 * Transforms textual item value to binary form.
 *
 * \param[in] item Scheme item to transform.
 * \param[in] txt Value to transform.
 * \param[in] txt_len Value length.
 * \param[out] bin Output buffer.
 * \param[in, out] bin_len Output buffer length, output length.
 *
 * \return Error code, KNOT_EOK if success.
 */
int yp_item_to_bin(
	const yp_item_t *item,
	const char *txt,
	size_t txt_len,
	uint8_t *bin,
	size_t *bin_len
);

/*!
 * Transforms binary item value to textual form.
 *
 * \param[in] item Scheme item to transform.
 * \param[in] bin Value to transform.
 * \param[in] bin_len Value length.
 * \param[out] txt Output buffer.
 * \param[in, out] txt_len Output buffer length, output length.
 * \param[in] style Value style.
 *
 * \return Error code, KNOT_EOK if success.
 */
int yp_item_to_txt(
	const yp_item_t *item,
	const uint8_t *bin,
	size_t bin_len,
	char *txt,
	size_t *txt_len,
	yp_style_t style
);

/*!
 * Converts binary value to integer value.
 *
 * \param[in] data Binary value to to transform.
 * \param[in] data_len Length of the value.
 *
 * \return Integer value.
 */
inline static int64_t yp_int(
	const uint8_t *data,
	size_t data_len)
{
	int64_t num = 0;
	memcpy(&num, data, data_len);
	return le64toh(num);
}

/*!
 * Converts binary value to boolean value.
 *
 * \param[in] data_len Length of the value.
 *
 * \return Boolean value.
 */
inline static bool yp_bool(
	size_t data_len)
{
	return (data_len > 0) ? true : false;
}

/*!
 * Converts binary value to option value.
 *
 * \param[in] data Binary value to to transform.
 *
 * \return Unsigned value.
 */
inline static unsigned yp_opt(
	const uint8_t *data)
{
	return (unsigned)data[0];
}

/*!
 * Converts binary value to string pointer.
 *
 * \param[in] data Binary value to to transform.
 *
 * \return String ointer.
 */
inline static const char* yp_str(
	const uint8_t *data)
{
	return (const char *)data;
}

/*!
 * Converts binary value to address value with port/mask.
 *
 * \param[in] data Binary value to to transform.
 * \param[in] data_len Length of the value.
 * \param[out] num Possible port/prefix value.
 *
 * \return Address value.
 */
struct sockaddr_storage yp_addr(
	const uint8_t *data,
	size_t data_len,
	int *num
);

/*!
 * Converts binary value to dname pointer.
 *
 * \param[in] data Binary value to to transform.
 *
 * \return Dname pointer.
 */
inline static const knot_dname_t* yp_dname(
	const uint8_t *data)
{
	return (const knot_dname_t *)data;
}

/*! @} */
