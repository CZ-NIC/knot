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
 * \brief Value transformations for Yparser.
 *
 * \addtogroup yparser
 * @{
 */

#pragma once

#include "libknot/yparser/ypschema.h"

struct knot_lookup;

/*!
 * Transforms textual item value to binary form.
 *
 * \param[in] item Schema item to transform.
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
 * \param[in] item Schema item to transform.
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
 * Converts binary value to string pointer.
 *
 * \param[in] data Binary value to transform.
 *
 * \return String pointer.
 */
inline static const char* yp_str(
	const uint8_t *data)
{
	return (const char *)data;
}

/*!
 * Converts binary value to boolean value.
 *
 * \param[in] data Binary value to transform.
 *
 * \return Boolean value.
 */
inline static bool yp_bool(
	const uint8_t *data)
{
	return (data[0] == 0) ? false : true;
}

/*!
 * Converts binary value to integer value.
 *
 * \param[in] data Binary value to transform.
 *
 * \return Integer value.
 */
int64_t yp_int(
	const uint8_t *data
);

/*!
 * Converts binary value to address value.
 *
 * \param[in] data Binary value to transform.
 *
 * \return Address value.
 */
struct sockaddr_storage yp_addr_noport(
	const uint8_t *data
);

/*!
 * Converts binary value to address value with an optional port.
 *
 * \param[in] data Binary value to transform.
 * \param[out] no_port No port indicator.
 *
 * \return Address value.
 */
struct sockaddr_storage yp_addr(
	const uint8_t *data,
	bool *no_port
);

/*!
 * Converts binary value to option value.
 *
 * \param[in] data Binary value to transform.
 *
 * \return Unsigned value.
 */
inline static unsigned yp_opt(
	const uint8_t *data)
{
	return (unsigned)data[0];
}

/*!
 * Converts binary value to dname pointer.
 *
 * \param[in] data Binary value to transform.
 *
 * \return Dname pointer.
 */
inline static const uint8_t* yp_dname(
	const uint8_t *data)
{
	return data;
}

/*!
 * Converts binary value to data pointer.
 *
 * Applies to all data types with 2-byte length prefix (YP_THEX, YP_TB64).
 *
 * \param[in] data Binary value to transform.
 *
 * \return Data pointer.
 */
inline static const uint8_t* yp_bin(
	const uint8_t *data)
{
	return data + 2;
}

/*!
 * Gets binary value length.
 *
 * Applies to all data types with 2-byte length prefix (YP_THEX, YP_TB64).
 *
 * \param[in] data Binary value to transform.
 *
 * \return Data length.
 */
const size_t yp_bin_len(
	const uint8_t *data
);

/*!
 * \brief Helper macros for conversion functions.
 */

#define YP_CHECK_CTX \
	if (in->error != KNOT_EOK) { \
		return in->error; \
	} else if (out->error != KNOT_EOK) { \
		return out->error; \
	} \

#define YP_CHECK_STOP \
	if (stop != NULL) { \
		assert(stop <= in->position + wire_ctx_available(in)); \
	} else { \
		stop = in->position + wire_ctx_available(in); \
	}

#define YP_LEN (stop - in->position)

#define YP_CHECK_PARAMS_BIN \
	YP_CHECK_CTX YP_CHECK_STOP

#define YP_CHECK_PARAMS_TXT \
	YP_CHECK_CTX

#define YP_CHECK_RET \
	YP_CHECK_CTX return KNOT_EOK;

/*!
 * \brief Conversion functions for basic types.
 */

int yp_str_to_bin(
	YP_TXT_BIN_PARAMS
);

int yp_str_to_txt(
	YP_BIN_TXT_PARAMS
);

int yp_bool_to_bin(
	YP_TXT_BIN_PARAMS
);

int yp_bool_to_txt(
	YP_BIN_TXT_PARAMS
);

int yp_int_to_bin(
	YP_TXT_BIN_PARAMS,
	int64_t min,
	int64_t max,
	yp_style_t style
);

int yp_int_to_txt(
	YP_BIN_TXT_PARAMS,
	yp_style_t style
);

int yp_addr_noport_to_bin(
	YP_TXT_BIN_PARAMS,
	bool allow_unix
);

int yp_addr_noport_to_txt(
	YP_BIN_TXT_PARAMS
);

int yp_addr_to_bin(
	YP_TXT_BIN_PARAMS
);

int yp_addr_to_txt(
	YP_BIN_TXT_PARAMS
);

int yp_addr_range_to_bin(
	YP_TXT_BIN_PARAMS
);

int yp_addr_range_to_txt(
	YP_BIN_TXT_PARAMS
);

int yp_option_to_bin(
	YP_TXT_BIN_PARAMS,
	const struct knot_lookup *opts
);

int yp_option_to_txt(
	YP_BIN_TXT_PARAMS,
	const struct knot_lookup *opts
);

int yp_dname_to_bin(
	YP_TXT_BIN_PARAMS
);

int yp_dname_to_txt(
	YP_BIN_TXT_PARAMS
);

int yp_hex_to_bin(
	YP_TXT_BIN_PARAMS
);

int yp_hex_to_txt(
	YP_BIN_TXT_PARAMS
);

int yp_base64_to_bin(
	YP_TXT_BIN_PARAMS
);

int yp_base64_to_txt(
	YP_BIN_TXT_PARAMS
);

/*! @} */
