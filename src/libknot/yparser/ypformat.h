/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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

#include "libknot/yparser/ypschema.h"

/*!
 * Formats key0 item.
 *
 * \param[in] item Schema item to format.
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
 * \param[in] item Schema item to format.
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
 * \param[in] item Schema item to format.
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
