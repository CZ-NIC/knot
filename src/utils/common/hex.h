/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>

/*!
 * \brief Convert string encoded in hex to bytes.
 *
 * \param input        Hex encoded input string.
 * \param output       Decoded bytes.
 * \param output_size  Size of the output.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int hex_decode(const char *input, uint8_t **output, size_t *output_size);
