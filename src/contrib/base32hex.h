/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Base32hex implementation (RFC 4648).
 *
 * \note Input Base32hex string can contain a-v characters. These characters
 *       are considered as A-V equivalent. Lower-case variant is used for encoding!
 */

#pragma once

#include <stdint.h>

/*!
 * \brief Encodes binary data using Base32hex.
 *
 * \note Output data buffer contains Base32hex text string which isn't
 *       terminated with '\0'!
 *
 * \param in		Input binary data.
 * \param in_len	Length of input data.
 * \param out		Output data buffer.
 * \param out_len	Size of output buffer.
 *
 * \retval >=0		length of output string.
 * \retval KNOT_ESPACE	if output buffer is not large enough.
 * \return KNOT_E*	if other error.
 */
int32_t knot_base32hex_encode(const uint8_t  *in,
                              const uint32_t in_len,
                              uint8_t        *out,
                              const uint32_t out_len);

/*!
 * \brief Encodes binary data using Base32hex and output stores to own buffer.
 *
 * \note Output data buffer contains Base32hex text string which isn't
 *       terminated with '\0'!
 *
 * \note Output buffer should be deallocated after use.
 *
 * \param in		Input binary data.
 * \param in_len	Length of input data.
 * \param out		Output data buffer.
 *
 * \retval >=0		length of output string.
 * \retval KNOT_E*	if error.
 */
int32_t knot_base32hex_encode_alloc(const uint8_t  *in,
                                    const uint32_t in_len,
                                    uint8_t        **out);

/*!
 * \brief Decodes text data using Base32hex.
 *
 * \note Input data needn't be terminated with '\0'.
 *
 * \note Input data must be continuous Base32hex string!
 *
 * \param in		Input text data.
 * \param in_len	Length of input string.
 * \param out		Output data buffer.
 * \param out_len	Size of output buffer.
 *
 * \retval >=0		length of output data.
 * \retval KNOT_ESPACE	if output buffer is not large enough.
 * \return KNOT_E*	if other error.
 */
int32_t knot_base32hex_decode(const uint8_t  *in,
                              const uint32_t in_len,
                              uint8_t        *out,
                              const uint32_t out_len);

/*!
 * \brief Decodes text data using Base32hex and output stores to own buffer.
 *
 * \note Input data needn't be terminated with '\0'.
 *
 * \note Input data must be continuous Base32hex string!
 *
 * \note Output buffer should be deallocated after use.
 *
 * \param in		Input text data.
 * \param in_len	Length of input string.
 * \param out		Output data buffer.
 *
 * \retval >=0		length of output data.
 * \retval KNOT_E*	if error.
 */
int32_t knot_base32hex_decode_alloc(const uint8_t  *in,
                                    const uint32_t in_len,
                                    uint8_t        **out);
