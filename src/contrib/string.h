/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief String manipulations.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

extern const char *configure_summary;

/*!
 * \brief Create a copy of a binary buffer.
 *
 * Like \c strdup, but for binary data.
 */
uint8_t *memdup(const uint8_t *data, size_t data_size);

/*!
 * \brief Compare a zero-terminated string with fixed-size memory.
 */
int strmemcmp(const char *str, const uint8_t *mem, size_t mem_size);

/*!
 * \brief Format string and take care of allocating memory.
 *
 * \note sprintf(3) manual page reference implementation.
 *
 * \param fmt Message format.
 * \return formatted message or NULL.
 */
char *sprintf_alloc(const char *fmt, ...);

/*!
 * \brief Create new string from a concatenation of s1 and s2.
 *
 * \param s1 First string.
 * \param s2 Second string.
 *
 * \retval Newly allocated string on success.
 * \retval NULL on error.
 */
char *strcdup(const char *s1, const char *s2);

/*!
 * \brief Create a copy of a string skipping leading and trailing white spaces.
 *
 * \return Newly allocated string, NULL in case of error.
 */
char *strstrip(const char *str);

/*!
 * \brief Convert upper-case letters to lower-case in a string.
 */
void strtolower(char *str);

/*!
 * \brief Compare data in time based on string length.
 *        This function just checks for (in)equality not for relation
 *
 * \param s1 The first address to compare.
 * \param s2 The second address to compare.
 * \param n The size of memory to compare.
 *
 * \return Non zero on difference and zero if the buffers are identical.
 */
int const_time_memcmp(const void *s1, const void *s2, size_t n);

/*!
 * \brief Fill memory with zeroes.
 *
 * Inspired by OPENSSL_cleanse. Such a memset shouldn't be optimized out.
 *
 * \param s The address to fill.
 * \param n The size of memory to fill.
 *
 * \return Pointer to the memory.
 */
void *memzero(void *s, size_t n);

/*!
 * \brief Convert binary data to hexadecimal string.
 */
char *bin_to_hex(const uint8_t *bin, size_t bin_len, bool upper_case);

/*!
 * \brief Convert hex encoded string to binary data.
 */
uint8_t *hex_to_bin(const char *hex, size_t *out_len);
