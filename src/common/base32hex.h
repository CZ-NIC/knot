/* base32hex.h -- Encode binary data using printable characters.
   Copyright (C) 2004, 2005, 2006, 2010 Free Software Foundation, Inc.
   Written by Ondřej Surý & Simon Josefsson.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef _BASE32HEX_H_
#define _BASE32HEX_H_

/* Get size_t. */
#include <stddef.h>

/* Get bool. */
#include <stdbool.h>

/*!
 * \brief Counts the size of the Base32Hex-encoded output for given input
 *        length.
 *
 * \note This uses that the expression (n+(k-1))/k means the smallest
 *       integer >= n/k, i.e., the ceiling of n/k.
 */
#define BASE32HEX_LENGTH(inlen) ((((inlen) + 4) / 5) * 8)

/*!
 * \brief Checks if the given character belongs to the Base32Hex alphabet.
 *
 * \param ch Character to check.
 *
 * \retval true if \a ch belongs to the Base32Hex alphabet.
 * \retval false otherwise.
 */
extern bool isbase32hex(char ch);

/*!
 * \brief Encodes the given character array using Base32 encoding with extended
 *        hex alphabet.
 *
 * If \a outlen is less than BASE32HEX_LENGTH(\a inlen), the function writes as
 * many bytes as possible to the output buffer. If \a outlen is more than
 * BASE32HEX_LENGTH(\a inlen), the output will be zero-terminated.
 *
 * \param in Input array of characters.
 * \param inlen Length of the input array.
 * \param out Output buffer.
 * \param outlen Size of the output buffer.
 */
extern void base32hex_encode(const char *in, size_t inlen, char *out,
                          size_t outlen);

/*!
 * \brief Encodes the given character array using Base32 encoding with extended
 *        hex alphabet and allocates space for the output.
 *
 * \param in Input array of characters.
 * \param inlen Length of the input array.
 * \param out Output buffer.
 *
 * \return Size of the allocated output buffer (0 if failed).
 */
extern size_t base32hex_encode_alloc(const char *in, size_t inlen, char **out);

/*!
 * \brief Decodes the given character array in Base32 encoding with extended
 *        hex alphabet.
 *
 * If \a *outlen is too small, as many bytes as possible will be written to
 * \a out. On return, \a *outlen holds the length of decoded bytes in \a out.
 *
 * \note As soon as any non-alphabet characters are encountered, decoding is
 *       stopped and false is returned.  This means that, when applicable, you
 *       must remove any line terminators that is part of the data stream before
 *       calling this function.
 *
 * \param in Input array of characters.
 * \param inlen Length of the input array.
 * \param out Output buffer.
 * \param outlen Size of the output buffer.
 *
 * \retval true if decoding was successful, i.e. if the input was valid
 *              base32hex data.
 * \retval false otherwise.
 */
extern bool base32hex_decode(const char *in, size_t inlen, char *out,
                          size_t *outlen);

/*!
 * \brief Allocate an output buffer and decode the base32hex encoded data to it.
 *
 * On return, the size of the decoded data is stored in \a *outlen. \a outlen
 * may be NULL, if the caller is not interested in the decoded length. \a *out
 * may be NULL to indicate an out of memory error, in which case \a *outlen
 * contains the size of the memory block needed.
 *
 * \param in Input array of characters.
 * \param inlen Length of the input array.
 * \param out Output buffer. \a *out may be NULL to indicate an out of memory
 *            error in which case \a *outlen contains the size of the memory
 *            block needed
 * \param outlen Size of the output buffer. May be NULL, if the caller is not
 *               interested in the decoded length
 *
 * \retval true on successful decoding and memory allocation errors. (Use the
 *              \a *out and \a *outlen parameters to differentiate between
 *              successful decoding and memory error.)
 * \retval false if the input was invalid, in which case \a *out is NULL and
 *               \a *outlen is undefined.
 */
extern bool base32hex_decode_alloc(const char *in, size_t inlen, char **out,
                                size_t *outlen);

#endif /* _BASE32HEX_H_ */
