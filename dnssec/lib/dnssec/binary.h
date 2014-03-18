#pragma once

#include <stdint.h>
#include <stdlib.h>

/*!
 * Universal structure to hold binary data.
 */
typedef struct dnssec_binary {
	uint8_t *data;
	size_t size;
} dnssec_binary_t;

/*!
 * Allocate binary from Base64 encoded string.
 *
 * \param[in]  base64  Base64 encoded data.
 * \param[out] binary  Decoded binary data.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_binary_from_base64(const dnssec_binary_t *base64,
			      dnssec_binary_t *binary);

/*!
 * Free content of binary structure.
 *
 * \param binary  Binary structure to be freed.
 */
void dnssec_binary_free(dnssec_binary_t *binary);

/*!
 * Create a copy of a binary structure.
 *
 * \param[in]  from  Source of the copy.
 * \param[out] to    Target of the copy.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_binary_dup(const dnssec_binary_t *from, dnssec_binary_t *to);

/*!
 * Resize binary structure to a new size.
 *
 * Internally uses \ref realloc, which means that this function can be
 * also used as alloc and free.
 *
 * \param data      Binary to be resized.
 * \param new_size  New size.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_binary_resize(dnssec_binary_t *data, size_t new_size);

/*!
 * Compare two binary structures (equivalent of memcmp).
 *
 * \note NULL sorts before data.
 *
 * \param one  First binary.
 * \param two  Second binary.
 *
 * \return 0 if one equals two, <0 if one sorts before two, >0 otherwise.
 */
int dnssec_binary_cmp(const dnssec_binary_t *one, const dnssec_binary_t *two);

/*!
 * Trim leading zeroes from the binary data.
 *
 * If the input are zeroes only, the last zero will be preserved.
 *
 * \param binary  Input to be trimmed.
 */
void dnssec_binary_ltrim(dnssec_binary_t *binary);
