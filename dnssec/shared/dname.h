#pragma once

#include <stdint.h>
#include <stdlib.h>

/*!
 * Maximal length of domain name including labels and length bytes.
 * \see RFC 1035
 */
#define DNAME_MAX_LENGTH 255

/*!
 * Maximal length of the domain name label, excluding the label size.
 * \see RFC 1035
 */
#define DNAME_MAX_LABEL_LENGTH 63

/*!
 * Get length of a domain name in wire format.
 */
size_t dname_length(const uint8_t *dname);

/*!
 * Copy domain name in wire format.
 */
uint8_t *dname_copy(const uint8_t *dname);

/*!
 * Normalize domain name in wire format.
 *
 * Currently converts all letters to lowercase.
 */
void dname_normalize(uint8_t *dname);

/*!
 * Convert domain name to human readable ASCII representation.
 *
 * The last label is NOT terminated by dot.
 */
char *dname_to_ascii(const uint8_t *dname);

/*!
 * Convert ASCII domain name to wire format.
 */
uint8_t *dname_from_ascii(const char *name);

/*!
 * Normalize ASCII domain name.
 *
 * Convert to lower case, trim rightmost empty labels.
 */
void dname_ascii_normalize(char *name);
