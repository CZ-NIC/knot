#pragma once

#include <stdint.h>
#include <stdbool.h>

#define DNSSEC_KEYID_SIZE 40
#define DNSSEC_KEYID_BINARY_SIZE 20

/*!
 * Check if a provided string is a valid key ID string.
 */
bool dnssec_keyid_is_valid(const char *id);

/*!
 * Normalize the key ID string.
 */
void dnssec_keyid_normalize(char *id);

/*!
 * Create a normalized copy if the key ID.
 */
char *dnssec_keyid_copy(const char *id);

/*!
 * Check if two key IDs are equal.
 */
bool dnssec_keyid_equal(const char *one, const char *two);
