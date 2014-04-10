#pragma once

#include "binary.h"

/*!
 * Convert binary data to preallocated hexadecimal string.
 */
int bin_to_hex_static(const dnssec_binary_t *bin, dnssec_binary_t *hex);

/**
 * Convert binary data to hexadecimal string.
 */
int bin_to_hex(const dnssec_binary_t *bin, char **hex_ptr);

/*!
 * Convert hex encoded string to preallocated binary data.
 */
int hex_to_bin_static(const dnssec_binary_t *hex, dnssec_binary_t *bin);

/*!
 * Convert hex encoded string to binary data.
 */
int hex_to_bin(const char *hex, dnssec_binary_t *bin);
