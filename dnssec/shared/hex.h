#pragma once

#include "binary.h"

/**
 * Convert binary data to hexadeciml string.
 */
int bin_to_hex(const dnssec_binary_t *bin, char **hex_ptr);

/*!
 * Convert hex encoded string to binary data.
 */
int hex_to_bin(const char *hex, dnssec_binary_t *bin);
