#pragma once

#include "binary.h"

/**
 * Convert binary data to hexadeciml string.
 */
char *hex_to_string(const dnssec_binary_t *data);
