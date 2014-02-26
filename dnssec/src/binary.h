#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "shared.h"

#define _cleanup_binary_ _cleanup_(dnssec_binary_free)

typedef struct dnssec_binary {
	uint8_t *data;
	size_t size;
} dnssec_binary_t;

int dnssec_binary_from_base64(dnssec_binary_t *binary, const uint8_t *base64,
			      size_t base64_size);

void dnssec_binary_free(dnssec_binary_t *binary);
