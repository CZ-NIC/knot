#pragma once

#include <stdint.h>
#include <stdlib.h>

typedef struct dnssec_binary {
	uint8_t *data;
	size_t size;
} dnssec_binary_t;
