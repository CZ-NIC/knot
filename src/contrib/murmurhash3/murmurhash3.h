/*
 * This is MurmurHash3. The original C++ code was placed in the public domain
 * by its author, Austin Appleby.
 */

#pragma once

#include <stdlib.h>
#include <stdint.h>

uint32_t hash(const char* data, size_t len);
