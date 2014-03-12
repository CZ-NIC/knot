#pragma once

#include <stddef.h>
#include <stdint.h>

/*!
 * Context for encoding of RR types bitmap used in NSEC/NSEC3.
 */
struct dnssec_nsec_bitmap;
typedef struct dnssec_nsec_bitmap dnssec_nsec_bitmap_t;

/*!
 * Allocate new bit map encoding context.
 */
dnssec_nsec_bitmap_t *dnssec_nsec_bitmap_new(void);

/*!
 * Clear existing bit map encoding context.
 */
void dnssec_nsec_bitmap_clear(dnssec_nsec_bitmap_t *bitmap);

/*!
 * Free bit map encoding context.
 */
void dnssec_nsec_bitmap_free(dnssec_nsec_bitmap_t *bitmap);

/*!
 * Add one RR type into the bitmap.
 */
void dnssec_nsec_bitmap_add(dnssec_nsec_bitmap_t *bitmap, uint16_t type);

/*!
 * Compute the size of the encoded bitmap.
 */
size_t dnssec_nsec_bitmap_size(const dnssec_nsec_bitmap_t *bitmap);

/*!
 * Write encoded bitmap into the given buffer.
 */
void dnssec_nsec_bitmap_write(const dnssec_nsec_bitmap_t *bitmap, uint8_t *output);
