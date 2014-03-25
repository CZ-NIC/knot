
#pragma once

#include <stdlib.h>
#include <stdint.h>

#include "common/mempattern.h"

typedef uint8_t knot_rr_t;

typedef struct knot_rrs {
	uint16_t rr_count;
	knot_rr_t *data;
} knot_rrs_t;

uint16_t knot_rr_size(const knot_rr_t *rr);
uint32_t knot_rr_ttl(const knot_rr_t *rr);
const uint8_t *knot_rr_rdata(const knot_rr_t *rr);
uint8_t *knot_rr_get_rdata(knot_rr_t *rr);
void knot_rr_set_size(knot_rr_t *rr, uint16_t size);
void knot_rr_set_ttl(knot_rr_t *rr, uint32_t ttl);
int knot_rrs_add_rr(knot_rrs_t *rrs, const knot_rr_t *rr, mm_ctx_t *mm);
knot_rrs_t *knot_rrs_new(mm_ctx_t *mm);
void knot_rrs_init(knot_rrs_t *rrs);
size_t knot_rrs_size(const knot_rrs_t *rrs);
uint16_t knot_rrs_rr_count(const knot_rrs_t *rrs);
knot_rr_t *knot_rrs_get_rr(const knot_rrs_t *rrs, size_t pos);
const knot_rr_t *knot_rrs_rr(const knot_rrs_t *rrs, size_t pos);
const uint8_t *knot_rrs_rr_rdata(const knot_rrs_t *rrs, size_t pos);
uint8_t *knot_rrs_rr_get_rdata(const knot_rrs_t *rrs, size_t pos);
uint16_t knot_rrs_rr_size(const knot_rrs_t *rrs, size_t pos);
uint32_t knot_rrs_rr_ttl(const knot_rrs_t *rrs, size_t pos);
uint8_t* knot_rrs_create_rr(knot_rrs_t *rrs, const uint16_t size,
                            const uint32_t ttl, mm_ctx_t *mm);
uint8_t* knot_rrs_create_rr_at_pos(knot_rrs_t *rrs,
                                   size_t pos, uint16_t size,
                                   uint32_t ttl, mm_ctx_t *mm);
int knot_rrs_remove_rr_at_pos(knot_rrs_t *rrs, size_t pos, mm_ctx_t *mm);
void knot_rrs_free(knot_rrs_t *rrs, mm_ctx_t *mm);
void knot_rrs_clear(knot_rrs_t *rrs, mm_ctx_t *mm);
int knot_rrs_copy(knot_rrs_t *dst, const knot_rrs_t *src, mm_ctx_t *mm);
int knot_rrs_synth_rrsig(uint16_t type, const knot_rrs_t *rrsig_rrs,
                         knot_rrs_t *out_sig, mm_ctx_t *mm);

