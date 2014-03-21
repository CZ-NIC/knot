#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "libknot/rr.h"
#include "libknot/common.h"
#include "common/errcode.h"

static const size_t RR_META_SIZE = sizeof(uint16_t) + sizeof(uint32_t);

uint16_t knot_rr_size(const knot_rr_t *rr)
{
	return *((uint16_t *)rr);
}

uint32_t knot_rr_ttl(const knot_rr_t *rr)
{
	return *((uint32_t *)(rr + sizeof(uint16_t)));
}

const uint8_t *knot_rr_rdata(const knot_rr_t *rr)
{
	return (const uint8_t *)(rr + RR_META_SIZE);
}

uint8_t *knot_rr_get_rdata(knot_rr_t *rr)
{
	return rr + RR_META_SIZE;
}

void knot_rr_set_size(knot_rr_t *rr, uint16_t size)
{
	*((uint16_t *)rr) = size;
}

void knot_rr_set_ttl(knot_rr_t *rr, uint32_t ttl)
{
	*((uint32_t *)(rr + sizeof(uint16_t))) = ttl;
}

static knot_rr_t *rr_seek(knot_rr_t *d, size_t pos)
{
	if (d == NULL) {
		return NULL;
	}

	size_t offset = 0;
	for (size_t i = 0; i < pos; i++) {
		knot_rr_t *rr = d + offset;
		offset += knot_rr_size(rr) + RR_META_SIZE;
	}

	return d + offset;
}

knot_rr_t *knot_rrs_get_rr(const knot_rrs_t *rrs, size_t pos)
{
	if (rrs == NULL || pos >= rrs->rr_count) {
		return NULL;
	}

	return rr_seek(rrs->data, pos);
}

const knot_rr_t *knot_rrs_rr(const knot_rrs_t *rrs, size_t pos)
{
	if (rrs == NULL || pos >= rrs->rr_count) {
		return NULL;
	}

	return (const knot_rr_t *)rr_seek(rrs->data, pos);
}

size_t knot_rrs_size(const knot_rrs_t *rrs)
{
	if (rrs == NULL) {
		return 0;
	}

	size_t total_size = 0;
	for (size_t i = 0; i < rrs->rr_count; ++i) {
		const knot_rr_t *rr = knot_rrs_rr(rrs, i);
		assert(rr);
		total_size += knot_rr_size(rr) + RR_META_SIZE;
	}

	return total_size;
}

int knot_rrs_remove_rr_at_pos(knot_rrs_t *rrs, size_t pos, mm_ctx_t *mm)
{
	if (rrs == NULL || pos >= rrs->rr_count) {
		return KNOT_EINVAL;
	}

	knot_rr_t *old_rr = knot_rrs_get_rr(rrs, pos);
	knot_rr_t *last_rr = knot_rrs_get_rr(rrs, rrs->rr_count - 1);
	assert(old_rr);
	assert(last_rr);

	size_t total_size = knot_rrs_size(rrs);
	uint16_t old_size = knot_rr_size(old_rr);

	void *old_threshold = old_rr + old_size + RR_META_SIZE;
	void *last_threshold = last_rr + knot_rr_size(last_rr) + RR_META_SIZE;
	// Move RDATA
	memmove(old_rr, old_threshold,
	        last_threshold - old_threshold);

	if (rrs->rr_count > 1) {
		// Realloc RDATA
		void *tmp = mm_realloc(mm, rrs->data,
		                       total_size - (old_size + RR_META_SIZE),
		                       total_size);
		if (tmp == NULL) {
			ERR_ALLOC_FAILED;
		} else {
			rrs->data = tmp;
		}
	} else {
		// Free RDATA
		mm_free(mm, rrs->data);
		rrs->data = NULL;
	}
	rrs->rr_count--;

	return KNOT_EOK;
}

uint8_t* knot_rrs_create_rr_at_pos(knot_rrs_t *rrs,
                                   size_t pos, uint16_t size,
                                   uint32_t ttl, mm_ctx_t *mm)
{
	if (rrs == NULL || pos > rrs->rr_count) {
		return NULL;
	}
	if (pos == rrs->rr_count) {
		// Normal RDATA addition
		return knot_rrs_create_rr(rrs, size, ttl, mm);
	}

	size_t total_size = knot_rrs_size(rrs);

	// Realloc data.
	void *tmp = mm_realloc(mm, rrs->data,
	                       total_size + size + RR_META_SIZE,
	                       total_size);
	if (tmp) {
		rrs->data = tmp;
	} else {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	knot_rr_t *old_rr = knot_rrs_get_rr(rrs, pos);
	knot_rr_t *last_rr = knot_rrs_get_rr(rrs, rrs->rr_count - 1);
	assert(old_rr);
	assert(last_rr);

	// Make space for new data by moving the array
	memmove(old_rr + size + RR_META_SIZE, old_rr,
	        (last_rr + RR_META_SIZE + knot_rr_size(last_rr)) - old_rr);

	// Set size for new RR
	knot_rr_set_size(old_rr, size);
	knot_rr_set_ttl(old_rr, ttl);

	rrs->rr_count++;
	assert(knot_rr_size(old_rr) > 0);
	return knot_rr_get_rdata(old_rr);
}

uint8_t* knot_rrs_create_rr(knot_rrs_t *rrs, const uint16_t size,
                            const uint32_t ttl, mm_ctx_t *mm)
{
	if (rrs == NULL) {
		return NULL;
	}

	size_t total_size = knot_rrs_size(rrs);
	/* Realloc RRs. */
	void *tmp = mm_realloc(mm, rrs->data, total_size + size + RR_META_SIZE,
	                       total_size);
	if (tmp) {
		rrs->data = tmp;
	} else {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	rrs->rr_count++;
	knot_rr_t *rr = knot_rrs_get_rr(rrs, rrs->rr_count - 1);
	assert(rr);

	knot_rr_set_size(rr, size);
	knot_rr_set_ttl(rr, ttl);

	return knot_rr_get_rdata(rr);
}

void knot_rrs_init(knot_rrs_t *rrs)
{
	if (rrs) {
		rrs->rr_count = 0;
		rrs->data = NULL;
	}
}

void knot_rrs_free(knot_rrs_t *rrs, mm_ctx_t *mm)
{
	if (rrs) {
		mm_free(mm, rrs->data);
		mm_free(mm, rrs);
	}
}

void knot_rrs_clear(knot_rrs_t *rrs, mm_ctx_t *mm)
{
	if (rrs) {
		mm_free(mm, rrs->data);
		rrs->rr_count = 0;
	}
}



