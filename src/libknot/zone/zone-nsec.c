/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "common/base32hex.c"
#include "common/descriptor.h"
#include "nsec3.h"
#include "util/utils.h"
#include "zone-contents.h"
#include "zone-nsec.h"

/* - RR types bitmap -------------------------------------------------------- */

#define BITMAP_WINDOW_SIZE 256
#define BITMAP_WINDOW_BYTES (BITMAP_WINDOW_SIZE/CHAR_BIT)
#define BITMAP_WINDOW_COUNT 256

#define NSEC3_HASH_LENGTH 20
#define NSEC3_ENCODED_HASH_LENGTH 32

typedef struct {
	uint8_t used;
	uint8_t data[BITMAP_WINDOW_BYTES];
} bitmap_window_t;

typedef struct {
	int used;
	bitmap_window_t windows[BITMAP_WINDOW_COUNT];
} bitmap_t;

static void bitmap_add_type(bitmap_t *bitmap, uint16_t type)
{
	int win = type / BITMAP_WINDOW_SIZE;
	int bit = type % BITMAP_WINDOW_SIZE;

	if (bitmap->used <= win)
		bitmap->used = win + 1;

	int win_byte = bit / CHAR_BIT;
	int win_bit  = bit % CHAR_BIT;

	bitmap_window_t *window = &bitmap->windows[win];
	window->data[win_byte] |= 0x80 >> win_bit;
	if (window->used <= win_byte)
		window->used = win_byte + 1;
}

static size_t bitmap_size(const bitmap_t *bitmap)
{
	size_t result = 0;

	for (int i = 0; i < bitmap->used; i++) {
		int used = bitmap->windows[i].used;
		if (used == 0)
			continue;

		result += 2 + used; // windows ID, window size, bitmap
	}

	return result;
}

static void bitmap_write(const bitmap_t *bitmap, uint8_t *output)
{
	uint8_t *write_ptr = output;
	for (int win = 0; win < bitmap->used; win++) {
		int used = bitmap->windows[win].used;
		if (used == 0)
			continue;

		*write_ptr = (uint8_t)win;
		write_ptr += 1;

		*write_ptr = (uint8_t)used;
		write_ptr += 1;

		memcpy(write_ptr, bitmap->windows[win].data, used);
		write_ptr += used;
	}
}

/* - NSEC3 names conversion ------------------------------------------------- */

static knot_dname_t *nsec3_hash_to_dname(const uint8_t *hash, size_t hash_size,
					 const char *apex, size_t apex_size)
{
	char name[KNOT_DNAME_MAX_LENGTH];
	size_t endp;

	endp = base32hex_encode(hash, hash_size, (uint8_t *)name, sizeof(name));
	assert(endp > 0);

	name[endp] = '.';
	endp += 1;

	memcpy(name + endp, apex, apex_size);
	endp += apex_size;

	knot_dname_t *dname = knot_dname_new_from_str(name, endp, NULL);
	knot_dname_to_lower(dname);

	return dname;
}

static knot_dname_t *name_to_hashed_name(const knot_dname_t *name,
                                         const knot_nsec3_params_t *params,
                                         const char *apex, size_t apex_size)
{
	uint8_t *hash = NULL;
	size_t hash_size = 0;

	if (knot_nsec3_sha1(params, name->name, name->size, &hash, &hash_size) != KNOT_EOK)
		return NULL;

	knot_dname_t *result = nsec3_hash_to_dname(hash, hash_size, apex, apex_size);
	free(hash);

	return result;
}

/* - NSEC chain iteration --------------------------------------------------- */

typedef int (*chain_iterate_cb)(knot_node_t *, knot_node_t *, void *);

/*!
 * \brief Iterate over
 */
static int chain_iterate(knot_zone_tree_t *nodes, chain_iterate_cb callback,
                         void *data)
{
	bool sorted = true;
	hattrie_iter_t *it = hattrie_iter_begin(nodes, sorted);

	if (!it)
		return KNOT_ENOMEM;

	if (hattrie_iter_finished(it))
		return KNOT_EINVAL;

	knot_node_t *first = (knot_node_t *)*hattrie_iter_val(it);
	knot_node_t *previous = first;
	knot_node_t *current = first;
	hattrie_iter_next(it);

	while (!hattrie_iter_finished(it)) {
		current = (knot_node_t *)*hattrie_iter_val(it);

		int result = callback(previous, current, data);
		if (result != KNOT_EOK) {
			hattrie_iter_free(it);
			return result;
		}

		previous = current;
		hattrie_iter_next(it);
	}

	hattrie_iter_free(it);

	return callback(current, first, data);
}

/* - NSEC3 nodes construction ----------------------------------------------- */

static knot_rrset_t *create_nsec3_rrset(knot_dname_t *owner,
                                        const knot_nsec3_params_t *params,
                                        const bitmap_t *bitmap,
                                        uint32_t ttl)
{
	knot_rrset_t *rrset;
	rrset = knot_rrset_new(owner, KNOT_RRTYPE_NSEC3, KNOT_CLASS_IN, ttl);
	if (!rrset)
		return NULL;

	size_t rdata_size = 6 + params->salt_length + NSEC3_HASH_LENGTH
			    + bitmap_size(bitmap);

	uint8_t *rdata = knot_rrset_create_rdata(rrset, rdata_size);
	if (!rdata) {
		knot_rrset_free(&rrset);
		return NULL;
	}

	*rdata = params->algorithm;                       // hash algorithm
	rdata += 1;
	*rdata = 0;                                       // flags
	rdata += 1;
	knot_wire_write_u16(rdata, params->iterations);   // iterations
	rdata += 2;
	*rdata = params->salt_length;                     // salt length
	rdata += 1;
	memcpy(rdata, params->salt, params->salt_length); // salt
	rdata += params->salt_length;
	*rdata = NSEC3_HASH_LENGTH;                       // hash length
	rdata += 1;
	memset(rdata, '\0', NSEC3_HASH_LENGTH);           // hash
	rdata += NSEC3_HASH_LENGTH;
	bitmap_write(bitmap, rdata);                      // bit map

	return rrset;
}

static knot_node_t *create_nsec3_node(knot_dname_t *owner,
                                      const bitmap_t *rr_types,
                                      const knot_zone_t *zone,
                                      uint32_t ttl)
{
	uint8_t flags = 0;
	knot_node_t *apex_node = zone->contents->apex;
	knot_node_t *new_node = knot_node_new(owner, apex_node, flags);
	if (!new_node)
		return NULL;

	const knot_nsec3_params_t *nsec3_params = &zone->contents->nsec3_params;
	knot_rrset_t *nsec3_rrset;
	nsec3_rrset = create_nsec3_rrset(owner, nsec3_params, rr_types, ttl);
	if (!nsec3_rrset) {
		knot_node_free(&new_node);
		return NULL;
	}

	if (knot_node_add_rrset_no_merge(new_node, nsec3_rrset) != KNOT_EOK) {
		knot_rrset_free(&nsec3_rrset);
		knot_node_free(&new_node);
		return NULL;
	}

	return new_node;
}

static int connect_nsec3_nodes(knot_node_t *current, knot_node_t *next, void *data)
{
	UNUSED(data);

	// TODO: a bit fragile, needs refactoring...

	assert(current);
	assert(next);

	uint8_t *encoded_hash = (uint8_t *)knot_dname_to_str(next->owner);
	assert(encoded_hash);

	uint8_t hash[NSEC3_HASH_LENGTH];

	int r = base32hex_decode(encoded_hash, NSEC3_ENCODED_HASH_LENGTH,
				hash, NSEC3_HASH_LENGTH);
	assert(r == NSEC3_HASH_LENGTH);

	uint8_t *rdata_hash = current->rrset_tree[0]->rdata;

	rdata_hash += 4;
	rdata_hash += 1 + *rdata_hash;
	assert(*rdata_hash == NSEC3_HASH_LENGTH);
	rdata_hash += 1;
	memcpy(rdata_hash, hash, NSEC3_HASH_LENGTH);

	return KNOT_EOK;
}

static int create_nsec3_chain(knot_zone_t *zone, uint32_t ttl)
{
	assert(zone);
	assert(zone->contents);
	assert(zone->contents->nodes);

	knot_zone_tree_t *nsec3_nodes = knot_zone_tree_create();
	if (!nsec3_nodes)
		return KNOT_ENOMEM;

	char *apex = knot_dname_to_str(zone->name);
	assert(apex);
	size_t apex_size = strlen(apex);

	const knot_nsec3_params_t *nsec3_params = &zone->contents->nsec3_params;

	int sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(zone->contents->nodes, sorted);
	while (!hattrie_iter_finished(it)) {
		knot_node_t *node = (knot_node_t *)*hattrie_iter_val(it);

		knot_dname_t *nsec3_owner;
		nsec3_owner = name_to_hashed_name(node->owner, nsec3_params,
						  apex, apex_size);
		assert(nsec3_owner);

		// TODO: move outside?
		bitmap_t bitmap = { 0 };
		for (int i = 0; i < node->rrset_count; i++) {
			bitmap_add_type(&bitmap, node->rrset_tree[i]->type);
		}

		knot_node_t *new_node = create_nsec3_node(nsec3_owner,
							  &bitmap, zone, ttl);

		int r = knot_zone_tree_insert(nsec3_nodes, new_node);
		assert(r == KNOT_EOK);

		hattrie_iter_next(it);
	}

	free(apex);

	int result = chain_iterate(nsec3_nodes, connect_nsec3_nodes, NULL);
	if (result != KNOT_EOK)
		return result;

	// TODO: atomic
	knot_zone_tree_deep_free(&zone->contents->nsec3_nodes);
	zone->contents->nsec3_nodes = nsec3_nodes;

	int r = knot_zone_contents_adjust(zone->contents, NULL, NULL, 0);
	assert(r == KNOT_EOK);


	return KNOT_EOK;
}


/* - NSEC nodes construction ------------------------------------------------ */

static knot_rrset_t *create_nsec_rrset(knot_dname_t *owner, knot_dname_t *next,
				       const bitmap_t *bitmap, uint32_t ttl)
{
	knot_rrset_t *rrset;
	rrset = knot_rrset_new(owner, KNOT_RRTYPE_NSEC, KNOT_CLASS_IN, ttl);
	if (!rrset)
		return NULL;

	size_t rdata_size = sizeof(knot_dname_t *) + bitmap_size(bitmap);
	uint8_t *rdata = knot_rrset_create_rdata(rrset, rdata_size);
	if (!rdata) {
		knot_rrset_free(&rrset);
		return NULL;
	}

	knot_dname_retain(next);
	memcpy(rdata, &next, sizeof(knot_dname_t *));
	bitmap_write(bitmap, rdata + sizeof(knot_dname_t *));

	return rrset;
}

static int add_nsec_connection(knot_node_t *node, knot_node_t *next, void *data)
{
	uint32_t ttl = *(uint32_t *)data;

	bitmap_t bitmap = { 0 };
	bitmap_add_type(&bitmap, KNOT_RRTYPE_NSEC);
	for (int i = 0; i < node->rrset_count; i++) {
		bitmap_add_type(&bitmap, node->rrset_tree[i]->type);
	}

	knot_rrset_t *nsec = create_nsec_rrset(node->owner, next->owner, &bitmap, ttl);
	if (!nsec)
		return KNOT_ENOMEM;

	return knot_node_add_rrset_no_merge(node, nsec);
}

static int create_nsec_chain(knot_zone_t *zone, uint32_t ttl)
{
	assert(zone);
	assert(zone->contents);
	assert(zone->contents->nodes);

	return chain_iterate(zone->contents->nodes, add_nsec_connection, &ttl);
}

/* - temporary helpers ------------------------------------------------------ */

static bool is_nsec3_enabled(const knot_zone_t *zone)
{
	return zone->contents->nsec3_params.salt_length > 0;
}

static bool get_zone_soa_min_ttl(const knot_zone_t *zone, uint32_t *ttl)
{
	assert(zone);
	assert(zone->contents);
	assert(zone->contents->apex);
	assert(ttl);

	knot_rrset_t *soa = knot_node_get_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
	if (!soa)
		return false;

	*ttl = knot_rrset_rdata_soa_minimum(soa);
	return true;
}

/* - future public API------------------------------------------------------- */

int knot_zone_create_nsec_chain(knot_zone_t *zone)
{
	if (!zone)
		return KNOT_EINVAL;

	uint32_t nsec_ttl = 0;
	if (!get_zone_soa_min_ttl(zone, &nsec_ttl))
		return KNOT_ERROR;

	if (is_nsec3_enabled(zone))
		return create_nsec3_chain(zone, nsec_ttl);
	else
		return create_nsec_chain(zone, nsec_ttl);
}

#if 0

static bool is_dnssec_type(uint16_t type)
{
	switch (type) {
	case KNOT_RRTYPE_RRSIG:
	case KNOT_RRTYPE_NSEC:
	case KNOT_RRTYPE_NSEC3:
		return true;
	default:
		return false;
	}
}

static bool only_dnssec_node(const knot_node_t *node)
{
	assert(node);

	for (int i = 0; i < node->rrset_count; i++) {
		uint16_t type = node->rrset_tree[i]->type;
		if (!is_dnssec_type(type))
			return true;
	}

	return false;
}

static knot_node_t *copy_nodnssec_node(const knot_node_t *from)
{
	knot_node_t *parent = NULL;
	uint8_t flags = 0;
	knot_node_t *copy = knot_node_new(from->owner, parent, flags);

	if (!copy)
		return NULL;

	for (int i = 0; i < from->rrset_count; i++) {
		if (is_dnssec_type(from->rrset_tree[i]->type))
			continue;

		knot_rrset_t *rrset = NULL;
		int result;

		result = knot_rrset_shallow_copy(from->rrset_tree[i], &rrset);
		if (result != KNOT_EOK) {
			knot_node_free_rrsets(copy, 1);
			knot_node_free(&copy);
			return NULL;
		}

		result = knot_node_add_rrset_no_merge(copy, rrset);
		if (result != KNOT_EOK) {
			knot_node_free_rrsets(copy, 1);
			knot_node_free(&copy);
			return NULL;
		}
	}

	return copy;
}

/*!
 * \brief Copies the zone content while skipping all NSEC(3) and RRSIG records.
 */
static knot_zone_contents_t *zone_strip_dnssec(const knot_zone_contents_t *current)
{
	assert(current);
	knot_zone_contents_t *stripped;

	stripped = knot_zone_contents_new(current->apex, current->zone);
	if (!stripped)
		return NULL;

	bool sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(current->nodes, sorted);
	while (!hattrie_iter_finished(it)) {
		knot_node_t *node = (knot_node_t *)*hattrie_iter_val(it);

		if (only_dnssec_node(node)) {
			hattrie_iter_next(it);
			continue;
		}

		knot_node_t *copy = copy_nodnssec_node(node);
		if (!copy) {
			knot_zone_contents_free(&stripped);
			return NULL;
		}

		if (knot_zone_contents_add_node(stripped, node, 1, 0) != KNOT_EOK) {
			knot_zone_contents_free(&stripped);
			return NULL;
		}

		hattrie_iter_next(it);
	}

	return stripped;
}

#endif
