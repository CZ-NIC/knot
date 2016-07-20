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

#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "contrib/hhash.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/murmurhash3/murmurhash3.h"
#include "libknot/errcode.h"

/* UCW array sorting defines. */
static int universal_cmp(uint32_t k1, uint32_t k2, hhash_t *tbl);
#define ASORT_PREFIX(X) hhash_##X
#define ASORT_KEY_TYPE uint32_t
#define ASORT_LT(x, y) (universal_cmp((x), (y), tbl) < 0)
#define ASORT_EXTRA_ARGS , hhash_t *tbl
#include "contrib/ucw/array-sort.h"
#include "contrib/ucw/binsearch.h"

/* Hopscotch internal defines. */
#define HOP_NEXT(x) __builtin_ctz((x))
#define HOP_LEN (sizeof(hhbitvec_t) * 8)
#define HOP_BIT(d) ((hhbitvec_t)1 << (d))
#define HHVAL_LEN sizeof(value_t)
#define HHKEY_LEN (HHVAL_LEN + sizeof(uint16_t))
#define HHSCAN_THRESHOLD (HOP_LEN / 2)

/* Data is composed of {value, keylen, key}.
 * Value is fixed size (pointer), so is keylen.
 * Key is variable-sized string. */
#define KEY_VAL(p) (p)
#define KEY_LEN(p) ((char*)(p) + HHVAL_LEN)
#define KEY_STR(p) ((char*)(p) + HHKEY_LEN)

/*! \brief Helper function to read key length. */
static inline uint16_t key_readlen(const void *k)
{
	uint16_t ret;
	memcpy(&ret, KEY_LEN(k), sizeof(ret));
	return ret;
}

/*! \brief Reduce distance to first free element. */
static int reduce_dist(hhash_t *t, int idx, int *empty)
{
	unsigned dist = HOP_LEN - 1;
	while (dist > 0) {
		/* Each index can address at most HOP_LEN next items in the hop vector.
		 * Idea here is to shuffle items in the bucket bitvector, so the
		 * free space moves closer to the left.
		 * The function should be repeated until we move the free bucket
		 * in the vicinity of the target index.
		 */
		unsigned cur = (t->size + *empty - dist) % t->size; /* bucket to be vacated */
		unsigned off = HOP_NEXT(t->item[cur].hop);     /* offset of first valid bucket */
		if (t->item[cur].hop != 0 && off < dist) {     /* only offsets in <s, f> are interesting */
			unsigned hit = (cur + off) % t->size;  /* this item will be displaced to [f] */
			t->item[*empty].d = t->item[hit].d;    /* displace data */
			t->item[hit].d = NULL;
			t->item[cur].hop &= ~HOP_BIT(off); /* displace bitvector index */
			t->item[cur].hop |=  HOP_BIT(dist);
			*empty = hit;
			return idx - (dist - off);               /* new distance */
		}
		--dist;
	}

	/* Cannot displace, this happens with p=1/fact(HOP_LEN). */
	*empty = 0;
	return KNOT_ESPACE;
}

/*! \brief Item comparator. */
static int key_cmp(const char *k1, uint16_t k1_len, const char *k2, uint16_t k2_len)
{
	int ret = memcmp(k1, k2, MIN(k1_len, k2_len));
	if (ret != 0) {
		return ret;
	}

	/* Key string is equal, compare lengths. */
	if (k1_len == k2_len) {
		return 0;
	} else if (k1_len < k2_len) {
		return -1;
	}

	return 1;
}

/*! \brief Universal comparator. */
static int universal_cmp(uint32_t i1, uint32_t i2, hhash_t *tbl)
{
	/* Get item data from indirect positions. */
	void *k1 = tbl->item[i1].d;
	void *k2 = tbl->item[i2].d;

	/* Read key lengths. */
	return key_cmp(KEY_STR(k1), key_readlen(k1), KEY_STR(k2), key_readlen(k2));
}

/*! \brief Check for equality. */
static bool hhelem_isequal(hhelem_t *elm, const char *key, uint16_t len)
{
	uint16_t klen;
	memcpy(&klen, KEY_LEN(elm->d), sizeof(klen));
	if (klen != len) {
		return false;
	}

	return memcmp(KEY_STR(elm->d), key, len) == 0;
}

/*! \brief Binary search index for key. */
#define CMP_I2K(t, k) (t)->item[t->index[k]].d
#define CMP_LE(t, i, x, ...) (key_cmp(KEY_STR(CMP_I2K(t, i)), key_readlen(CMP_I2K(t, i)), x, __VA_ARGS__) <= 0)

/* Free and NULL the index, if any exists. */
static inline void hhash_invalidate_index(hhash_t* tbl) {
	if (!tbl->index)
		return;
	mm_free(tbl->mm, tbl->index);
	tbl->index = NULL;
}

/*! \brief Free a table element. Find matching index + offset. */
static int hhelem_free(hhash_t* tbl, uint32_t id, unsigned dist, value_t *val)
{
	/* Remove from the source bitvector. */
	hhelem_t *elm = &tbl->item[id];
	elm->hop &= ~HOP_BIT(dist);

	/* Copy value for future reference. */
	elm = &tbl->item[(id + dist) % tbl->size];
	if (val != NULL) {
		memcpy(val, KEY_VAL(elm->d), sizeof(value_t));
	}

	/* Erase data from target element. */
	mm_free(tbl->mm, elm->d);
	elm->d = NULL;

	hhash_invalidate_index(tbl);

	/* Update table weight. */
	--tbl->weight;
	return KNOT_EOK;
}

/*! \brief Find first free element from id. */
static int find_free(hhash_t *t, unsigned idx)
{
	/* Distance is measured as a shortest path forward.
	 * Table is treated as circular, so we need to scan
	 * first <elm..end> and <start..elm - 1> */
	hhelem_t *np = t->item + t->size;
	hhelem_t *elm = NULL;

	/* From <elm, end> */
	for (elm = t->item + idx; elm != np; ++elm) {
		if (elm->d == NULL) {
			return elm - (t->item + idx);
		}
	}
	/* From <start, elm) */
	np = t->item + idx;
	for (elm = t->item; elm != np; ++elm) {
		if (elm->d == NULL) {
			return (elm - t->item) + (t->size - idx);
		}
	}

	return KNOT_ESPACE; /* Table is full. */
}

/*! \brief Find match in the bucket vicinity <0, HOP_LEN> */
static unsigned find_match(hhash_t *tbl, uint32_t idx, const char* key, uint16_t len)
{
	unsigned empty = 0;
	unsigned dist = 0;
	hhbitvec_t match = tbl->item[idx].hop;
	while (match != 0) {
		dist = HOP_NEXT(match);
		empty = (idx + dist) % tbl->size;
		if (hhelem_isequal(tbl->item + empty, key, len)) {
			return dist;
		} else {
			match &= ~HOP_BIT(dist); /* clear potential match */
		}
	}

	return HOP_LEN + 1;
}

/*! \brief Free allocated buckets and order index. */
static void hhash_free_buckets(hhash_t *tbl)
{
	assert(tbl != NULL);
	/* Free buckets. */
	for (unsigned i = 0; i < tbl->size; ++i) {
		mm_free(tbl->mm, tbl->item[i].d);
	}
	
	hhash_invalidate_index(tbl);
}

hhash_t *hhash_create(uint32_t size)
{

	knot_mm_t mm;
	mm_ctx_init(&mm);
	return hhash_create_mm(size, &mm);
}

hhash_t *hhash_create_mm(uint32_t size, const knot_mm_t *mm)
{
	if (size == 0) {
		return NULL;
	}

	const size_t total_len = sizeof(hhash_t) + size * sizeof(hhelem_t);
	hhash_t *tbl = mm_alloc((knot_mm_t *)mm, total_len);
	if (tbl == NULL) {
		return NULL;
	}
	memset(tbl, 0, total_len);

	knot_mm_t *mm_copy = mm_alloc((knot_mm_t *)mm, sizeof(knot_mm_t));
	if (mm_copy == NULL) {
		mm_free((knot_mm_t *)mm, tbl);
		return NULL;
	}
	memcpy(mm_copy, mm, sizeof(knot_mm_t));

	tbl->size = size;
	tbl->mm = mm_copy;

	return tbl;
}

void hhash_clear(hhash_t *tbl)
{
	if (tbl == NULL) {
		return;
	}

	/* Clear buckets. */
	hhash_free_buckets(tbl);
	memset(tbl->item, 0, tbl->size * sizeof(hhelem_t));

	/* Reset weight. */
	tbl->weight = 0;
}

void hhash_free(hhash_t *tbl)
{
	if (tbl == NULL) {
		return;
	}

	/* Clear all keys and index. */
	hhash_free_buckets(tbl);

	/* Free table. */
	knot_mm_free_t mm_free = tbl->mm->free;
	if (mm_free) {
		mm_free(tbl->mm);
		mm_free(tbl);
	}
}

value_t *hhash_find(hhash_t* tbl, const char* key, uint16_t len)
{
	/* It is faster to scan index using binary search for low fill,
	 * as it doesn't present constant hashing penalty. */
	if (tbl->index && tbl->weight < HHSCAN_THRESHOLD) {
		int k = BIN_SEARCH_FIRST_GE_CMP(tbl, tbl->weight, CMP_LE, key, len) - 1;
		if (k > -1) {
			hhelem_t *found = tbl->item + tbl->index[k];
			if (hhelem_isequal(found, key, len)) {
				return (value_t *)KEY_VAL(found->d);
			}
		}
		return NULL; /* Not found. */
	}

	return hhash_map(tbl, key, len, 0); /* Don't insert. */
}

value_t *hhash_map(hhash_t* tbl, const char* key, uint16_t len, uint16_t mode)
{
	if (tbl == NULL) {
		return NULL;
	}

	/* Find an exact match in <id, id + HOP_LEN). */
	uint32_t id = hash(key, len) % tbl->size;
	int dist = find_match(tbl, id, key, len);
	if (dist <= HOP_LEN) {
		/* Found exact match, return value. */
		hhelem_t *match = &tbl->item[(id + dist) % tbl->size];
		return (value_t *)KEY_VAL(match->d);
	}

	/* We didn't find an exact match, continue only if inserting. */
	if (!(mode & HHASH_INSERT)) {
		return NULL;
	} else if (tbl->weight >= tbl->size) { /* Or full table. */
		return NULL;
	}

	hhash_invalidate_index(tbl);

	/* Reduce distance to fit <id, id + HOP_LEN) */
	dist = find_free(tbl, id);
	if (dist < 0) { /* Did not find any fit. */
		return NULL;
	}
	int empty = (id + dist) % tbl->size;
	while (dist >= HOP_LEN) {
		dist = reduce_dist(tbl, dist, &empty);
		/* Couldn't reduce the distance, no fit available. */
		if (dist < 0) {
			return NULL;
		}
	}

	/* Insert to given position. */
	char *new_key = mm_alloc(tbl->mm, HHKEY_LEN + len);
	if (new_key != NULL) {
		memset(KEY_VAL(new_key), 0,    sizeof(value_t));
		memcpy(KEY_LEN(new_key), &len, sizeof(uint16_t));
		memcpy(KEY_STR(new_key), key,  len);
	} else {
		return NULL;
	}

	/* found free elm 'k' which is in <id, id + HOP_LEN) */
	assert(tbl->item[empty].d == NULL);
	tbl->item[id].hop |= HOP_BIT(dist);
	tbl->item[empty].d = new_key;

	++tbl->weight;

	return (value_t *)KEY_VAL(new_key);
}

int hhash_insert(hhash_t* tbl, const char* key, uint16_t len, value_t val)
{
	value_t *rval = hhash_map(tbl, key, len, HHASH_INSERT);
	if (rval) {
		*rval = val;
		return KNOT_EOK;
	}
	return KNOT_ESPACE;
}

int hhash_del(hhash_t* tbl, const char* key, uint16_t len)
{
	if (tbl == NULL) {
		return KNOT_EINVAL;
	}

	uint32_t idx = hash(key, len) % tbl->size;
	unsigned dist = find_match(tbl, idx, key, len);
	if (dist > HOP_LEN) {
		return KNOT_ENOENT;
	}

	return hhelem_free(tbl, idx, dist, NULL);
}

value_t *hhash_indexval(hhash_t* tbl, unsigned i)
{
	if (tbl != NULL && tbl->index != NULL) {
		return (value_t *)KEY_VAL(tbl->item[ tbl->index[i] ].d);
	}

	return 0;
}

void hhash_build_index(hhash_t* tbl)
{
	if (tbl == NULL || tbl->index) { /* no need to rebuild if exists */
		return;
	}

	/* Rebuild index. */
	uint32_t total = tbl->weight;
	if (total == 0) {
		return;
	}
	tbl->index = mm_alloc(tbl->mm, total * sizeof(uint32_t));

	uint32_t i = 0, indexed = 0;
	while (indexed < total) {
		/* Non-empty item, store index. */
		if (tbl->item[i].d != NULL) {
			tbl->index[indexed] = i;
			++indexed;
		}
		++i; /* Next item. */
	}

	hhash_sort(tbl->index, indexed, tbl);
}

int hhash_find_leq(hhash_t* tbl, const char* key, uint16_t len, value_t** dst)
{
	*dst = NULL;
	if (tbl->weight == 0) {
		return 1;
	}

	int k = BIN_SEARCH_FIRST_GE_CMP(tbl, tbl->weight, CMP_LE, key, len) - 1;
	if (k > -1) {
		hhelem_t *found = tbl->item + tbl->index[k];
		*dst = (value_t *)KEY_VAL(found->d);
		/* Compare if found equal or predecessor. */
		if (hhelem_isequal(found, key, len)) {
			return 0; /* Exact match. */
		} else {
			return -1; /* Predecessor. */
		}
	}

	/* No predecessor. */
	return 1;
}

int hhash_find_next(hhash_t* tbl, const char* key, uint16_t len, value_t** dst)
{
	*dst = NULL;
	if (tbl->weight == 0) {
		return 1;
	}

	int k = BIN_SEARCH_FIRST_GE_CMP(tbl, tbl->weight, CMP_LE, key, len);
	/* Found prev or equal, we want next */
	if (k + 1 < tbl->weight) {
		hhelem_t *found = tbl->item + tbl->index[k + 1];
		*dst = (value_t *)KEY_VAL(found->d);
		return 0;
	} else {
		return 1;
	}
}

/* Private iterator flags. */
enum {
	HH_SORTED  = 0x01 /* sorted iteration */
};

static void* hhash_sorted_iter_item(hhash_iter_t *i)
{
	hhash_t *tbl = i->tbl;
	uint32_t pos = tbl->index[i->i];
	return tbl->item[pos].d;
}

static inline bool hhash_sorted_iter_finished(hhash_iter_t* i)
{
	return i->i >= i->tbl->weight;
}

static inline void hhash_sorted_iter_next(hhash_iter_t* i)
{
	if (hhash_iter_finished(i)) {
		return;
	}
	++i->i;
}

static const char* hhash_sorted_iter_key(hhash_iter_t* i, uint16_t* len)
{
	if (hhash_iter_finished(i)) {
		return NULL;
	}

	void *key = hhash_sorted_iter_item(i);
	*len = key_readlen(key);
	return KEY_STR(key);
}

static value_t *hhash_sorted_iter_val(hhash_iter_t* i)
{
	if (hhash_iter_finished(i)) {
		return NULL;
	}

	return (value_t *)KEY_VAL(hhash_sorted_iter_item(i));
}

static uint32_t hhash_unsorted_seek_valid(hhash_t *tbl, uint32_t idx)
{
	while (idx < tbl->size) {
		if (tbl->item[idx].d != NULL) {
			break;
		}
		++idx;
	}

	return idx;
}

static void hhash_unsorted_iter_begin(hhash_iter_t *i)
{
	i->i = hhash_unsorted_seek_valid(i->tbl, 0);
}

static inline bool hhash_unsorted_iter_finished(hhash_iter_t* i)
{
	return i->i >= i->tbl->size;
}

static void hhash_unsorted_iter_next(hhash_iter_t* i)
{
	if (hhash_iter_finished(i)) {
		return;
	}

	i->i = hhash_unsorted_seek_valid(i->tbl, i->i + 1);
}

static const char* hhash_unsorted_iter_key(hhash_iter_t* i, uint16_t* len)
{
	if (hhash_iter_finished(i)) {
		return NULL;
	}

	void *key = i->tbl->item[i->i].d;
	*len = key_readlen(key);
	return KEY_STR(key);
}

static value_t *hhash_unsorted_iter_val(hhash_iter_t* i)
{
	if (hhash_iter_finished(i)) {
		return NULL;
	}

	return (value_t *)KEY_VAL(i->tbl->item[i->i].d);
}

void hhash_iter_begin(hhash_t* tbl, hhash_iter_t* i, bool sorted)
{
	memset(i, 0, sizeof(hhash_iter_t));
	i->tbl = tbl;
	if (sorted) {
		i->flags |= HH_SORTED;
		if (!hhash_iter_finished(i)) {
			assert(tbl->index);
		}
	} else {
		hhash_unsorted_iter_begin(i);
	}
}

void hhash_iter_next(hhash_iter_t* i)
{
	if (i->flags & HH_SORTED) hhash_sorted_iter_next(i);
	else                      hhash_unsorted_iter_next(i);
}

bool hhash_iter_finished(hhash_iter_t* i)
{
	if (i->flags & HH_SORTED) return hhash_sorted_iter_finished(i);
	else                      return hhash_unsorted_iter_finished(i);
}

const char* hhash_iter_key(hhash_iter_t* i, uint16_t* len)
{
	if (i->flags & HH_SORTED) return hhash_sorted_iter_key(i, len);
	else                      return hhash_unsorted_iter_key(i, len);
}

value_t *hhash_iter_val(hhash_iter_t* i)
{
	if (i->flags & HH_SORTED) return hhash_sorted_iter_val(i);
	else                      return hhash_unsorted_iter_val(i);
}
