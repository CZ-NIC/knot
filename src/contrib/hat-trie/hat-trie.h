/*
 * This file is part of hat-trie
 *
 * Copyright (c) 2011 by Daniel C. Jones <dcjones@cs.washington.edu>
 *
 * This is an ANSI C99 implementation of the HAT-trie data structure of Askitis
 * and Sinha, an extremely efficient (space and time) modern variant of tries.
 * The HAT-trie is in essence a hybrid data structure, combining tries and hash
 * tables in a clever way to try to get the best of both worlds.
 *
 * The version implemented here maps arrays of bytes to words (i.e., unsigned
 * longs), which can be used to store counts, pointers, etc, or not used at all if
 * you simply want to maintain a set of unique strings.
 *
 * For details see
 *  1. Askitis, N., & Sinha, R. (2007). HAT-trie: a cache-conscious trie-based data
 *     structure for strings. Proceedings of the thirtieth Australasian conference on
 *     Computer science-Volume 62 (pp. 97–105). Australian Computer Society, Inc.
 *  2. Askitis, N., & Zobel, J. (2005). Cache-conscious collision resolution in
 *     string hash tables. String Processing and Information Retrieval (pp.
 *     91–102). Springer.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdbool.h>

#include "contrib/hhash.h"

struct knot_mm;

/* Hat-trie defines. */
#define TRIE_ZEROBUCKETS  0    /* Do not use hash buckets (pure trie). */
#define TRIE_BUCKET_SIZE  253  /* 253, 509, 765 for n*4K pages per 1 hhash. */
#define TRIE_BUCKET_INCR  256  /* Size increase. */
#define TRIE_BUCKET_MAX   4    /* Maximum N table increments. */
#define TRIE_MAXCHAR      0xff /* Use 7-bit ASCII alphabet. */
#define TRIE_EOK          KNOT_EOK

typedef struct hattrie_t_ hattrie_t;

hattrie_t* hattrie_create (void);              //< Create an empty hat-trie.
void       hattrie_free   (hattrie_t*);        //< Free all memory used by a trie.
void       hattrie_clear  (hattrie_t*);        //< Remove all entries.
size_t     hattrie_weight (const hattrie_t*);  //< Number of entries

/** Create new trie with custom bucket size and memory management.
 */
hattrie_t* hattrie_create_n (unsigned, const struct knot_mm *);

/** Duplicate an existing trie.
 */
hattrie_t* hattrie_dup (const hattrie_t*, value_t (*nval)(value_t));

/** Build order index on all ahtable nodes in trie.
 */
void hattrie_build_index (hattrie_t*);

int hattrie_apply_rev (hattrie_t*, int (*f)(value_t*,void*), void* d);
int hattrie_apply_rev_ahtable(hattrie_t* T, int (*f)(void*,void*), void* d);

/** Find the given key in the trie, inserting it if it does not exist, and
 * returning a pointer to its key.
 *
 * This pointer is not guaranteed to be valid after additional calls to
 * hattrie_get, hattrie_del, hattrie_clear, or other functions that modifies the
 * trie.
 */
value_t* hattrie_get (hattrie_t*, const char* key, size_t len);

/** Find a given key in the table, returning a NULL pointer if it does not
 * exist. */
value_t* hattrie_tryget (hattrie_t*, const char* key, size_t len);

/** Find a given key in the table, returning a NULL pointer if it does not
 * exist. Also set prev to point to previous node. */
int hattrie_find_leq (hattrie_t*, const char* key, size_t len, value_t** dst);
/** Find a next value for given key, returning NULL if it does not exist. */
int hattrie_find_next (hattrie_t* T, const char* key, size_t len, value_t **dst);

/** Delete a given key from trie. Returns 0 if successful or -1 if not found.
 */
int hattrie_del(hattrie_t* T, const char* key, size_t len);

typedef struct hattrie_iter_t_ hattrie_iter_t;

hattrie_iter_t* hattrie_iter_begin     (const hattrie_t*, bool sorted);
void            hattrie_iter_next      (hattrie_iter_t*);
bool            hattrie_iter_finished  (hattrie_iter_t*);
void            hattrie_iter_free      (hattrie_iter_t*);
const char*     hattrie_iter_key       (hattrie_iter_t*, size_t* len);
value_t*        hattrie_iter_val       (hattrie_iter_t*);

#ifdef __cplusplus
}
#endif
