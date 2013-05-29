/*
 * This file is part of hat-trie.
 *
 * Copyright (c) 2011 by Daniel C. Jones <dcjones@cs.washington.edu>
 *
 */

#include <config.h>
#include <assert.h>
#include <string.h>
#include "ahtable.h"
#include "murmurhash3.h"

enum {
    AH_SORTED  = 0x01,/* sorted iteration */
    AH_INDEXED = 0x02 /* reuse index from table */
};

const size_t ahtable_max_load_factor = 10000.0; /* arbitrary large number => don't resize */
static const uint16_t LONG_KEYLEN_MASK = 0x7fff;

/* Allocate by larger chunks to avoid frequent reallocs. */
/* http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2 */
static inline unsigned next_size(unsigned v) {
    --v;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return (++v) << 1; /* x2 */
}

static size_t keylen(slot_t s) {
    if (0x1 & *s) {
        return (size_t) (*((uint16_t*) s) >> 1);
    }
    else {
        return (size_t) (*s >> 1);
    }
}

static value_t* slotval(slot_t s)
{
    size_t k = keylen(s);
    s += k < 128 ? 1 : 2;
    s += k;
    return (value_t*) s;
}

static const char* slotkey(slot_t s, size_t* len)
{
    *len = keylen(s);
    return (const char*) (s + (*len < 128 ? 1 : 2));
}

static int cmpkeystr(const char* a, size_t ka, slot_t b)
{
    size_t kb = keylen(b);
    b += kb < 128 ? 1 : 2;

    int c = memcmp(a, b, ka < kb ? ka : kb);
    return c == 0 ? (int) ka - (int) kb : c;
}

static int cmpkey(const void* a_, const void* b_)
{
    slot_t a = *(slot_t*) a_;
    slot_t b = *(slot_t*) b_;

    size_t ka = keylen(a), kb = keylen(b);

    a += ka < 128 ? 1 : 2;
    b += kb < 128 ? 1 : 2;

    int c = memcmp(a, b, ka < kb ? ka : kb);
    return c == 0 ? (int) ka - (int) kb : c;
}

ahtable_t* ahtable_create()
{
    return ahtable_create_n(AHTABLE_INIT_SIZE);
}


ahtable_t* ahtable_create_n(size_t n)
{
    ahtable_t* T = malloc(sizeof(ahtable_t));
    memset(T, 0, sizeof(ahtable_t));

    T->n = n;
    T->max_m = (size_t) (ahtable_max_load_factor * (double) T->n);
    T->slots = malloc(n * sizeof(slot_t));
    memset(T->slots, 0, n * sizeof(slot_t));

    const size_t sslen = 2 * T->n * sizeof(uint32_t); /* used | reserved */
    T->slot_sizes = malloc(sslen);
    memset(T->slot_sizes, 0, sslen);

    return T;
}


void ahtable_free(ahtable_t* T)
{
    if (T == NULL) return;
    size_t i;
    for (i = 0; i < T->n; ++i) free(T->slots[i]);
    free(T->slots);
    free(T->slot_sizes);
    free(T->index);
    free(T);
}


size_t ahtable_size(const ahtable_t* T)
{
    return T->m;
}


void ahtable_clear(ahtable_t* T)
{
    size_t i;
    for (i = 0; i < T->n; ++i) free(T->slots[i]);
    T->n = AHTABLE_INIT_SIZE;
    T->slots = realloc(T->slots, T->n * sizeof(slot_t));
    memset(T->slots, 0, T->n * sizeof(slot_t));

    const size_t sslen = 2 * T->n * sizeof(uint32_t); /* used | reserved */
    T->slot_sizes = realloc(T->slot_sizes, sslen);
    memset(T->slot_sizes, 0, sslen);

    if (T->index) {
        free(T->index);
        T->index = NULL;
    }
}


static slot_t ins_key(slot_t s, const char* key, size_t len, value_t** val)
{
    // key length
    if (len < 128) {
        s[0] = (unsigned char) (len << 1);
        s += 1;
    }
    else {
        /* The most significant bit is set to indicate that two bytes are
         * being used to store the key length. */
        *((uint16_t*) s) = ((uint16_t) len << 1) | 0x1;
        s += 2;
    }

    // key
    memcpy(s, key, len * sizeof(unsigned char));
    s += len;

    // value
    *val = (value_t*) s;
    **val = 0;
    s += sizeof(value_t);

    return s;
}


static void ahtable_expand(ahtable_t* T)
{
    /* Resizing a table is essentially building a brand new one.
     * One little shortcut we can take on the memory allocation front is to
     * figure out how much memory each slot needs in advance.
     */
    assert(T->n > 0);
    size_t new_n = 2 * T->n;
    size_t slot_scount = 2 * new_n; /* used | reserved */
    uint32_t* slot_sizes = malloc(slot_scount * sizeof(uint32_t));
    memset(slot_sizes, 0, slot_scount * sizeof(uint32_t));

    const char* key;
    size_t len = 0;
    size_t m = 0;
    size_t h;
    ahtable_iter_t i;
    ahtable_iter_begin(T, &i, false);
    while (!ahtable_iter_finished(&i)) {
        key = ahtable_iter_key(&i, &len);
        h = hash(key, len) % new_n;
        slot_sizes[h] +=
            len + sizeof(value_t) + (len >= 128 ? 2 : 1);
        slot_sizes[new_n + h] = slot_sizes[h];

        ++m;
        ahtable_iter_next(&i);
    }
    assert(m == T->m);
    ahtable_iter_free(&i);


    /* allocate slots */
    slot_t* slots = malloc(new_n * sizeof(slot_t));
    size_t j;
    for (j = 0; j < new_n; ++j) {
        if (slot_sizes[j] > 0) {
            slots[j] = malloc(slot_sizes[j]);
        }
        else slots[j] = NULL;
    }

    /* rehash values. A few shortcuts can be taken here as well, as we know
     * there will be no collisions. Instead of the regular insertion routine,
     * we keep track of the ends of every slot and simply insert keys.
     * */
    slot_t* slots_next = malloc(new_n * sizeof(slot_t));
    memcpy(slots_next, slots, new_n * sizeof(slot_t));
    m = 0;
    value_t* u;
    value_t* v;
    ahtable_iter_begin(T, &i, false);
    while (!ahtable_iter_finished(&i)) {

        key = ahtable_iter_key(&i, &len);
        h = hash(key, len) % new_n;

        slots_next[h] = ins_key(slots_next[h], key, len, &u);
        v = ahtable_iter_val(&i);
        *u = *v;

        ++m;
        ahtable_iter_next(&i);
    }
    assert(m == T->m);
    ahtable_iter_free(&i);


    free(slots_next);
    for (j = 0; j < T->n; ++j) free(T->slots[j]);

    free(T->slots);
    T->slots = slots;

    free(T->slot_sizes);
    T->slot_sizes = slot_sizes;

    T->n = new_n;
    T->max_m = (size_t) (ahtable_max_load_factor * (double) T->n);
}

static value_t* insert_key(ahtable_t* T, uint32_t h, const char* key, size_t len)
{
    uint32_t new_size = T->slot_sizes[h];
    new_size += (len >= 128 ? 2 : 1);        // key length
    new_size += len * sizeof(unsigned char); // key
    new_size += sizeof(value_t);             // value

    /* fetch reserved size */
    uint32_t* reserved = &T->slot_sizes[T->n + h];
    if (*reserved < new_size) {
        *reserved = next_size(new_size);
        T->slots[h] = realloc(T->slots[h], *reserved);
    }
    ++T->m;

    value_t *val = NULL;
    ins_key(T->slots[h] + T->slot_sizes[h], key, len, &val);
    T->slot_sizes[h] = new_size;

    return val;
}


static value_t* find_val(ahtable_t* T, const char* key, size_t len, uint32_t i)
{
    size_t k = 0;

    /* search the array for our key */
    slot_t s = T->slots[i];
    slot_t np = T->slots[i] + T->slot_sizes[i];
    while (s < np) {
        /* get the key length */
        k = keylen(s);
        s += k < 128 ? 1 : 2;

        /* skip keys that are longer than ours */
        if (k != len) {
            s += k + sizeof(value_t);
            continue;
        }

        /* key found. */
        if (memcmp(s, key, len) == 0) {
            return (value_t*) (s + len);
        }
        /* key not found. */
        else {
            s += k + sizeof(value_t);
            continue;
        }
    }

    return NULL;
}


value_t* ahtable_get(ahtable_t* T, const char* key, size_t len)
{
    /* if we are at capacity, preemptively resize */
    if (T->m >= T->max_m) {
        ahtable_expand(T);
    }

    /* attempt to find value for given key */
    uint32_t i = hash(key, len) % T->n;
    value_t *ret = find_val(T, key, len, i);
    if (ret == NULL) { /* insert if not found */
        ret = insert_key(T, i, key, len);
    }

    return ret;
}


value_t* ahtable_tryget(ahtable_t* T, const char* key, size_t len )
{
    uint32_t i = hash(key, len) % T->n;
    return find_val(T, key, len, i);
}

value_t *ahtable_indexval(ahtable_t* T, unsigned i)
{
    return slotval(T->index[i]);
}

void ahtable_build_index(ahtable_t* T)
{
    if (T->index) {
        free(T->index);
        T->index = NULL;
    }

    if (T->m == 0) return;

    T->index = malloc(T->m * sizeof(slot_t));

    slot_t s;
    size_t j, k, u;
    for (j = 0, u = 0; j < T->n; ++j) {
        s = T->slots[j];
        while (s < T->slots[j] + T->slot_sizes[j]) {
            T->index[u++] = s;
            k = keylen(s);
            s += k < 128 ? 1 : 2;
            s += k + sizeof(value_t);
        }
    }

    qsort(T->index, T->m, sizeof(slot_t), cmpkey);
}

int ahtable_find_leq (ahtable_t* T, const char* key, size_t len, value_t** dst)
{
    *dst = NULL;
    if (T->m == 0) return 1;
    assert(T->index != NULL);

    /* the array is T->m size and sorted, use binary search */
    int r = 0;
    int a = 0, b = T->m - 1, k = 0;
    while (a <= b) {
        k = (a + b) / 2;    /* divide interval */
        r = cmpkeystr(key, len, T->index[k]);
        if (r == 0) {
            break;
        }
        if (r < 0) {
            b = k - 1;
        } else {
            a = k + 1;
        }

    }


    if (r < 0) {
        --k;    /* k is after previous node */
        r = -1;
    } else if (r > 0) {
        r = -1; /* k is previous node */
    }
    if (k > -1) {
        *dst = ahtable_indexval(T, k);
    }

    return r;
}

void ahtable_insert (ahtable_t* T, const char* key, size_t len, value_t val)
{
    /* if we are at capacity, preemptively resize */
    if (T->m >= T->max_m) {
        ahtable_expand(T);
    }

    uint32_t i = hash(key, len) % T->n;
    *insert_key(T, i, key, len) = val;
}


int ahtable_del(ahtable_t* T, const char* key, size_t len)
{
    uint32_t i = hash(key, len) % T->n;
    size_t k;
    slot_t s;

    /* search the array for our key */
    s = T->slots[i];
    while ((size_t) (s - T->slots[i]) < T->slot_sizes[i]) {
        /* get the key length */
        k = keylen(s);
        s += k < 128 ? 1 : 2;

        /* skip keys that are longer than ours */
        if (k != len) {
            s += k + sizeof(value_t);
            continue;
        }

        /* key found. */
        if (memcmp(s, key, len) == 0) {
            /* move everything over, resize the array */
            unsigned char* t = s + len + sizeof(value_t);
            s -= k < 128 ? 1 : 2;
            memmove(s, t, T->slot_sizes[i] - (size_t) (t - T->slots[i]));
            T->slot_sizes[i] -= (size_t) (t - s);
            --T->m;
            return 0;
        }
        /* key not found. */
        else {
            s += k + sizeof(value_t);
            continue;
        }
    }

    // Key was not found. Do nothing.
    return -1;
}


/* Sorted/unsorted iterators are kept private and exposed by passing the
sorted flag to ahtable_iter_begin. */

static void ahtable_sorted_iter_begin(ahtable_t* T, ahtable_iter_t *i)
{
    if (T->index) {
        i->d.xs = T->index;
        i->flags |= AH_INDEXED;
        return;
    }

    i->d.xs = malloc(T->m * sizeof(slot_t));

    slot_t s;
    size_t j, k, u;
    for (j = 0, u = 0; j < T->n; ++j) {
        s = T->slots[j];
        while (s < T->slots[j] + T->slot_sizes[j]) {
            i->d.xs[u++] = s;
            k = keylen(s);
            s += k < 128 ? 1 : 2;
            s += k + sizeof(value_t);
        }
    }

    qsort(i->d.xs, T->m, sizeof(slot_t), cmpkey);
}


static inline bool ahtable_sorted_iter_finished(ahtable_iter_t* i)
{
    return i->i >= i->T->m;
}


static inline void ahtable_sorted_iter_next(ahtable_iter_t* i)
{
    if (ahtable_iter_finished(i)) return;
    ++i->i;
}

static void ahtable_sorted_iter_del(ahtable_iter_t* i)
{
    if (ahtable_iter_finished(i)) return;
    /*! \todo same as unsorted, but remove from iterator sorted array */
    assert(0);
}


static inline void ahtable_sorted_iter_free(ahtable_iter_t* i)
{
    if (i == NULL) return;
    if (!(i->flags & AH_INDEXED)) {
        free(i->d.xs);
    }
}


static const char* ahtable_sorted_iter_key(ahtable_iter_t* i, size_t* len)
{
    if (ahtable_iter_finished(i)) return NULL;
    return slotkey(i->d.xs[i->i], len);
}


static value_t*  ahtable_sorted_iter_val(ahtable_iter_t* i)
{
    if (ahtable_iter_finished(i)) return NULL;
    return slotval(i->d.xs[i->i]);
}

static void ahtable_unsorted_iter_begin(ahtable_t* T, ahtable_iter_t *i)
{
    for (i->i = 0; i->i < i->T->n; ++i->i) {
        i->d.s = T->slots[i->i];
        if ((size_t) (i->d.s - T->slots[i->i]) >= T->slot_sizes[i->i]) continue;
        break;
    }
}


static inline bool ahtable_unsorted_iter_finished(ahtable_iter_t* i)
{
    return i->i >= i->T->n;
}


static void ahtable_unsorted_iter_next(ahtable_iter_t* i)
{
    if (ahtable_iter_finished(i)) return;

    /* get the key length */
    size_t k = keylen(i->d.s);
    i->d.s += k < 128 ? 1 : 2;

    /* skip to the next key */
    i->d.s += k + sizeof(value_t);

    if ((size_t) (i->d.s - i->T->slots[i->i]) >= i->T->slot_sizes[i->i]) {
        do {
            ++i->i;
        } while(i->i < i->T->n &&
                i->T->slot_sizes[i->i] == 0);

        if (i->i < i->T->n) i->d.s = i->T->slots[i->i];
        else i->d.s = NULL;
    }
}

static void ahtable_unsorted_iter_del(ahtable_iter_t* i)
{
    /* get the entry length */
    size_t k = keylen(i->d.s);
    unsigned char* t = i->d.s + (k < 128 ? 1 : 2) + k + sizeof(value_t);
    memmove(i->d.s, t, i->T->slot_sizes[i->i] - (size_t)(t - i->T->slots[i->i]));
    i->T->slot_sizes[i->i] -= (size_t)(t - i->d.s);
    --i->T->m;

    /* find next filled slot*/
    if ((size_t) (i->d.s - i->T->slots[i->i]) >= i->T->slot_sizes[i->i]) {
        do {
            ++i->i;
        } while(i->i < i->T->n &&
                i->T->slot_sizes[i->i] == 0);

        if (i->i < i->T->n) i->d.s = i->T->slots[i->i];
        else i->d.s = NULL;
    }
}

static const char* ahtable_unsorted_iter_key(ahtable_iter_t* i, size_t* len)
{
    if (ahtable_iter_finished(i)) return NULL;

    slot_t s = i->d.s;
    size_t k;
    if (0x1 & *s) {
        k = (size_t) (*((uint16_t*) s)) >> 1;
        s += 2;
    }
    else {
        k = (size_t) (*s >> 1);
        s += 1;
    }

    *len = k;
    return (const char*) s;
}


static value_t* ahtable_unsorted_iter_val(ahtable_iter_t* i)
{
    if (ahtable_iter_finished(i)) return NULL;
    return slotval(i->d.s);
}


void ahtable_iter_begin(ahtable_t* T, ahtable_iter_t* i, bool sorted) {
    memset(i, 0, sizeof(ahtable_iter_t));
    i->T = T;
    if (sorted) {
        i->flags |= AH_SORTED;
        ahtable_sorted_iter_begin(T, i);
    } else {
        ahtable_unsorted_iter_begin(T, i);
    }
}


void ahtable_iter_next(ahtable_iter_t* i)
{
    if (i->flags & AH_SORTED) ahtable_sorted_iter_next(i);
    else                      ahtable_unsorted_iter_next(i);
}

void ahtable_iter_del(ahtable_iter_t* i)
{
    if (i->flags & AH_SORTED) ahtable_sorted_iter_del(i);
    else                      ahtable_unsorted_iter_del(i);
}


bool ahtable_iter_finished(ahtable_iter_t* i)
{
    if (i->flags & AH_SORTED) return ahtable_sorted_iter_finished(i);
    else                      return ahtable_unsorted_iter_finished(i);
}

void ahtable_iter_free(ahtable_iter_t* i)
{
    if (i == NULL) return;
    if (i->flags & AH_SORTED) ahtable_sorted_iter_free(i);
}


const char* ahtable_iter_key(ahtable_iter_t* i, size_t* len)
{
    if (i->flags & AH_SORTED) return ahtable_sorted_iter_key(i, len);
    else                      return ahtable_unsorted_iter_key(i, len);
}


value_t* ahtable_iter_val(ahtable_iter_t* i)
{
    if (i->flags & AH_SORTED) return ahtable_sorted_iter_val(i);
    else                      return ahtable_unsorted_iter_val(i);
}
