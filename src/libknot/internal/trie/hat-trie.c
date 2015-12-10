/*
 * This file is part of hat-trie.
 *
 * Copyright (c) 2011 by Daniel C. Jones <dcjones@cs.washington.edu>
 *
 */

#include <stdint.h>
#include <assert.h>
#include <string.h>
#include "libknot/internal/trie/hat-trie.h"
#include "libknot/internal/hhash.h"

/* number of child nodes for used alphabet */
#define NODE_CHILDS (TRIE_MAXCHAR+1)
/* initial nodestack size */
#define NODESTACK_INIT 128
/* hashtable max fill (undefine to maximize) */
#define HHASH_MAX_FILL 0.9

static const uint8_t NODE_TYPE_TRIE          = 0x1;
static const uint8_t NODE_TYPE_PURE_BUCKET   = 0x2;
static const uint8_t NODE_TYPE_HYBRID_BUCKET = 0x4;
static const uint8_t NODE_HAS_VAL            = 0x8;

struct trie_node_t_;

/* Node's may be trie nodes or buckets. This union allows us to keep
 * non-specific pointer. */
typedef union node_ptr_
{
    hhash_t*           b;
    struct trie_node_t_* t;
    uint8_t*             flag;
} node_ptr;

typedef struct trie_node_t_
{
    uint8_t flag;

    /* the value for the key that is consumed on a trie node */
    value_t val;

    /* Map a character to either a trie_node_t or a hhash_t. The first byte
     * must be examined to determine which. */
    node_ptr xs[NODE_CHILDS];

} trie_node_t;

struct hattrie_t_
{
    node_ptr root; // root node
    size_t m;      // number of stored keys
    unsigned bsize; // bucket size
    mm_ctx_t mm;
};

/* Create an empty trie node. */
static trie_node_t* alloc_empty_node(hattrie_t* T)
{
    trie_node_t* node = T->mm.alloc(T->mm.ctx, sizeof(trie_node_t));
    node->flag = NODE_TYPE_TRIE;
    node->val  = 0;

    memset(node->xs, 0, sizeof(node_ptr) * NODE_CHILDS);
    return node;
}

/* Create a new trie node with all pointer pointing to the given child (which
 * can be NULL). */
static trie_node_t* alloc_trie_node(hattrie_t* T, node_ptr child)
{
    trie_node_t* node = T->mm.alloc(T->mm.ctx, sizeof(trie_node_t));
    node->flag = NODE_TYPE_TRIE;
    node->val  = 0;

    size_t i;
    for (i = 0; i < NODE_CHILDS; ++i) node->xs[i] = child;
    return node;
}

/* iterate trie nodes until string is consumed or bucket is found */
static node_ptr hattrie_consume_ns(node_ptr **s, size_t *sp, size_t slen,
                                const char **k, size_t *l, unsigned min_len)
{

    node_ptr *bs = *s;
    node_ptr node = bs[*sp].t->xs[(unsigned char) **k];
    while (node.flag && *node.flag & NODE_TYPE_TRIE && *l > min_len) {
        ++*k;
        --*l;
        /* build node stack if slen > 0 */
        if (slen > 0) {
            if (*sp == slen - 1) {
                /* switch pointers if allocating from base
                 * this is a bit ugly, but needed to avoid memory allocation
                 * most of the time
                 */
                slen *= 2;
                if (bs == *s) { /* points to original stack mem */
                    bs = malloc(slen * sizeof(node_ptr));
                    memcpy(bs, *s, (slen/2) * sizeof(node_ptr));
                } else {        /* points to heap memory already */
                    node_ptr *bs_new = realloc(bs, slen * sizeof(node_ptr));
					/* \note tricky, hattrie should be slowly moved from 'never-expect-malloc-fail' state */
					if (bs_new == NULL) {
						*sp = 0;      /* caller will get take care of freeing old 'bs' */
						return bs[0]; /* return root node, so the search fails */
					} else {
						bs = bs_new;
					}
                }
                /* update parent pointer on resize */
                *s = bs;
            }
            /* increment stack pointer */
            ++*sp;
        }
        bs[*sp] = node;
        node = node.t->xs[(unsigned char) **k];
    }

    /* stack top is always parent node */
    assert(*bs[*sp].flag & NODE_TYPE_TRIE);
    return node;
}

/*! \brief Consume key. */
static inline node_ptr hattrie_consume(node_ptr *parent, const char **key,
                                       size_t *key_len, unsigned min_len)
{
    size_t sp = 0;
    return hattrie_consume_ns(&parent, &sp, 0, key, key_len, min_len);
}

/* use node value and return pointer to it */
static inline value_t* hattrie_useval(hattrie_t *T, node_ptr n)
{
    if (!(n.t->flag & NODE_HAS_VAL)) {
        n.t->flag |= NODE_HAS_VAL;
        ++T->m;
    }
    return &n.t->val;
}

/* clear node value if exists */
static inline int hattrie_clrval(hattrie_t *T, node_ptr n)
{
    if (n.t->flag & NODE_HAS_VAL) {
        n.t->flag &= ~NODE_HAS_VAL;
        n.t->val = 0;
        --T->m;
        return 0;
    }
    return -1;
}

/* find rightmost non-empty node */
static value_t* hattrie_find_rightmost(node_ptr node)
{
    /* iterate children from right */
    if (*node.flag & NODE_TYPE_TRIE) {
        for (int i = TRIE_MAXCHAR; i > -1; --i) {
            /* skip repeated pointers to hybrid bucket */
            if (i < TRIE_MAXCHAR && node.t->xs[i].t == node.t->xs[i + 1].t)
                continue;
            /* nest if trie */
            value_t *ret = hattrie_find_rightmost(node.t->xs[i]);
            if (ret) {
                return ret;
            }
        }
        /* use trie node value if no children found */
        if (node.t->flag & NODE_HAS_VAL) {
            return &node.t->val;
        }

        /* no non-empty children? */
        return NULL;
    }

    /* node is hashtable */
    if (node.b->weight == 0) {
        return NULL;
    }
    /* return rightmost value */
    assert(node.b->index);
    return hhash_indexval(node.b, node.b->weight - 1);
}

static value_t* hattrie_find_leftmost(node_ptr node)
{
    /* iterate children from left */
    if (*node.flag & NODE_TYPE_TRIE) {
        for (int i = 0; i <= TRIE_MAXCHAR; ++i) {
            /* skip repeated pointers to hybrid bucket */
            if (i < TRIE_MAXCHAR - 1 && node.t->xs[i].t == node.t->xs[i + 1].t) {
                continue;
            }
            /* nest if trie */
            value_t *ret = hattrie_find_leftmost(node.t->xs[i]);
            if (ret) {
                return ret;
            }
        }
        /* use trie node value if no children found */
        if (node.t->flag & NODE_HAS_VAL) {
            return &node.t->val;
        }

        /* no non-empty children? */
        return NULL;
    }

    /* node is hashtable */
    if (node.b->weight == 0) {
        return NULL;
    }
    /* return leftmost value */
    assert(node.b->index);
    return hhash_indexval(node.b, 0);
}

/* find node in trie and keep node stack (if slen > 0) */
static node_ptr hattrie_find_ns(node_ptr **s, size_t *sp, size_t slen,
                                const char **key, size_t *len)
{
    assert(*(*s)[*sp].flag & NODE_TYPE_TRIE);

    if (*len == 0) return (*s)[*sp]; /* parent, as sp == 0 */

    node_ptr node = hattrie_consume_ns(s, sp, slen, key, len, 1);

    /* using pure trie and couldn't find the key, return stack top */
    if (node.flag == NULL) {
        node = (*s)[*sp];
    }

    /* if the trie node consumes value, use it */
    if (*node.flag & NODE_TYPE_TRIE) {
        if (!(node.t->flag & NODE_HAS_VAL)) {
            node.flag = NULL;
        }
        return node;
    }

    /* pure bucket holds only key suffixes, skip current char */
    if (*node.flag & NODE_TYPE_PURE_BUCKET) {
        ++*key;
        --*len;
    }

    /* do not scan bucket, it's not needed for this operation */
    return node;
}

/* find node in trie */
static inline node_ptr hattrie_find(node_ptr *parent, const char **key, size_t *len)
{
    size_t sp = 0;
    return hattrie_find_ns(&parent, &sp, 0, key, len);
}

/* initialize root node */
static void hattrie_initroot(hattrie_t *T)
{
    node_ptr node;
    if (T->bsize > 0) {
        node.b = hhash_create(TRIE_BUCKET_SIZE);
        node.b->flag = NODE_TYPE_HYBRID_BUCKET;
        node.b->c0 = 0x00;
        node.b->c1 = TRIE_MAXCHAR;
        T->root.t = alloc_trie_node(T, node);
    } else {
        T->root.t = alloc_empty_node(T);
    }
}

/* Free hat-trie nodes recursively. */
static void hattrie_free_node(node_ptr node, mm_free_t free_cb)
{
    if (*node.flag & NODE_TYPE_TRIE) {
        size_t i;
        for (i = 0; i < NODE_CHILDS; ++i) {
            if (i > 0 && node.t->xs[i].t == node.t->xs[i - 1].t)
                continue;

            /* XXX: recursion might not be the best choice here. It is possible
             * to build a very deep trie. */
            if (node.t->xs[i].t)
                hattrie_free_node(node.t->xs[i], free_cb);
        }
        if (free_cb)
            free_cb(node.t);
    }
    else {
        hhash_free(node.b);
    }
}

/* Initialize hat-trie. */
static void hattrie_init(hattrie_t * T, unsigned bucket_size)
{
    T->m = 0;
    T->bsize = bucket_size;
    hattrie_initroot(T);
}

/* Deinitialize hat-trie. */
static void hattrie_deinit(hattrie_t * T)
{
    if (T->bsize > 0 || T->mm.free)
        hattrie_free_node(T->root, T->mm.free);
}

hattrie_t* hattrie_create()
{
    mm_ctx_t mm;
    mm_ctx_init(&mm);
    return hattrie_create_n(TRIE_BUCKET_SIZE, &mm);
}

void hattrie_free(hattrie_t* T)
{
    if (T == NULL) {
        return;
    }
    hattrie_deinit(T);
    if (T->mm.free)
        T->mm.free(T);
}

void hattrie_clear(hattrie_t* T)
{
    if (T == NULL) {
        return;
    }

    hattrie_deinit(T);
    hattrie_init(T, T->bsize);
}

hattrie_t* hattrie_dup(const hattrie_t* T, value_t (*nval)(value_t))
{
    hattrie_t *N = hattrie_create_n(T->bsize, &T->mm);

    if (nval == NULL) {
        return N;
    }

    /*! \todo could be probably implemented faster */

    size_t l = 0;
    const char *k = NULL;
    hattrie_iter_t *i = hattrie_iter_begin(T, false);
    while (!hattrie_iter_finished(i)) {
        k = hattrie_iter_key(i, &l);
        *hattrie_get(N, k, l) = nval(*hattrie_iter_val(i));
        hattrie_iter_next(i);
    }
    hattrie_iter_free(i);
    return N;
}

size_t hattrie_weight (const hattrie_t *T)
{
    if (T == NULL) {
        return 0;
    }

    return T->m;
}

hattrie_t* hattrie_create_n(unsigned bucket_size, const mm_ctx_t *mm)
{
    hattrie_t* T = mm_alloc((mm_ctx_t *)mm, sizeof(hattrie_t));
    memcpy(&T->mm, mm, sizeof(mm_ctx_t));
    hattrie_init(T, bucket_size);
    return T;
}

static void node_build_index(node_ptr node)
{
    /* build index on all hashtable nodes */
    if (*node.flag & NODE_TYPE_TRIE) {
        size_t i;
        for (i = 0; i < NODE_CHILDS; ++i) {
            if (i > 0 && node.t->xs[i].t == node.t->xs[i - 1].t) continue;
            if (node.t->xs[i].t) node_build_index(node.t->xs[i]);
        }
    }
    else {
        hhash_build_index(node.b);
    }
}

void hattrie_build_index(hattrie_t *T)
{
    node_build_index(T->root);
}

static int node_apply(node_ptr node, int (*f)(value_t*,void*), void* d)
{
    int result = TRIE_EOK;

    if (*node.flag & NODE_TYPE_TRIE) {
        size_t i;
        for (i = 0; i < NODE_CHILDS; ++i) {
            if (i > 0 && node.t->xs[i].t == node.t->xs[i - 1].t) {
                continue;
            }
            if (node.t->xs[i].t) {
                result = node_apply(node.t->xs[i], f, d);
            }
            if (result == TRIE_EOK && *node.flag & NODE_HAS_VAL) {
                result = f(&node.t->val, d);
            }
            if (result != TRIE_EOK) {
                break;
            }
        }
    }
    else {
        hhash_iter_t i;
        hhash_iter_begin(node.b, &i, false);
        while (!hhash_iter_finished(&i)) {
            result = f(hhash_iter_val(&i), d);
            if (result != TRIE_EOK) {
                break;
            }
            hhash_iter_next(&i);
        }
    }

    return result;
}

static int node_apply_ahtable(node_ptr node, int (*f)(void*,void*), void* d)
{
    int result = TRIE_EOK;

    if (*node.flag & NODE_TYPE_TRIE) {
        size_t i;
        for (i = 0; i < NODE_CHILDS; ++i) {
            if (i > 0 && node.t->xs[i].t == node.t->xs[i - 1].t) {
                continue;
            }
            if (node.t->xs[i].t) {
                result = node_apply_ahtable(node.t->xs[i], f, d);
                if (result != TRIE_EOK) {
                    break;
                }
            }
        }
    }
    else {
        result = f(node.b, d);
    }

    return result;
}

int hattrie_apply_rev(hattrie_t* T, int (*f)(value_t*,void*), void* d)
{
    return node_apply(T->root, f, d);
}

int hattrie_apply_rev_ahtable(hattrie_t* T, int (*f)(void*,void*), void* d)
{
    return node_apply_ahtable(T->root, f, d);
}

int hattrie_split_mid(node_ptr node, unsigned *left_m, unsigned *right_m)
{
    /* count the number of occourances of every leading character */
    unsigned int cs[NODE_CHILDS]; // occurance count for leading chars
    memset(cs, 0, NODE_CHILDS * sizeof(unsigned int));
    uint16_t len;
    const char* key;

    /*! \todo expensive, maybe some heuristics or precalc would be better */
    hhash_iter_t i;
    hhash_iter_begin(node.b, &i, false);
    while (!hhash_iter_finished(&i)) {
        key = hhash_iter_key(&i, &len);
        assert(len > 0);
        cs[(unsigned char) key[0]] += 1;
        hhash_iter_next(&i);
    }

    /* choose a split point */
    unsigned int all_m;
    unsigned char j = node.b->c0;
    all_m   = node.b->weight;
    *left_m  = cs[j];
    *right_m = all_m - *left_m;
    int d;

    while (j + 1 < node.b->c1) {
        d = abs((int) (*left_m + cs[j + 1]) - (int) (*right_m - cs[j + 1]));
        if (d <= abs((int) (*left_m) - (int) (*right_m)) && *left_m + cs[j + 1] < all_m) {
            j += 1;
            *left_m  += cs[j];
            *right_m -= cs[j];
        }
        else break;
    }

    return j;
}

static value_t *find_below(hattrie_t *T, node_ptr parent,
                          const char *key, size_t len);

static void hashnode_split_reinsert(hattrie_t *T, node_ptr parent, node_ptr src)
{
    value_t* u = NULL;
    const char* key = NULL;
    uint16_t len = 0;
    hhash_iter_t i;

    hhash_iter_begin(src.b, &i, false);
    while (!hhash_iter_finished(&i)) {
        key = hhash_iter_key(&i, &len);
        u   = hhash_iter_val(&i);

        *find_below(T, parent, key, len) = *u;

        hhash_iter_next(&i);
    }
    hhash_free(src.b);
}

static size_t hashnode_nextsize(unsigned items)
{
    /* Next bucket size increments. */
    size_t increment = ((items + (TRIE_BUCKET_INCR/2))/TRIE_BUCKET_INCR);
    if (increment > TRIE_BUCKET_MAX) {
       increment = TRIE_BUCKET_MAX;
    }
    /* Align to closest bucket size. */
    return TRIE_BUCKET_SIZE + increment * TRIE_BUCKET_INCR;
}

static void hashnode_split(hattrie_t *T, node_ptr parent, node_ptr node)
{
    /* Find split point. */
    unsigned left_m, right_m;
    unsigned char j = hattrie_split_mid(node, &left_m, &right_m);

    /* now split into two nodes corresponding to ranges [0, j] and
     * [j + 1, TRIE_MAXCHAR], respectively. */

    /* create new left and right nodes
     * one node may reuse existing if it keeps hybrid flag
     * hybrid -> pure always needs a new table
     */
    unsigned char c0 = node.b->c0, c1 = node.b->c1;
    node_ptr left, right;
    right.b = hhash_create(hashnode_nextsize(right_m));
    left.b = hhash_create(hashnode_nextsize(left_m));

    /* setup created nodes */
    left.b->c0    = c0;
    left.b->c1    = j;
    left.b->flag = c0 == j ? NODE_TYPE_PURE_BUCKET : NODE_TYPE_HYBRID_BUCKET; // need to force it
    right.b->c0   = j + 1;
    right.b->c1   = c1;
    right.b->flag = right.b->c0 == right.b->c1 ?
                      NODE_TYPE_PURE_BUCKET : NODE_TYPE_HYBRID_BUCKET;

    /* update the parent's pointer */
    unsigned int c;
    for (c = c0; c <= j; ++c) parent.t->xs[c] = left;
    for (; c <= c1; ++c)      parent.t->xs[c] = right;

    /* fill new tables */
    hashnode_split_reinsert(T, parent, node);
}

/* Perform one split operation on the given node with the given parent.
 */
static void node_split(hattrie_t* T, node_ptr parent, node_ptr node)
{
    /* only buckets may be split */
    assert(*node.flag & NODE_TYPE_PURE_BUCKET ||
           *node.flag & NODE_TYPE_HYBRID_BUCKET);

    assert(*parent.flag & NODE_TYPE_TRIE);

    if (*node.flag & NODE_TYPE_PURE_BUCKET) {
        /* turn the pure bucket into a hybrid bucket */
        parent.t->xs[node.b->c0].t = alloc_trie_node(T, node);

        /* if the bucket had an empty key, move it to the new trie node */
        value_t* val = hhash_find(node.b, NULL, 0);
        if (val) {
            parent.t->xs[node.b->c0].t->val     = *val;
            parent.t->xs[node.b->c0].t->flag |= NODE_HAS_VAL;
            *val = 0;
            hhash_del(node.b, NULL, 0);
        }

        node.b->c0   = 0x00;
        node.b->c1   = TRIE_MAXCHAR;
        node.b->flag = NODE_TYPE_HYBRID_BUCKET;

        return;
    }

    /* This is a hybrid bucket. Perform a proper split. */
    hashnode_split(T, parent, node);
}

static value_t *find_below(hattrie_t *T, node_ptr parent, const char *key, size_t len)
{
    /* consume all trie nodes, now parent must be trie and child anything */
    node_ptr node = hattrie_consume(&parent, &key, &len, 0);
    assert(*parent.flag & NODE_TYPE_TRIE);

    /* if the key has been consumed on a trie node, use its value */
    if (len == 0) {
        if (*node.flag & NODE_TYPE_TRIE) {
            return hattrie_useval(T, node);
        } else if (*node.flag & NODE_TYPE_HYBRID_BUCKET) {
            return hattrie_useval(T, parent);
        }
    }

#ifdef HHASH_MAX_FILL
    /* preemptively split the bucket if fill is over threshold */
    if (node.b->weight >= node.b->size * HHASH_MAX_FILL) {
        node_split(T, parent, node);
        return find_below(T, parent, key, len);
    }
#endif

    /* attempt to fit new element and split if it doesn't fit */
    value_t *val = NULL;
    assert(len > 0);
    if (*node.flag & NODE_TYPE_PURE_BUCKET) {
        val = hhash_map(node.b, key + 1, len - 1, HHASH_INSERT);
    }
    else {
        val = hhash_map(node.b, key, len, HHASH_INSERT);
    }

    /* not inserted, recursively split */
    if (val == NULL) {
        node_split(T, parent, node);
        val = find_below(T, parent, key, len);
    }

    return val;
}

value_t* hattrie_get(hattrie_t* T, const char* key, size_t len)
{
    node_ptr parent = T->root;
    value_t *val = NULL;
    assert(*parent.flag & NODE_TYPE_TRIE);

    /* Find value below root node if not empty string. */
    if (len == 0) {
        val = &parent.t->val;
    } else {
        val = find_below(T, parent, key, len);
    }

    /* Count insertions. */
    if (val && *val == NULL) {
        ++T->m;
    }

    return val;
}

value_t* hattrie_tryget(hattrie_t* T, const char* key, size_t len)
{
    /* find node for given key */
    node_ptr parent = T->root;
    node_ptr node = hattrie_find(&parent, &key, &len);
    if (node.flag == NULL) {
        return NULL;
    }

    /* if the trie node consumes value, use it */
    if (*node.flag & NODE_TYPE_TRIE) {
        return &node.t->val;
    }

    return hhash_find(node.b, key, len);
}

static value_t* hattrie_walk_left(node_ptr* s, size_t sp,
                             const char* key, value_t* (*f)(node_ptr))
{
    value_t *r = NULL;
    while (r == NULL)  {
        /* if not found prev in table, it should be
         * the rightmost of the nodes left of the current
         */
        node_ptr visited = s[sp].t->xs[(unsigned char)*key];
        for (int i = *key - 1; i > -1; --i) {
            if (s[sp].t->xs[i].flag == visited.flag)
                continue; /* skip pointers to visited container */
            r = f(s[sp].t->xs[i]);
            if (r) {
                return r;
            }
        }

        /* use trie node value if possible */
        if (s[sp].t->flag & NODE_HAS_VAL) {
            return &s[sp].t->val;
        }

        /* consumed whole stack */
        if (sp == 0) {
            break;
        }

        /* pop stack */
        --key;
        --sp;
    }

    return NULL;
}

static value_t* hattrie_walk_right(node_ptr* s, size_t sp,
                                   const char* key, value_t* (*f)(node_ptr))
{
    value_t *r = NULL;
    while (r == NULL)  {
        /* if not found next in table, it should be
         * the leftmost of the nodes right of the current
         */
        node_ptr visited = s[sp].t->xs[(unsigned char)*key];
        for (int i = *key + 1; i <= TRIE_MAXCHAR; ++i) {
            if (s[sp].t->xs[i].flag == visited.flag)
                continue; /* skip pointers to visited container */
            r = f(s[sp].t->xs[i]);
            if (r) {
                return r;
            }
        }
        /* use trie node value if possible */
        if (s[sp].t->flag & NODE_HAS_VAL) {
            return &s[sp].t->val;
        }

        /* consumed whole stack */
        if (sp == 0) {
            break;
        }

        /* pop stack */
        --key;
        --sp;
    }

    return NULL;
}

int hattrie_find_leq (hattrie_t* T, const char* key, size_t len, value_t** dst)
{
    /* create node stack for traceback */
    size_t sp = 0;
    node_ptr bs[NODESTACK_INIT];  /* base stack (will be enough mostly) */
    node_ptr *ns = bs;            /* generic ptr, could point to new mem */
    ns[sp] = T->root;

    /* find node for given key */
    int ret = 1; /* no node on the left matches */
    node_ptr node = hattrie_find_ns(&ns, &sp, NODESTACK_INIT, &key, &len);
    if (node.flag == NULL) {
        *dst = hattrie_walk_left(ns, sp, key, hattrie_find_rightmost);
        if (ns != bs) free(ns);
        if (*dst) {
            return -1; /* found previous */
        }
        return 1; /* no previous key found */
    }

    /* assign value from trie or find in table */
    if (*node.flag & NODE_TYPE_TRIE) {
        *dst = &node.t->val;
        ret = 0;     /* found exact match */
    } else {
        *dst = hhash_find(node.b, key, len);
        if (*dst) {
            ret = 0; /* found exact match */
        } else {     /* look for previous in hashtable */
            ret = hhash_find_leq(node.b, key, len, dst);
        }
    }

    /* return if found equal or left in hashtable */
    if (*dst == 0) {
        /* we're retracing from pure bucket, pop the key */
        if (*node.flag & NODE_TYPE_PURE_BUCKET) {
            --key;
        }
        /* walk up the stack of visited nodes and find closest match on the left */
        *dst = hattrie_walk_left(ns, sp, key, hattrie_find_rightmost);
        if (*dst) {
            ret = -1; /* found previous */
        } else {
            ret = 1; /* no previous key found */
        }
    }

    if (ns != bs) free(ns);
    return ret;
}

int hattrie_find_next (hattrie_t* T, const char* key, size_t len, value_t **dst)
{
    /* create node stack for traceback */
    size_t sp = 0;
    node_ptr bs[NODESTACK_INIT];  /* base stack (will be enough mostly) */
    node_ptr *ns = bs;            /* generic ptr, could point to new mem */
    ns[sp] = T->root;

    /* find node for given key */
    node_ptr ptr = hattrie_find_ns(&ns, &sp, NODESTACK_INIT, &key, &len);
    if (ptr.flag == NULL) {
        *dst = hattrie_walk_right(ns, sp, key, hattrie_find_leftmost);
        if (ns != bs) free(ns);
        if (*dst) {
            return 0; /* found next. */
        } else {
            return 1; /* no next key found. */
        }
    }

    int ret = 0;
    if (*ptr.flag & NODE_TYPE_TRIE) {
        /* Get next using walk. */
        ret = 1;
    } else {
        ret = hhash_find_next(ptr.b, key, len, dst);
    }

    if (ret == 1) {
        /* we're retracing from pure bucket, pop the key. */
        if (*ptr.flag & NODE_TYPE_PURE_BUCKET) {
            --key;
        }
        *dst = hattrie_walk_right(ns, sp, key, hattrie_find_leftmost);
        if (ns != bs) free(ns);
        if (*dst) {
            ret = 0; /* found next. */
        } else {
            ret = 1; /* no next key found. */
        }
    }

    return ret;
}

int hattrie_del(hattrie_t* T, const char* key, size_t len)
{
    node_ptr parent = T->root;
    assert(*parent.flag & NODE_TYPE_TRIE);

    /* find node for deletion */
    node_ptr node = hattrie_find(&parent, &key, &len);
    if (node.flag == NULL) {
        return -1;
    }

    /* if consumed on a trie node, clear the value */
    if (*node.flag & NODE_TYPE_TRIE) {
        return hattrie_clrval(T, node);
    }

    /* remove from bucket */
    size_t m_old = node.b->weight;
    int ret =  hhash_del(node.b, key, len);
    T->m -= (m_old - node.b->weight);

    /* merge empty buckets */
    /*! \todo */

    return ret;
}

/* plan for iteration:
 * This is tricky, as we have no parent pointers currently, and I would like to
 * avoid adding them. That means maintaining a stack
 *
 */

typedef struct hattrie_node_stack_t_
{
    unsigned char   c;
    size_t level;

    node_ptr node;
    struct hattrie_node_stack_t_* next;

} hattrie_node_stack_t;

struct hattrie_iter_t_
{
    char* key;
    size_t keysize; // space reserved for the key
    size_t level;

    /* keep track of keys stored in trie nodes */
    bool    has_nil_key;
    value_t nil_val;

    const hattrie_t* T;
    bool sorted;
    hhash_iter_t* i;
    hattrie_node_stack_t* stack;
};

static void hattrie_iter_pushchar(hattrie_iter_t* i, size_t level, char c)
{
    if (i->keysize < level) {
        i->keysize *= 2;
        i->key = realloc(i->key, i->keysize * sizeof(char));
    }

    if (level > 0) {
        i->key[level - 1] = c;
    }

    i->level = level;
}

static void hattrie_iter_nextnode(hattrie_iter_t* i)
{
    if (i->stack == NULL) return;

    /* pop the stack */
    node_ptr node;
    hattrie_node_stack_t* next;
    unsigned char   c;
    size_t level;

    node  = i->stack->node;
    next  = i->stack->next;
    c     = i->stack->c;
    level = i->stack->level;

    free(i->stack);
    i->stack = next;

    if (*node.flag & NODE_TYPE_TRIE) {
        hattrie_iter_pushchar(i, level, c);

        if(node.t->flag & NODE_HAS_VAL) {
            i->has_nil_key = true;
            i->nil_val = node.t->val;
        }

        /* push all child nodes from right to left */
        int j;
        for (j = TRIE_MAXCHAR; j >= 0; --j) {

            /* skip repeated pointers to hybrid bucket */
            if (j < TRIE_MAXCHAR && node.t->xs[j].t == node.t->xs[j + 1].t) continue;

            // push stack
            next = i->stack;
            i->stack = malloc(sizeof(hattrie_node_stack_t));
            i->stack->node  = node.t->xs[j];
            i->stack->next  = next;
            i->stack->level = level + 1;
            i->stack->c     = (unsigned char) j;
        }
    }
    else {
        if (*node.flag & NODE_TYPE_PURE_BUCKET) {
            hattrie_iter_pushchar(i, level, c);
        }
        else {
            i->level = level - 1;
        }

        i->i = malloc(sizeof(hhash_iter_t));
        hhash_iter_begin(node.b, i->i, i->sorted);
    }
}

hattrie_iter_t* hattrie_iter_begin(const hattrie_t* T, bool sorted)
{
    hattrie_iter_t* i = NULL;
    if (T) {
        i = malloc(sizeof(hattrie_iter_t));
        i->T = T;
        i->sorted = sorted;
        i->i = NULL;
        i->keysize = 16;
        i->key = malloc(i->keysize * sizeof(char));
        i->level   = 0;
        i->has_nil_key = false;
        i->nil_val     = 0;

        i->stack = malloc(sizeof(hattrie_node_stack_t));
        i->stack->next   = NULL;
        i->stack->node   = T->root;
        i->stack->c      = '\0';
        i->stack->level  = 0;

        while (((i->i == NULL || hhash_iter_finished(i->i)) && !i->has_nil_key) &&
               i->stack != NULL ) {

            free(i->i);
            i->i = NULL;
            hattrie_iter_nextnode(i);
        }

        if (i->i != NULL && hhash_iter_finished(i->i)) {
             free(i->i);
             i->i = NULL;
        }
    }

    return i;
}

void hattrie_iter_next(hattrie_iter_t* i)
{
    if (hattrie_iter_finished(i)) return;

    if (i->i != NULL && !hhash_iter_finished(i->i)) {
        hhash_iter_next(i->i);
    }
    else if (i->has_nil_key) {
        i->has_nil_key = false;
        i->nil_val = 0;
        hattrie_iter_nextnode(i);
    }

    while (((i->i == NULL || hhash_iter_finished(i->i)) && !i->has_nil_key) &&
           i->stack != NULL ) {

        free(i->i);
        i->i = NULL;
        hattrie_iter_nextnode(i);
    }

    if (i->i != NULL && hhash_iter_finished(i->i)) {
        free(i->i);
        i->i = NULL;
    }
}

bool hattrie_iter_finished(hattrie_iter_t* i)
{
    return i->stack == NULL && i->i == NULL && !i->has_nil_key;
}

void hattrie_iter_free(hattrie_iter_t* i)
{
    if (i == NULL) return;
    if (i->i) {
        free(i->i);
    }

    hattrie_node_stack_t* next;
    while (i->stack) {
        next = i->stack->next;
        free(i->stack);
        i->stack = next;
    }

    free(i->key);
    free(i);
}

const char* hattrie_iter_key(hattrie_iter_t* i, size_t* len)
{
    if (hattrie_iter_finished(i)) return NULL;

    uint16_t sublen;
    const char* subkey;

    if (i->has_nil_key) {
        subkey = NULL;
        sublen = 0;
    }
    else subkey = hhash_iter_key(i->i, &sublen);

    if (i->keysize < i->level + sublen + 1) {
        while (i->keysize < i->level + sublen + 1) i->keysize *= 2;
        i->key = realloc(i->key, i->keysize * sizeof(char));
    }

    if (sublen > 0) {
        memcpy(i->key + i->level, subkey, sublen);
    }
    i->key[i->level + sublen] = '\0';

    *len = i->level + sublen;
    return i->key;
}

value_t* hattrie_iter_val(hattrie_iter_t* i)
{
    if (i->has_nil_key) return &i->nil_val;

    if (hattrie_iter_finished(i)) return NULL;

    return hhash_iter_val(i->i);
}
