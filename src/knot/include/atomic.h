#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#ifdef HAVE_STDATOMIC
#include <stdatomic.h>
#endif
#ifdef HAVE_STDALIGN
#include <stdalign.h>
#define KNOT_ALIGN(align) alignas(align)
#else
#define KNOT_ALIGN(align)
#endif
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#ifdef HAVE_STDATOMIC
#define KNOT_ATOMIC _Atomic
#define KNOT_ATOMIC_INIT(dst, src) atomic_init(&(dst), src)
#define KNOT_ATOMIC_GET(src, dst) (dst) = atomic_load(src)
#define KNOT_ATOMIC_GET_RELAXED(src, dst) (dst) = atomic_load_explicit(src, memory_order_relaxed)
#define KNOT_ATOMIC_COMPARE_EXCHANGE_WEAK(src, cmp, val) atomic_compare_exchange_weak(src, &(cmp), val)
#define KNOT_ATOMIC_COMPARE_EXCHANGE_STRONG(src, cmp, val) atomic_compare_exchange_strong(src, &(cmp), val)
#define KNOT_ATOMIC_GET_SUB(src, val) atomic_fetch_sub(src, val)
#define KNOT_ATOMIC_GET_ADD(src, val) atomic_fetch_add(src, val)
#else
#ifdef HAVE_ATOMIC
#define KNOT_ATOMIC volatile
#define KNOT_ATOMIC_INIT(dst, src) __atomic_store(&(dst), &(src), __ATOMIC_SEQ_CST)
#define KNOT_ATOMIC_GET(src, dst) __atomic_load(src, &(dst), __ATOMIC_CONSUME)
#define KNOT_ATOMIC_GET_RELAXED(src, dst) __atomic_load(src, &(dst), __ATOMIC_RELAXED)
#define KNOT_ATOMIC_COMPARE_EXCHANGE_WEAK(src, cmp, val) __atomic_compare_exchange(src, &(cmp), &(val), true, __ATOMIC_ACQ_REL, __ATOMIC_CONSUME)
#define KNOT_ATOMIC_COMPARE_EXCHANGE_STRONG KNOT_ATOMIC_COMPARE_EXCHANGE_WEAK
#define KNOT_ATOMIC_GET_SUB(src, val) __atomic_fetch_sub(src, val, __ATOMIC_ACQ_REL)
#define KNOT_ATOMIC_GET_ADD(src, val) __atomic_fetch_add(src, val, __ATOMIC_ACQ_REL)
#else
#error Need atomic or stdatomic support
#endif
#endif

