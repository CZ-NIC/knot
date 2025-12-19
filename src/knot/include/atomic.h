#pragma once

#ifndef HAVE_C11_ATOMIC
 #error "Missing C11 stdatomic support"
#endif

#include <stdatomic.h>

#define KNOT_ALIGN(align) _Alignas(align)
#define KNOT_ATOMIC _Atomic
#define KNOT_ATOMIC_INIT(dst, src) atomic_init(&(dst), src)
#define KNOT_ATOMIC_GET(src, dst) (dst) = atomic_load(src)
#define KNOT_ATOMIC_GET_RELAXED(src, dst) (dst) = atomic_load_explicit(src, memory_order_relaxed)
#define KNOT_ATOMIC_COMPARE_EXCHANGE_WEAK(src, cmp, val) atomic_compare_exchange_weak(src, &(cmp), val)
#define KNOT_ATOMIC_COMPARE_EXCHANGE_STRONG(src, cmp, val) atomic_compare_exchange_strong(src, &(cmp), val)
#define KNOT_ATOMIC_GET_SUB(src, val) atomic_fetch_sub(src, val)
#define KNOT_ATOMIC_GET_ADD(src, val) atomic_fetch_add(src, val)
