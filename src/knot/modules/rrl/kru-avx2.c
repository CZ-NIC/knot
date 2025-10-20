/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

// Checked with clang 12 (2021) and gcc 6 (2016).
// For other cases we'll rather keep just the generic implementation.
#if defined(__x86_64__) && (__clang_major__ >= 12 || __GNUC__ >= 6) && !defined(__APPLE__)

// This file has code for new-ish x86 (2015+ usually, Atom 2021+) - AES + AVX2
#ifdef __clang__
	// Force using specific instructions only if target architecture/optimization not specified
	#if !defined(__AVX2__)
		#pragma clang attribute push (__attribute__((target("arch=x86-64-v3,aes"))), \
								apply_to = function)
	#endif
#else
	#pragma GCC push_options
	#if __GNUC__ >= 11
		#pragma GCC target("arch=x86-64-v3,aes")
		// try harder for auto-vectorization, etc.
		#pragma GCC optimize("O3")
	#else
		#pragma GCC target("avx2,aes")
	#endif
#endif

#define USE_AES 1
#define USE_AVX2 1
#define USE_SSE41 1

#include "./kru.inc.c"
const struct kru_api KRU_AVX2 = KRU_API_INITIALIZER;

#ifdef __clang__
	#if !defined(__AVX2__)
		#pragma clang attribute pop
	#endif
#else
	#pragma GCC pop_options
#endif

__attribute__((constructor))
static void detect_CPU_avx2(void)
{
	// Checking just AES+AVX2 will most likely be OK even if we used arch=x86-64-v3
	if (__builtin_cpu_supports("aes") && __builtin_cpu_supports("avx2")) {
		KRU = KRU_AVX2;
	}
}

#else

#include "./kru.h"
const struct kru_api KRU_AVX2 = {NULL};

#endif
