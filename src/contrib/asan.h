/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

/*
 * see sanitizer/asan_interface.h in compiler-rt (LLVM)
 */
#ifndef __has_feature
  #define __has_feature(feature) 0
#endif

#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
  void __asan_poison_memory_region(void const volatile *addr, size_t size);
  void __asan_unpoison_memory_region(void const volatile *addr, size_t size);

  #define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
    __asan_unpoison_memory_region((addr), (size))

  #if defined(__GNUC__) && !defined(__clang__)  /* A faulty GCC workaround. */
    #if (__GNUC__ >= 14)  /* newer versions of gcc */
      #define ASAN_POISON_MEMORY_REGION(addr, size)                    \
        do {                                                           \
          _Pragma("GCC diagnostic push");                              \
          _Pragma("GCC diagnostic ignored \"-Wmaybe-uninitialized\""); \
          __asan_poison_memory_region((addr), (size));                 \
          _Pragma("GCC diagnostic pop");                               \
        } while (0)
    #else  /* older versions of gcc */
      #pragma GCC diagnostic push
      #pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
      #define ASAN_POISON_MEMORY_REGION(addr, size) \
        __asan_poison_memory_region((addr), (size));
      #pragma GCC diagnostic pop
    #endif
  #else  /* non-gcc (clang) definition */
    #define ASAN_POISON_MEMORY_REGION(addr, size) \
      __asan_poison_memory_region((addr), (size));
  #endif

#else /* __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__) */
  #define ASAN_POISON_MEMORY_REGION(addr, size) \
    ((void)(addr), (void)(size))
  #define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
    ((void)(addr), (void)(size))
#endif /* __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__) */
