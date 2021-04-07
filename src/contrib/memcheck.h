#pragma once
#ifdef KNOT_ENABLE_MEMCHECK
#include <memcheck.h>
#else
#define VALGRIND_MAKE_MEM_NOACCESS(...)
#define VALGRIND_MAKE_MEM_UNDEFINED(...)
#define VALGRIND_MAKE_MEM_DEFINED(...)
#endif