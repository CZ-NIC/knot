#pragma once
#ifdef KNOT_ENABLE_MEMCHECK
#include <valgrind/memcheck.h>
#include <valgrind/valgrind.h>
#else
#define RUNNING_ON_VALGRIND 0
#define VALGRIND_MAKE_MEM_NOACCESS(...)
#define VALGRIND_MAKE_MEM_UNDEFINED(...)
#define VALGRIND_MAKE_MEM_DEFINED(...)
#endif
