// <copyright file="modcounter.h" company="Microsoft">
//  Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>

#pragma once
#include <stdio.h>
#include "knot/include/module.h"

//# Start : DONOT MAKE CHANGES HERE TO ADD COUNTERS
#define COMBINE_NAME(p1, p2) p1##_##p2
#define COMMA_SEPARATED_P2(p1, p2) p2,
#define STRING_P2(p1, p2) #p2,
#define ARRAY_SIZE_P2_COMMA(p1, p2) ARRAY_SIZE(p2),
#define NO_CHANGE_P2(p1, p2) p2

#define CREATE_ENUM(ename, foreach) \
typedef enum { \
    foreach(COMBINE_NAME, ename, COMMA_SEPARATED_P2, _) \
} ename##_enum_t;

#define CREATE_STR_ARR(ename, foreach) \
static const char *str_map_##ename[] = { \
    foreach(STRING_P2, _, NO_CHANGE_P2, _) \
};

#define CREATE_SUB_ENUM(ename, foreach) CREATE_ENUM(ename, foreach)

#define ARRAY_SIZE(array)       (sizeof(array) / sizeof((array)[0]))

#ifdef CREATE_COUNTER_DEFINITIONS
#define CREATE_COUNTERS(ename, foreach) \
    CREATE_ENUM(ename, foreach) \
    CREATE_STR_ARR(ename, foreach)
#define CREATE_DIMENSIONS(ename, foreach) \
    CREATE_ENUM(ename, foreach) \
    CREATE_STR_ARR(ename, foreach) \
static char *to_str_function_##ename(uint32_t idx, uint32_t count) { assert(idx < ARRAY_SIZE(str_map_##ename)); return strdup(str_map_##ename[idx]); }
#define CREATE_NAME_MAP(name, foreach) \
static const knotd_mod_idx_to_str_f name##_map_to_str[] = { \
    foreach(COMBINE_NAME, to_str_function, COMMA_SEPARATED_P2, _) \
}; \
static const int name##_dim_size[] = { \
    foreach(COMBINE_NAME, str_map, ARRAY_SIZE_P2_COMMA, _) \
};
#else
#define CREATE_COUNTERS(ename, foreach) CREATE_ENUM(ename, foreach)
#define CREATE_DIMENSIONS(ename, foreach) CREATE_ENUM(ename, foreach)
#define CREATE_NAME_MAP(name, foreach)
#endif
//# End of DONOT MAKE CHANGES HERE TO ADD COUNTERS