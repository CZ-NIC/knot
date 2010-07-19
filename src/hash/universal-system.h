#ifndef UNIVERSAL_SYSTEM
#define UNIVERSAL_SYSTEM

#include "common.h"
#include <stdint.h>

#define US_FNC_COUNT 4

/*----------------------------------------------------------------------------*/

void us_initialize();

/*----------------------------------------------------------------------------*/
/*!
 * @brief Generates new hash functions for the given generation.
 */
int us_next( uint generation );

/*----------------------------------------------------------------------------*/

/** \bug C99 inline won't be linkable (so not exportable) without .c and has
 *       compatibility issues.
 *       Consider static inline definition in header or removing inline.
 */
uint32_t us_hash( uint32_t value, uint table_exp, uint c,
				  uint generation );

/*----------------------------------------------------------------------------*/

#endif
