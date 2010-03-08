#ifndef UNIVERSAL_SYSTEM
#define UNIVERSAL_SYSTEM

#include "common.h"
#include <stdint.h>

/*----------------------------------------------------------------------------*/

void us_generate_coefs( unsigned int *generation );

/*----------------------------------------------------------------------------*/

void us_initialize();

/*----------------------------------------------------------------------------*/

int us_next( uint generation );

/*----------------------------------------------------------------------------*/

inline uint32_t us_hash( uint32_t value, unsigned int table_exp, uint c,
                         uint generation );

/*----------------------------------------------------------------------------*/

#endif
