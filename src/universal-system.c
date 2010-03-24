/*!
 * @todo What if all numbers are tried and still need rehash?
 *       (that means 2mld rehashes - we can live with that ;)
 */

#include "universal-system.h"

#include <limits.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

static unsigned int coefs[2][2];	// two generations, two functions

const unsigned int MAX_UINT_EXP = 32;
const unsigned long MAX_UINT_MY = 4294967295;

/*----------------------------------------------------------------------------*/

void us_generate_coefs( unsigned int *generation ) {
    generation[0] = rand() % MAX_UINT_MY;

    if (generation[0] % 2 == 0) {
        generation[0] = (generation[0] == 0) ? 1 : generation[0] - 1;
    }

    generation[1] = generation[0];
    while (generation[1] == generation[0]) {
        printf("Generating random coeficient...\n");
        generation[1] = rand() % MAX_UINT_MY;
        if (generation[1] % 2 == 0) {
            generation[1] = (generation[1] == 0) ? 1 : generation[1] - 1;
        }
    }
}

/*----------------------------------------------------------------------------*/

void us_initialize()
{
    int i;

    assert(UINT_MAX == MAX_UINT_MY);
    srand(time(NULL));

    /*
     * Initialize both generations of functions by generating random odd numbers
     */

    for (i = 0; i < 2; ++i) {
        us_generate_coefs(coefs[i]);
    }
}

/*----------------------------------------------------------------------------*/

int us_next( uint generation )
{
    // generate new coeficients for the new generation
    us_generate_coefs(coefs[generation >> 1]);
    return 0;
}

/*----------------------------------------------------------------------------*/

uint32_t us_hash( uint32_t value, unsigned int table_exp, uint c,
                  uint generation )
{
    /* multiplication should overflow if larger than MAX_UINT
       this is the same as (coef * value) mod MAX_UINT */
    assert(table_exp <= 32);
    assert(c <= 1);
    assert(generation <= 2);
    return ((coefs[generation >> 1][c] * value) >> (MAX_UINT_EXP - table_exp));
}
