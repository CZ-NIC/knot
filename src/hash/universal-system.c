/*!
 * @file universal-system.c
 *
 * @todo What if all numbers are tried and still need rehash?
 *       (that means 2mld rehashes - we can live with that ;)
 * @todo Consider counting generations from 0, will be easier!
 */

#include "universal-system.h"

#include <limits.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define GEN_COUNT 2
static uint coefs[US_FNC_COUNT * GEN_COUNT];

const uint MAX_UINT_EXP = 32;
const unsigned long MAX_UINT_MY = 4294967295;

/*----------------------------------------------------------------------------*/

void us_generate_coefs( uint from, uint to ) {

	for (uint i = from; i < to; ++i) {
		int used = 0;

		do {
			// generate random odd number
			coefs[i] = rand() % MAX_UINT_MY;
			if (coefs[i] % 2 == 0) {
				coefs[i] = (coefs[i] == 0) ? 1 : coefs[i] - 1;
			}
			// check if this coeficient is already used
			uint j = from;
			while (used == 0 && j < i) {
				if (coefs[j++] == coefs[i]) {
					used = 1;
				}
			}
			// if already used, generate again
		} while (used != 0);
	}
}

/*----------------------------------------------------------------------------*/

void us_initialize()
{
	assert(UINT_MAX == MAX_UINT_MY);
    srand(time(NULL));

    /*
     * Initialize both generations of functions by generating random odd numbers
     */
	us_generate_coefs(0, US_FNC_COUNT * GEN_COUNT);
}

/*----------------------------------------------------------------------------*/
/*!
 * @note @a generation starts from 1
 */
int us_next( uint generation )
{
    // generate new coeficients for the new generation
	us_generate_coefs((generation - 1) * US_FNC_COUNT, generation * US_FNC_COUNT);
    return 0;
}

/*----------------------------------------------------------------------------*/
/*!
 * @param c Number of the hash function (0 .. US_FNC_COUNT - 1).
 * @param generation Number of the generation of functions (0 .. GEN_COUNT).
 */
uint32_t us_hash( uint32_t value, uint table_exp, uint c, uint generation )
{
    /* multiplication should overflow if larger than MAX_UINT
       this is the same as (coef * value) mod MAX_UINT */
    assert(table_exp <= 32);
	assert(c < US_FNC_COUNT);
	assert(generation <= GEN_COUNT);
	return ((coefs[(generation * (c + 1)) - 1] * value)
			>> (MAX_UINT_EXP - table_exp));
}
