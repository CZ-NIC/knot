/* ***************************************************************************** */
/* Copyright:      Francois Panneton and Pierre L'Ecuyer, University of Montreal */
/*                 Makoto Matsumoto, Hiroshima University                        */
/* Notice:         This code can be used freely for personal, academic,          */
/*                 or non-commercial purposes. For commercial purposes,          */
/*                 please contact P. L'Ecuyer at: lecuyer@iro.UMontreal.ca       */
/* ***************************************************************************** */

rngstate_t* InitWELLRNG1024a (unsigned *init);
double WELLRNG1024a (rngstate_t* s);

/*!
 * \brief Get pseudorandom number from PRNG initialized in thread-local storage.
 *
 * No need for initialization, TLS will take care of it.
 *
 * \retval Pseudorandom number.
 */
double tls_rand();

/*!
 * \brief Set PRNG seed in thread-local storage to requested value.
 *
 * Seed is 4 * 32 bytes wide.
 */
void tls_seed_set(unsigned init[32]);
