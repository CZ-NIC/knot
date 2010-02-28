#ifndef BITSET
#define BITSET

#include <stdint.h>	/* uint32_t */

#define WORD_EXP 5

typedef uint32_t* bitset_t;

inline void BITSET_CREATE( bitset_t *bitset, unsigned int n );

inline void BITSET_DESTROY( bitset_t bitset );

inline void BITSET_SET( bitset_t bitset, unsigned int i );

inline void BITSET_UNSET( bitset_t bitset, unsigned int i );

inline unsigned int BITSET_GET( bitset_t bitset, unsigned int i );

inline unsigned int BITSET_ISSET( bitset_t bitset, unsigned int i );

inline void BITSET_CLEAR( bitset_t bitset, unsigned int n );

#endif /* BITSET */
