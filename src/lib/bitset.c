#include "bitset.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#define WORD_SIZE 32
#define WORD_CHECK 31

static unsigned int size = 0;
//static bitset_t clear = NULL;

void BITSET_CREATE( bitset_t *bitset, unsigned int n )
{
	size = ((n >> WORD_EXP) + 1) * sizeof(uint32_t);
	*bitset = (bitset_t)malloc(size);
	//clear = (bitset_t)malloc(size);
	//memset(clear, 0, size);
}

void BITSET_DESTROY( bitset_t *bitset )
{
	assert(size > 0);
    free(*bitset);
    *bitset = NULL;
}

void BITSET_SET( bitset_t bitset, unsigned int i )
{
	assert(size > 0);
	bitset[((unsigned)i) >> WORD_EXP]
			|= (1 << (((unsigned)i) & WORD_CHECK));
}

void BITSET_UNSET( bitset_t bitset, unsigned int i )
{
	assert(size > 0);
	bitset[((unsigned)i) >> WORD_EXP]
			&= ~(1 << (((unsigned)i) & WORD_CHECK));
}

unsigned int BITSET_GET( bitset_t bitset, unsigned int i )
{
	assert(size > 0);
	return bitset[((unsigned)i) >> WORD_EXP]
		& (1 << (((unsigned)i) & WORD_CHECK));
}

unsigned int BITSET_ISSET( bitset_t bitset, unsigned int i )
{
	assert(size > 0);
	return BITSET_GET(bitset, i) != 0;
	//return 0;
}

void BITSET_CLEAR( bitset_t bitset, unsigned int n )
{
	assert(size > 0);
	memset(bitset, 0, size);
	//memcpy(bitset, clear, size);
}
