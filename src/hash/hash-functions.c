#include "hash-functions.h"

/*--------------------------------- FNV HASH ---------------------------------*/

unsigned long int fnv_hash(const char *data, int size, int bits)
{
	int shift, i;
	unsigned long int mask;
	unsigned long int hash = 2166136261;

	if (bits == -1) {
		shift = 0;
		mask = 0xFFFFFFFF;
	} else {
		shift = 32 - bits;
		mask = (1U << shift) - 1U;
	}

	for (i = 0; i < size; i++) {
		hash = (hash * 16777619) ^ data[i];
	}

	if (shift == 0) {
		return hash;
	}

	return (hash ^(hash >> shift)) & mask;
}

unsigned long int fnv_hash2(char *data, int size, int bits)
{
	int i;
	const unsigned int p = 16777619;
	unsigned long int hash = 2166136261;

	for (i = 0; i < size; i++) {
		hash = (hash ^ data[i]) * p;
	}

	hash += hash << 13;
	hash ^= hash >> 7;
	hash += hash << 3;
	hash ^= hash >> 17;
	hash += hash << 5;

	return hash;
}

/*------------------------------- JENKINS HASH -------------------------------*/

/* The mixing step */
#define mix(a,b,c) \
	{ \
		a=a-b;  a=a-c;  a=a^(c>>13); \
		b=b-c;  b=b-a;  b=b^(a<<8);  \
		c=c-a;  c=c-b;  c=c^(b>>13); \
		a=a-b;  a=a-c;  a=a^(c>>12); \
		b=b-c;  b=b-a;  b=b^(a<<16); \
		c=c-a;  c=c-b;  c=c^(b>>5);  \
		a=a-b;  a=a-c;  a=a^(c>>3);  \
		b=b-c;  b=b-a;  b=b^(a<<10); \
		c=c-a;  c=c-b;  c=c^(b>>15); \
	}

/* The whole new hash function */
u4 jhash(k, length, initval)
register u1 *k;        /* the key */
u4           length;   /* the length of the key in bytes */
u4           initval;  /* the previous hash, or an arbitrary value */
{
	register u4 a, b, c; /* the internal state */
	u4          len;    /* how many key bytes still need mixing */

	/* Set up the internal state */
	len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* variable initialization of internal state */

	/*---------------------------------------- handle most of the key */
	while (len >= 12) {
		a = a + (k[0] + ((u4)k[1] << 8) + ((u4)k[2] << 16) + ((u4)k[3] << 24));
		b = b + (k[4] + ((u4)k[5] << 8) + ((u4)k[6] << 16) + ((u4)k[7] << 24));
		c = c + (k[8] + ((u4)k[9] << 8) + ((u4)k[10] << 16) + ((u4)k[11] << 24));
		mix(a, b, c);
		k = k + 12;
		len = len - 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c = c + length;
	switch (len) {           /* all the case statements fall through */
	case 11:
		c = c + ((u4)k[10] << 24);
	case 10:
		c = c + ((u4)k[9] << 16);
	case 9 :
		c = c + ((u4)k[8] << 8);
		/* the first byte of c is reserved for the length */
	case 8 :
		b = b + ((u4)k[7] << 24);
	case 7 :
		b = b + ((u4)k[6] << 16);
	case 6 :
		b = b + ((u4)k[5] << 8);
	case 5 :
		b = b + k[4];
	case 4 :
		a = a + ((u4)k[3] << 24);
	case 3 :
		a = a + ((u4)k[2] << 16);
	case 2 :
		a = a + ((u4)k[1] << 8);
	case 1 :
		a = a + k[0];
		/* case 0: nothing left to add */
	}
	mix(a, b, c);
	/*-------------------------------------------- report the result */
	return c;
}

/*--------------------------------- SDBM HASH --------------------------------*/

unsigned long sdbm_hash(const unsigned char *key, int size)
{
	int i = 0;
	unsigned long h = 0;

	while (i < size) {
		h = key[i++] + (h << 6) + (h << 16) - h;
	}

	return h;
}

/*--------------------------------- SDBM HASH --------------------------------*/

unsigned long djb_hash(const unsigned char *key, int size)
{
	unsigned long h = 0;
	int i;

	for (i = 0; i < size; i++) {
		h = 33 * h ^ key[i];
	}

	return h;
}

/*--------------------------------- JSW HASH ---------------------------------*/

// TODO: needs table of random numbers

//unsigned long jsw_hash( const unsigned char *key, int size )
//{
//	unsigned long h = 16777551;
//	int i;
//
//	for ( i = 0; i < size; i++ )
//		h = ( h << 1 | h >> 31 ) ^ tab[key[i]];
//
//	return h;
//
//}

/*--------------------------------- ELF HASH ---------------------------------*/

unsigned long elf_hash(const unsigned char *key, int size)
{
	unsigned long h = 0, g;
	int i;

	for (i = 0; i < size; i++) {
		h = (h << 4) + key[i];
		g = h & 0xf0000000L;

		if (g != 0) {
			h ^= g >> 24;
		}

		h &= ~g;
	}

	return h;
}
