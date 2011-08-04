/*  Copyright (C) 2011 CZ.NIC Labs

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
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
u4 jhash(register u1 *k, u4 length, u4 initval)
{
	register u4 a, b, c; /* the internal state */
	u4 len;    /* how many key bytes still need mixing */

	/* Set up the internal state */
	len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* variable initialization of internal state */

	/*---------------------------------------- handle most of the key */
	while (len >= 12) {
		a = a + (k[0] + ((u4)k[1] << 8)
		      + ((u4)k[2] << 16) + ((u4)k[3] << 24));
		b = b + (k[4] + ((u4)k[5] << 8)
		      + ((u4)k[6] << 16) + ((u4)k[7] << 24));
		c = c + (k[8] + ((u4)k[9] << 8)
		      + ((u4)k[10] << 16) + ((u4)k[11] << 24));
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
