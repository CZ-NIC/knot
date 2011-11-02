/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*
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
*/

///* The whole new hash function */
//u4 jhash(register u1 *k, u4 length, u4 initval)
//{
//	register u4 a, b, c; /* the internal state */
//	u4 len;    /* how many key bytes still need mixing */

//	/* Set up the internal state */
//	len = length;
//	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
//	c = initval;         /* variable initialization of internal state */

//	/*---------------------------------------- handle most of the key */
//	while (len >= 12) {
//		a = a + (k[0] + ((u4)k[1] << 8)
//		      + ((u4)k[2] << 16) + ((u4)k[3] << 24));
//		b = b + (k[4] + ((u4)k[5] << 8)
//		      + ((u4)k[6] << 16) + ((u4)k[7] << 24));
//		c = c + (k[8] + ((u4)k[9] << 8)
//		      + ((u4)k[10] << 16) + ((u4)k[11] << 24));
//		mix(a, b, c);
//		k = k + 12;
//		len = len - 12;
//	}

//	/*------------------------------------- handle the last 11 bytes */
//	c = c + length;
//	switch (len) {           /* all the case statements fall through */
//	case 11:
//		c = c + ((u4)k[10] << 24);
//	case 10:
//		c = c + ((u4)k[9] << 16);
//	case 9 :
//		c = c + ((u4)k[8] << 8);
//		/* the first byte of c is reserved for the length */
//	case 8 :
//		b = b + ((u4)k[7] << 24);
//	case 7 :
//		b = b + ((u4)k[6] << 16);
//	case 6 :
//		b = b + ((u4)k[5] << 8);
//	case 5 :
//		b = b + k[4];
//	case 4 :
//		a = a + ((u4)k[3] << 24);
//	case 3 :
//		a = a + ((u4)k[2] << 16);
//	case 2 :
//		a = a + ((u4)k[1] << 8);
//	case 1 :
//		a = a + k[0];
//		/* case 0: nothing left to add */
//	}
//	mix(a, b, c);
//	/*-------------------------------------------- report the result */
//	return c;
//}



#define hashsize(n) ((ub4)1<<(n))
#define hashmask(n) (hashsize(n)-1)

/*
--------------------------------------------------------------------
mix -- mix 3 32-bit values reversibly.
For every delta with one or two bits set, and the deltas of all three
  high bits or all three low bits, whether the original value of a,b,c
  is almost all zero or is uniformly distributed,
* If mix() is run forward or backward, at least 32 bits in a,b,c
  have at least 1/4 probability of changing.
* If mix() is run forward, every bit of c will change between 1/3 and
  2/3 of the time.  (Well, 22/100 and 78/100 for some 2-bit deltas.)
mix() was built out of 36 single-cycle latency instructions in a 
  structure that could supported 2x parallelism, like so:
      a -= b; 
      a -= c; x = (c>>13);
      b -= c; a ^= x;
      b -= a; x = (a<<8);
      c -= a; b ^= x;
      c -= b; x = (b>>13);
      ...
  Unfortunately, superscalar Pentiums and Sparcs can't take advantage 
  of that parallelism.  They've also turned some of those single-cycle
  latency instructions into multi-cycle latency instructions.  Still,
  this is the fastest good hash I could find.  There were about 2^^68
  to choose from.  I only looked at a billion or so.
--------------------------------------------------------------------
*/
#define mix(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

/*
--------------------------------------------------------------------
hash() -- hash a variable-length key into a 32-bit value
  k       : the key (the unaligned variable-length array of bytes)
  len     : the length of the key, counting by bytes
  initval : can be any 4-byte value
Returns a 32-bit value.  Every bit of the key affects every bit of
the return value.  Every 1-bit and 2-bit delta achieves avalanche.
About 6*len+35 instructions.

The best hash table sizes are powers of 2.  There is no need to do
mod a prime (mod is sooo slow!).  If you need less than 32 bits,
use a bitmask.  For example, if you need only 10 bits, do
  h = (h & hashmask(10));
In which case, the hash table should have hashsize(10) elements.

If you are hashing n strings (ub1 **)k, do it like this:
  for (i=0, h=0; i<n; ++i) h = hash( k[i], len[i], h);

By Bob Jenkins, 1996.  bob_jenkins@burtleburtle.net.  You may use this
code any way you wish, private, educational, or commercial.  It's free.

See http://burtleburtle.net/bob/hash/evahash.html
Use for hash table lookup, or anything where one collision in 2^^32 is
acceptable.  Do NOT use for cryptographic purposes.
--------------------------------------------------------------------
*/

ub4 jhash(k, length, initval)
register ub1 *k;        /* the key */
register ub4  length;   /* the length of the key */
register ub4  initval;  /* the previous hash, or an arbitrary value */
{
   register ub4 a,b,c,len;

   /* Set up the internal state */
   len = length;
   a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
   c = initval;         /* the previous hash value */

   /*---------------------------------------- handle most of the key */
   while (len >= 12)
   {
      a += (k[0] +((ub4)k[1]<<8) +((ub4)k[2]<<16) +((ub4)k[3]<<24));
      b += (k[4] +((ub4)k[5]<<8) +((ub4)k[6]<<16) +((ub4)k[7]<<24));
      c += (k[8] +((ub4)k[9]<<8) +((ub4)k[10]<<16)+((ub4)k[11]<<24));
      mix(a,b,c);
      k += 12; len -= 12;
   }

   /*------------------------------------- handle the last 11 bytes */
   c += length;
   switch(len)              /* all the case statements fall through */
   {
   case 11: c+=((ub4)k[10]<<24);
   case 10: c+=((ub4)k[9]<<16);
   case 9 : c+=((ub4)k[8]<<8);
      /* the first byte of c is reserved for the length */
   case 8 : b+=((ub4)k[7]<<24);
   case 7 : b+=((ub4)k[6]<<16);
   case 6 : b+=((ub4)k[5]<<8);
   case 5 : b+=k[4];
   case 4 : a+=((ub4)k[3]<<24);
   case 3 : a+=((ub4)k[2]<<16);
   case 2 : a+=((ub4)k[1]<<8);
   case 1 : a+=k[0];
     /* case 0: nothing left to add */
   }
   mix(a,b,c);
   /*-------------------------------------------- report the result */
   return c;
}

#undef hashsize
#undef hashmask

