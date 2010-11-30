/*
 * zonec.c -- zone compiler.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>

#include "common.h"
#include "zonec.h"
#include "dname.h"
#include "rrset.h"
#include "rdata.h"
#include "node.h"
#include "descriptor.h"

#include "zparser.h"

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!! MASSIVE TODO move these functions to separate files 

#define IP6ADDRLEN	(128/8)

#define APL_NEGATION_MASK      0x80U

static dnslib_lookup_table_t *dnslib_lookup_by_name(dnslib_lookup_table_t *table,
					     const char *name)
{
	while (table->name != NULL) {
		if (strcasecmp(name, table->name) == 0) {
			return table;
		}
		table++;
	}

	return NULL;
}

static dnslib_lookup_table_t *dnslib_lookup_by_id(dnslib_lookup_table_t *table,
					   int id)
{
	while (table->name != NULL) {
		if (table->id == id) {
			return table;
		}
		table++;
	}

	return NULL;
}


/*!
 * \brief Strlcpy - safe string copy function, based on FreeBSD implementation.
 *
 * http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/string/
 *
 * \param dst Destination string.
 * \param src Source string.
 * \param siz How many characters to copy - 1.
 *
 * \return strlen(src), if retval >= siz, truncation occurred.
 */
static size_t strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0) {
				break;
			}
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0) {
			*d = '\0';        /* NUL-terminate dst */
		}
		while (*s++)
			;
	}

	return(s - src - 1);        /* count does not include NUL */
}

static int my_b32_pton(const char *src, uint8_t *target, size_t tsize)
{
	char ch;
	size_t p=0;

	memset(target,'\0',tsize);
	while((ch = *src++)) {
		uint8_t d;
		size_t b;
		size_t n;

		if(p+5 >= tsize*8)
		       return -1;

		if(isspace(ch))
			continue;

		if(ch >= '0' && ch <= '9')
			d=ch-'0';
		else if(ch >= 'A' && ch <= 'V')
			d=ch-'A'+10;
		else if(ch >= 'a' && ch <= 'v')
			d=ch-'a'+10;
		else
			return -1;

		b=7-p%8;
		n=p/8;

		if(b >= 4)
			target[n]|=d << (b-4);
		else {
			target[n]|=d >> (4-b);
			target[n+1]|=d << (b+4);
		}
		p+=5;
	}
	return (p+7)/8;
}

#define Assert(Cond) if (!(Cond)) abort()

static const char Base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char Pad64 = '=';

/* (From RFC1521 and draft-ietf-dnssec-secext-03.txt)
   The following encoding technique is taken from RFC 1521 by Borenstein
   and Freed.  It is reproduced here in a slightly edited form for
   convenience.

   A 65-character subset of US-ASCII is used, enabling 6 bits to be
   represented per printable character. (The extra 65th character, "=",
   is used to signify a special processing function.)

   The encoding process represents 24-bit groups of input bits as output
   strings of 4 encoded characters. Proceeding from left to right, a
   24-bit input group is formed by concatenating 3 8-bit input groups.
   These 24 bits are then treated as 4 concatenated 6-bit groups, each
   of which is translated into a single digit in the base64 alphabet.

   Each 6-bit group is used as an index into an array of 64 printable
   characters. The character referenced by the index is placed in the
   output string.

                         Table 1: The Base64 Alphabet

      Value Encoding  Value Encoding  Value Encoding  Value Encoding
          0 A            17 R            34 i            51 z
          1 B            18 S            35 j            52 0
          2 C            19 T            36 k            53 1
          3 D            20 U            37 l            54 2
          4 E            21 V            38 m            55 3
          5 F            22 W            39 n            56 4
          6 G            23 X            40 o            57 5
          7 H            24 Y            41 p            58 6
          8 I            25 Z            42 q            59 7
          9 J            26 a            43 r            60 8
         10 K            27 b            44 s            61 9
         11 L            28 c            45 t            62 +
         12 M            29 d            46 u            63 /
         13 N            30 e            47 v
         14 O            31 f            48 w         (pad) =
         15 P            32 g            49 x
         16 Q            33 h            50 y

   Special processing is performed if fewer than 24 bits are available
   at the end of the data being encoded.  A full encoding quantum is
   always completed at the end of a quantity.  When fewer than 24 input
   bits are available in an input group, zero bits are added (on the
   right) to form an integral number of 6-bit groups.  Padding at the
   end of the data is performed using the '=' character.

   Since all base64 input is an integral number of octets, only the
         -------------------------------------------------
   following cases can arise:

       (1) the final quantum of encoding input is an integral
           multiple of 24 bits; here, the final unit of encoded
	   output will be an integral multiple of 4 characters
	   with no "=" padding,
       (2) the final quantum of encoding input is exactly 8 bits;
           here, the final unit of encoded output will be two
	   characters followed by two "=" padding characters, or
       (3) the final quantum of encoding input is exactly 16 bits;
           here, the final unit of encoded output will be three
	   characters followed by one "=" padding character.
   */

int
b64_ntop(uint8_t const *src, size_t srclength, char *target, size_t targsize) {
	size_t datalength = 0;
	uint8_t input[3];
	uint8_t output[4];
	size_t i;

	while (2 < srclength) {
		input[0] = *src++;
		input[1] = *src++;
		input[2] = *src++;
		srclength -= 3;

		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
		output[3] = input[2] & 0x3f;
		Assert(output[0] < 64);
		Assert(output[1] < 64);
		Assert(output[2] < 64);
		Assert(output[3] < 64);

		if (datalength + 4 > targsize)
			return (-1);
		target[datalength++] = Base64[output[0]];
		target[datalength++] = Base64[output[1]];
		target[datalength++] = Base64[output[2]];
		target[datalength++] = Base64[output[3]];
	}

	/* Now we worry about padding. */
	if (0 != srclength) {
		/* Get what's left. */
		input[0] = input[1] = input[2] = '\0';
		for (i = 0; i < srclength; i++)
			input[i] = *src++;

		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
		Assert(output[0] < 64);
		Assert(output[1] < 64);
		Assert(output[2] < 64);

		if (datalength + 4 > targsize)
			return (-1);
		target[datalength++] = Base64[output[0]];
		target[datalength++] = Base64[output[1]];
		if (srclength == 1)
			target[datalength++] = Pad64;
		else
			target[datalength++] = Base64[output[2]];
		target[datalength++] = Pad64;
	}
	if (datalength >= targsize)
		return (-1);
	target[datalength] = '\0';	/* Returned value doesn't count \0. */
	return (datalength);
}


static int	inet_pton4 (const char *src, uint8_t *dst);
static int	inet_pton6 (const char *src, uint8_t *dst);

/*
 *
 * The definitions we might miss.
 *
 */
#ifndef NS_INT16SZ
#define	NS_INT16SZ	2
#endif

#ifndef NS_IN6ADDRSZ
#define NS_IN6ADDRSZ 16
#endif

#ifndef NS_INADDRSZ
#define NS_INADDRSZ 4
#endif

/* int
 * inet_pton(af, src, dst)
 *	convert from presentation format (which usually means ASCII printable)
 *	to network format (which is usually some kind of binary format).
 * return:
 *	1 if the address was valid for the specified address family
 *	0 if the address wasn't valid (`dst' is untouched in this case)
 *	-1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *	Paul Vixie, 1996.
 */
int
inet_pton(af, src, dst)
	int af;
	const char *src;
	void *dst;
{
	switch (af) {
	case AF_INET:
		return (inet_pton4(src, dst));
	case AF_INET6:
		return (inet_pton6(src, dst));
	default:
		errno = EAFNOSUPPORT;
		return (-1);
	}
	/* NOTREACHED */
}

/* int
 * inet_pton4(src, dst)
 *	like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *	1 if `src' is a valid dotted quad, else 0.
 * notice:
 *	does not touch `dst' unless it's returning 1.
 * author:
 *	Paul Vixie, 1996.
 */
static int
inet_pton4(src, dst)
	const char *src;
	uint8_t *dst;
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
	uint8_t tmp[NS_INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr(digits, ch)) != NULL) {
			uint32_t new = *tp * 10 + (pch - digits);

			if (new > 255)
				return (0);
			*tp = new;
			if (! saw_digit) {
				if (++octets > 4)
					return (0);
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
		} else
			return (0);
	}
	if (octets < 4)
		return (0);

	memcpy(dst, tmp, NS_INADDRSZ);
	return (1);
}

/* int
 * inet_pton6(src, dst)
 *	convert presentation level address to network order binary form.
 * return:
 *	1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *	(1) does not touch `dst' unless it's returning 1.
 *	(2) :: in a full address is silently ignored.
 * credit:
 *	inspired by Mark Andrews.
 * author:
 *	Paul Vixie, 1996.
 */
static int
inet_pton6(src, dst)
	const char *src;
	uint8_t *dst;
{
	static const char xdigits_l[] = "0123456789abcdef",
			  xdigits_u[] = "0123456789ABCDEF";
	uint8_t tmp[NS_IN6ADDRSZ], *tp, *endp, *colonp;
	const char *xdigits, *curtok;
	int ch, saw_xdigit;
	uint32_t val;

	memset((tp = tmp), '\0', NS_IN6ADDRSZ);
	endp = tp + NS_IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			}
			if (tp + NS_INT16SZ > endp)
				return (0);
			*tp++ = (uint8_t) (val >> 8) & 0xff;
			*tp++ = (uint8_t) val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) &&
		    inet_pton4(curtok, tp) > 0) {
			tp += NS_INADDRSZ;
			saw_xdigit = 0;
			break;	/* '\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + NS_INT16SZ > endp)
			return (0);
		*tp++ = (uint8_t) (val >> 8) & 0xff;
		*tp++ = (uint8_t) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	memcpy(dst, tmp, NS_IN6ADDRSZ);
	return (1);
}


#ifndef IN6ADDRSZ
#define IN6ADDRSZ   16   /* IPv6 T_AAAA */
#endif

#ifndef INT16SZ
#define INT16SZ     2    /* for systems without 16-bit ints */
#endif

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

static const char *inet_ntop4(const u_char *src, char *dst, size_t size);
static const char *inet_ntop6(const u_char *src, char *dst, size_t size);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
const char *
inet_ntop(int af, const void *src, char *dst, size_t size)
{
	switch (af) {
	case AF_INET:
		return (inet_ntop4(src, dst, size));
	case AF_INET6:
		return (inet_ntop6(src, dst, size));
	default:
		errno = EAFNOSUPPORT;
		return (NULL);
	}
	/* NOTREACHED */
}

/* const char *
 * inet_ntop4(src, dst, size)
 *	format an IPv4 address, more or less like inet_ntoa()
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a u_char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
inet_ntop4(const u_char *src, char *dst, size_t size)
{
	static const char fmt[] = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];
	int l;

	l = snprintf(tmp, size, fmt, src[0], src[1], src[2], src[3]);
	if (l <= 0 || l >= (int)size) {
		errno = ENOSPC;
		return (NULL);
	}
	strlcpy(dst, tmp, size);
	return (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
inet_ntop6(const u_char *src, char *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	char *tp, *ep;
	struct { int base, len; } best, cur;
	u_int words[IN6ADDRSZ / INT16SZ];
	int i;
	int advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + sizeof(tmp);
	for (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			if (i == best.base) {
				if (tp + 1 >= ep)
					return (NULL);
				*tp++ = ':';
			}
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0) {
			if (tp + 1 >= ep)
				return (NULL);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
			if (!inet_ntop4(src+12, tp, (size_t)(ep - tp)))
				return (NULL);
			tp += strlen(tp);
			break;
		}
		advance = snprintf(tp, ep - tp, "%x", words[i]);
		if (advance <= 0 || advance >= ep - tp)
			return (NULL);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ)) {
		if (tp + 1 >= ep)
			return (NULL);
		*tp++ = ':';
	}
	if (tp + 1 >= ep)
		return (NULL);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((size_t)(tp - tmp) > size) {
		errno = ENOSPC;
		return (NULL);
	}
	strlcpy(dst, tmp, size);
	return (dst);
}


static int b64rmap_initialized = 0;
static uint8_t b64rmap[256];

static const uint8_t b64rmap_special = 0xf0;
static const uint8_t b64rmap_end = 0xfd;
static const uint8_t b64rmap_space = 0xfe;
static const uint8_t b64rmap_invalid = 0xff;

/**
 * Initializing the reverse map is not thread safe.
 * Which is fine for NSD. For now...
 **/
static void
b64_initialize_rmap ()
{
	int i;
	char ch;

	/* Null: end of string, stop parsing */
	b64rmap[0] = b64rmap_end;

	for (i = 1; i < 256; ++i) {
		ch = (char)i;
		/* Whitespaces */
		if (isspace(ch))
			b64rmap[i] = b64rmap_space;
		/* Padding: stop parsing */
		else if (ch == Pad64)
			b64rmap[i] = b64rmap_end;
		/* Non-base64 char */
		else
			b64rmap[i] = b64rmap_invalid;
	}

	/* Fill reverse mapping for base64 chars */
	for (i = 0; Base64[i] != '\0'; ++i)
		b64rmap[(uint8_t)Base64[i]] = i;

	b64rmap_initialized = 1;
}

static int
b64_pton_do(char const *src, uint8_t *target, size_t targsize)
{
	int tarindex, state, ch;
	uint8_t ofs;

	state = 0;
	tarindex = 0;

	while (1)
	{
		ch = *src++;
		ofs = b64rmap[ch];

		if (ofs >= b64rmap_special) {
			/* Ignore whitespaces */
			if (ofs == b64rmap_space)
				continue;
			/* End of base64 characters */
			if (ofs == b64rmap_end)
				break;
			/* A non-base64 character. */
			return (-1);
		}

		switch (state) {
		case 0:
			if ((size_t)tarindex >= targsize)
				return (-1);
			target[tarindex] = ofs << 2;
			state = 1;
			break;
		case 1:
			if ((size_t)tarindex + 1 >= targsize)
				return (-1);
			target[tarindex]   |=  ofs >> 4;
			target[tarindex+1]  = (ofs & 0x0f)
						<< 4 ;
			tarindex++;
			state = 2;
			break;
		case 2:
			if ((size_t)tarindex + 1 >= targsize)
				return (-1);
			target[tarindex]   |=  ofs >> 2;
			target[tarindex+1]  = (ofs & 0x03)
						<< 6;
			tarindex++;
			state = 3;
			break;
		case 3:
			if ((size_t)tarindex >= targsize)
				return (-1);
			target[tarindex] |= ofs;
			tarindex++;
			state = 0;
			break;
		default:
			abort();
		}
	}

	/*
	 * We are done decoding Base-64 chars.  Let's see if we ended
	 * on a byte boundary, and/or with erroneous trailing characters.
	 */

	if (ch == Pad64) {		/* We got a pad char. */
		ch = *src++;		/* Skip it, get next. */
		switch (state) {
		case 0:		/* Invalid = in first position */
		case 1:		/* Invalid = in second position */
			return (-1);

		case 2:		/* Valid, means one byte of info */
			/* Skip any number of spaces. */
			for ((void)NULL; ch != '\0'; ch = *src++)
				if (b64rmap[ch] != b64rmap_space)
					break;
			/* Make sure there is another trailing = sign. */
			if (ch != Pad64)
				return (-1);
			ch = *src++;		/* Skip the = */
			/* Fall through to "single trailing =" case. */
			/* FALLTHROUGH */

		case 3:		/* Valid, means two bytes of info */
			/*
			 * We know this char is an =.  Is there anything but
			 * whitespace after it?
			 */
			for ((void)NULL; ch != '\0'; ch = *src++)
				if (b64rmap[ch] != b64rmap_space)
					return (-1);

			/*
			 * Now make sure for cases 2 and 3 that the "extra"
			 * bits that slopped past the last full byte were
			 * zeros.  If we don't check them, they become a
			 * subliminal channel.
			 */
			if (target[tarindex] != 0)
				return (-1);
		}
	} else {
		/*
		 * We ended by seeing the end of the string.  Make sure we
		 * have no partial bytes lying around.
		 */
		if (state != 0)
			return (-1);
	}

	return (tarindex);
}


static int
b64_pton_len(char const *src)
{
	int tarindex, state, ch;
	uint8_t ofs;

	state = 0;
	tarindex = 0;

	while (1)
	{
		ch = *src++;
		ofs = b64rmap[ch];

		if (ofs >= b64rmap_special) {
			/* Ignore whitespaces */
			if (ofs == b64rmap_space)
				continue;
			/* End of base64 characters */
			if (ofs == b64rmap_end)
				break;
			/* A non-base64 character. */
			return (-1);
		}

		switch (state) {
		case 0:
			state = 1;
			break;
		case 1:
			tarindex++;
			state = 2;
			break;
		case 2:
			tarindex++;
			state = 3;
			break;
		case 3:
			tarindex++;
			state = 0;
			break;
		default:
			abort();
		}
	}

	/*
	 * We are done decoding Base-64 chars.  Let's see if we ended
	 * on a byte boundary, and/or with erroneous trailing characters.
	 */

	if (ch == Pad64) {		/* We got a pad char. */
		ch = *src++;		/* Skip it, get next. */
		switch (state) {
		case 0:		/* Invalid = in first position */
		case 1:		/* Invalid = in second position */
			return (-1);

		case 2:		/* Valid, means one byte of info */
			/* Skip any number of spaces. */
			for ((void)NULL; ch != '\0'; ch = *src++)
				if (b64rmap[ch] != b64rmap_space)
					break;
			/* Make sure there is another trailing = sign. */
			if (ch != Pad64)
				return (-1);
			ch = *src++;		/* Skip the = */
			/* Fall through to "single trailing =" case. */
			/* FALLTHROUGH */

		case 3:		/* Valid, means two bytes of info */
			/*
			 * We know this char is an =.  Is there anything but
			 * whitespace after it?
			 */
			for ((void)NULL; ch != '\0'; ch = *src++)
				if (b64rmap[ch] != b64rmap_space)
					return (-1);

		}
	} else {
		/*
		 * We ended by seeing the end of the string.  Make sure we
		 * have no partial bytes lying around.
		 */
		if (state != 0)
			return (-1);
	}

	return (tarindex);
}


int
b64_pton(char const *src, uint8_t *target, size_t targsize)
{
	if (!b64rmap_initialized)
		b64_initialize_rmap ();

	if (target)
		return b64_pton_do (src, target, targsize);
	else
		return b64_pton_len (src);
}







void
set_bit(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	bits[index / 8] |= (1 << (7 - index % 8));
}

uint32_t
strtoserial(const char* nptr, const char** endptr)
{
	uint32_t i = 0;
	uint32_t serial = 0;

	for(*endptr = nptr; **endptr; (*endptr)++) {
		switch (**endptr) {
		case ' ':
		case '\t':
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			i *= 10;
			i += (**endptr - '0');
			break;
		default:
			break;
		}
	}
	serial += i;
	return serial;
}

static inline void
write_uint32(void *dst, uint32_t data)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
	* (uint32_t *) dst = htonl(data);
#else
	uint8_t *p = (uint8_t *) dst;
	p[0] = (uint8_t) ((data >> 24) & 0xff);
	p[1] = (uint8_t) ((data >> 16) & 0xff);
	p[2] = (uint8_t) ((data >> 8) & 0xff);
	p[3] = (uint8_t) (data & 0xff);
#endif
}

/* Taken from RFC 2535, section 7.  */
dnslib_lookup_table_t dns_algorithms[] = {
	{ 1, "RSAMD5" },	/* RFC 2537 */
	{ 2, "DH" },		/* RFC 2539 */
	{ 3, "DSA" },		/* RFC 2536 */
	{ 4, "ECC" },
	{ 5, "RSASHA1" },	/* RFC 3110 */
	{ 252, "INDIRECT" },
	{ 253, "PRIVATEDNS" },
	{ 254, "PRIVATEOID" },
	{ 0, NULL }
};

/* Taken from RFC 4398, section 2.1.  */
dnslib_lookup_table_t dns_certificate_types[] = {
/*	0		Reserved */
	{ 1, "PKIX" },	/* X.509 as per PKIX */
	{ 2, "SPKI" },	/* SPKI cert */
	{ 3, "PGP" },	/* OpenPGP packet */
	{ 4, "IPKIX" },	/* The URL of an X.509 data object */
	{ 5, "ISPKI" },	/* The URL of an SPKI certificate */
	{ 6, "IPGP" },	/* The fingerprint and URL of an OpenPGP packet */
	{ 7, "ACPKIX" },	/* Attribute Certificate */
	{ 8, "IACPKIX" },	/* The URL of an Attribute Certificate */
	{ 253, "URI" },	/* URI private */
	{ 254, "OID" },	/* OID private */
/*	255 		Reserved */
/* 	256-65279	Available for IANA assignment */
/*	65280-65534	Experimental */
/*	65535		Reserved */
	{ 0, NULL }
};

/* Imported from lexer. */
extern int hexdigit_to_int(char ch);

const dnslib_dname_t *error_dname;
dnslib_node_t *error_domain;

/* The database file... */
static const char *dbfile = 0;

/* Some global flags... */
static int vflag = 0;
/* if -v then print progress each 'progress' RRs */
static int progress = 10000;

/* Total errors counter */
static long int totalerrors = 0;
static long int totalrrs = 0;

extern uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE];
extern uint16_t nsec_highest_rcode;

uint32_t
strtottl(const char *nptr, const char **endptr)
{
	uint32_t i = 0;
	uint32_t seconds = 0;

	for(*endptr = nptr; **endptr; (*endptr)++) {
		switch (**endptr) {
		case ' ':
		case '\t':
			break;
		case 's':
		case 'S':
			seconds += i;
			i = 0;
			break;
		case 'm':
		case 'M':
			seconds += i * 60;
			i = 0;
			break;
		case 'h':
		case 'H':
			seconds += i * 60 * 60;
			i = 0;
			break;
		case 'd':
		case 'D':
			seconds += i * 60 * 60 * 24;
			i = 0;
			break;
		case 'w':
		case 'W':
			seconds += i * 60 * 60 * 24 * 7;
			i = 0;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			i *= 10;
			i += (**endptr - '0');
			break;
		default:
			seconds += i;
			return seconds;
		}
	}
	seconds += i;
	return seconds;
}


/*
 * Allocate SIZE+sizeof(uint16_t) bytes and store SIZE in the first
 * element.  Return a pointer to the allocation.
 */
static uint16_t *
alloc_rdata(size_t size)
{
	uint16_t *result = malloc(sizeof(uint16_t) + size);
	*result = size;
	return result;
}

uint16_t *
alloc_rdata_init(const void *data, size_t size)
{
	uint16_t *result = malloc(sizeof(uint16_t) + size);
	*result = size;
	memcpy(result + 1, data, size);
	return result;
}

/*
 * These are parser function for generic zone file stuff.
 */
uint16_t *
zparser_conv_hex(const char *hex, size_t len)
{
	/* convert a hex value to wireformat */
	uint16_t *r = NULL;
	uint8_t *t;
	int i;

	if (len % 2 != 0) {
		fprintf(stderr, "number of hex digits must be a multiple of 2");
	} else if (len > MAX_RDLENGTH * 2) {
		fprintf(stderr, "hex data exceeds maximum rdata length (%d)",
				   MAX_RDLENGTH);
	} else {
		/* the length part */

		r = alloc_rdata(len/2);

		t = (uint8_t *)(r + 1);

		/* Now process octet by octet... */
		while (*hex) {
			*t = 0;
			for (i = 16; i >= 1; i -= 15) {
				if (isxdigit((int)*hex)) {
					*t += hexdigit_to_int(*hex) * i;
				} else {
					fprintf(stderr,
						"illegal hex character '%c'",
						(int) *hex);
					return NULL;
				}
				++hex;
			}
			++t;
		}
	}
	return r;
}

/* convert hex, precede by a 1-byte length */
uint16_t *
zparser_conv_hex_length(const char *hex, size_t len)
{
	uint16_t *r = NULL;
	uint8_t *t;
	int i;
	if (len % 2 != 0) {
		fprintf(stderr, "number of hex digits must be a multiple of 2");
	} else if (len > 255 * 2) {
		fprintf(stderr, "hex data exceeds 255 bytes");
	} else {
		uint8_t *l;

		/* the length part */
		r = alloc_rdata(len/2+1);
		t = (uint8_t *)(r + 1);

		l = t++;
		*l = '\0';

		/* Now process octet by octet... */
		while (*hex) {
			*t = 0;
			for (i = 16; i >= 1; i -= 15) {
				if (isxdigit((int)*hex)) {
					*t += hexdigit_to_int(*hex) * i;
				} else {
					fprintf(stderr,
						"illegal hex character '%c'",
						(int) *hex);
					return NULL;
				}
				++hex;
			}
			++t;
			++*l;
		}
	}
	return r;
}

uint16_t *
zparser_conv_time(const char *time)
{
	/* convert a time YYHM to wireformat */
	uint16_t *r = NULL;
	struct tm tm;

	/* Try to scan the time... */
	if (!strptime(time, "%Y%m%d%H%M%S", &tm)) {
		fprintf(stderr, "date and time is expected");
	} else {
		uint32_t l = htonl(mktime_from_utc(&tm));
		r = alloc_rdata_init(&l, sizeof(l));
	}
	return r;
}

uint16_t *
zparser_conv_services(const char *protostr,
		      char *servicestr)
{
	/*
	 * Convert a protocol and a list of service port numbers
	 * (separated by spaces) in the rdata to wireformat
	 */
	uint16_t *r = NULL;
	uint8_t *p;
	uint8_t bitmap[65536/8];
	char sep[] = " ";
	char *word;
	int max_port = -8;
	/* convert a protocol in the rdata to wireformat */
	struct protoent *proto;

	memset(bitmap, 0, sizeof(bitmap));

	proto = getprotobyname(protostr);
	if (!proto) {
		proto = getprotobynumber(atoi(protostr));
	}
	if (!proto) {
		fprintf(stderr, "unknown protocol '%s'", protostr);
		return NULL;
	}

	for (word = strtok(servicestr, sep); word; word = strtok(NULL, sep)) {
		struct servent *service;
		int port;

		service = getservbyname(word, proto->p_name);
		if (service) {
			/* Note: ntohs not ntohl!  Strange but true.  */
			port = ntohs((uint16_t) service->s_port);
		} else {
			char *end;
			port = strtol(word, &end, 10);
			if (*end != '\0') {
				fprintf(stderr, "unknown service '%s' for protocol '%s'",
						   word, protostr);
				continue;
			}
		}

		if (port < 0 || port > 65535) {
			fprintf(stderr, "bad port number %d", port);
		} else {
			set_bit(bitmap, port);
			if (port > max_port)
				max_port = port;
		}
	}

	r = alloc_rdata(sizeof(uint8_t) + max_port / 8 + 1);
	p = (uint8_t *) (r + 1);
	*p = proto->p_proto;
	memcpy(p + 1, bitmap, *r);

	return r;
}

uint16_t *
zparser_conv_serial(const char *serialstr)
{
	uint16_t *r = NULL;
	uint32_t serial;
	const char *t;

	serial = strtoserial(serialstr, &t);
	if (*t != '\0') {
		fprintf(stderr, "serial is expected");
	} else {
		serial = htonl(serial);
		r = alloc_rdata_init(&serial, sizeof(serial));
	}
	return r;
}

uint16_t *
zparser_conv_period(const char *periodstr)
{
	/* convert a time period (think TTL's) to wireformat) */
	uint16_t *r = NULL;
	uint32_t period;
	const char *end;

	/* Allocate required space... */
	period = strtottl(periodstr, &end);
	if (*end != '\0') {
		fprintf(stderr, "time period is expected");
	} else {
		period = htonl(period);
		r = alloc_rdata_init(&period, sizeof(period));
	}
	return r;
}

uint16_t *
zparser_conv_short(const char *text)
{
	uint16_t *r = NULL;
	uint16_t value;
	char *end;

	value = htons((uint16_t) strtol(text, &end, 10));
	if (*end != '\0') {
		fprintf(stderr, "integer value is expected");
	} else {
		r = alloc_rdata_init(&value, sizeof(value));
	}
	return r;
}

uint16_t *
zparser_conv_byte(const char *text)
{
	uint16_t *r = NULL;
	uint8_t value;
	char *end;

	value = (uint8_t) strtol(text, &end, 10);
	if (*end != '\0') {
		fprintf(stderr, "integer value is expected");
	} else {
		r = alloc_rdata_init(&value, sizeof(value));
	}
	return r;
}

uint16_t *
zparser_conv_algorithm(const char *text)
{
	const dnslib_lookup_table_t *alg;
	uint8_t id;

	alg = dnslib_lookup_by_name(dns_algorithms, text);
	if (alg) {
		id = (uint8_t) alg->id;
	} else {
		char *end;
		id = (uint8_t) strtol(text, &end, 10);
		if (*end != '\0') {
			fprintf(stderr, "algorithm is expected");
			return NULL;
		}
	}

	return alloc_rdata_init(&id, sizeof(id));
}

uint16_t *
zparser_conv_certificate_type(const char *text)
{
	/* convert a algoritm string to integer */
	const dnslib_lookup_table_t *type;
	uint16_t id;

	type = dnslib_lookup_by_name(dns_certificate_types, text);
	if (type) {
		id = htons((uint16_t) type->id);
	} else {
		char *end;
		id = htons((uint16_t) strtol(text, &end, 10));
		if (*end != '\0') {
			fprintf(stderr, "certificate type is expected");
			return NULL;
		}
	}

	return alloc_rdata_init(&id, sizeof(id));
}

uint16_t *
zparser_conv_a(const char *text)
{
	in_addr_t address;
	uint16_t *r = NULL;

	if (inet_pton(AF_INET, text, &address) != 1) {
		fprintf(stderr, "invalid IPv4 address '%s'", text);
	} else {
		r = alloc_rdata_init(&address, sizeof(address));
	}
	return r;
}

uint16_t *
zparser_conv_aaaa(const char *text)
{
	uint8_t address[IP6ADDRLEN];
	uint16_t *r = NULL;

	if (inet_pton(AF_INET6, text, address) != 1) {
		fprintf(stderr, "invalid IPv6 address '%s'", text);
	} else {
		r = alloc_rdata_init(address, sizeof(address));
	}
	return r;
}

uint16_t *
zparser_conv_text(const char *text, size_t len)
{
	uint16_t *r = NULL;

	if (len > 255) {
		fprintf(stderr, "text string is longer than 255 characters,"
				   " try splitting it into multiple parts");
	} else {
		uint8_t *p;
		r = alloc_rdata(len + 1);
		p = (uint8_t *) (r + 1);
		*p = len;
		memcpy(p + 1, text, len);
	}
	return r;
}

uint16_t *
zparser_conv_dns_name(const uint8_t* name, size_t len)
{
	uint16_t* r = NULL;
	uint8_t* p = NULL;
	r = alloc_rdata(len);
	p = (uint8_t *) (r + 1);
	memcpy(p, name, len);

	return r;
}

uint16_t *
zparser_conv_b32(const char *b32)
{
	uint8_t buffer[B64BUFSIZE];
	uint16_t *r = NULL;
	int i;

	if(strcmp(b32, "-") == 0) {
		return alloc_rdata_init("", 1);
	}
	i = my_b32_pton(b32, buffer+1, B64BUFSIZE-1);
	if (i == -1 || i > 255) {
		fprintf(stderr, "invalid base32 data");
	} else {
		buffer[0] = i; /* store length byte */
		r = alloc_rdata_init(buffer, i+1);
	}
	return r;
}

uint16_t *
zparser_conv_b64(const char *b64)
{
	uint8_t buffer[B64BUFSIZE];
	uint16_t *r = NULL;
	int i;

	i = b64_pton(b64, buffer, B64BUFSIZE);
	if (i == -1) {
		fprintf(stderr, "invalid base64 data");
	} else {
		r = alloc_rdata_init(buffer, i);
	}
	return r;
}

uint16_t *
zparser_conv_rrtype(const char *text)
{
	uint16_t *r = NULL;
	uint16_t type = dnslib_rrtype_from_string(text);

	if (type == 0) {
		fprintf(stderr, "unrecognized RR type '%s'", text);
	} else {
		type = htons(type);
		r = alloc_rdata_init(&type, sizeof(type));
	}
	return r;
}

uint16_t *
zparser_conv_nxt(uint8_t nxtbits[])
{
	/* nxtbits[] consists of 16 bytes with some zero's in it
	 * copy every byte with zero to r and write the length in
	 * the first byte
	 */
	uint16_t i;
	uint16_t last = 0;

	for (i = 0; i < 16; i++) {
		if (nxtbits[i] != 0)
			last = i + 1;
	}

	return alloc_rdata_init(nxtbits, last);
}


/* we potentially have 256 windows, each one is numbered. empty ones
 * should be discarded
 */
uint16_t *
zparser_conv_nsec(uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE])
{
	/* nsecbits contains up to 64K of bits which represent the
	 * types available for a name. Walk the bits according to
	 * nsec++ draft from jakob
	 */
	uint16_t *r;
	uint8_t *ptr;
	size_t i,j;
	uint16_t window_count = 0;
	uint16_t total_size = 0;
	uint16_t window_max = 0;

	/* The used windows.  */
	int used[NSEC_WINDOW_COUNT];
	/* The last byte used in each the window.  */
	int size[NSEC_WINDOW_COUNT];

	window_max = 1 + (nsec_highest_rcode / 256);

	/* used[i] is the i-th window included in the nsec
	 * size[used[0]] is the size of window 0
	 */

	/* walk through the 256 windows */
	for (i = 0; i < window_max; ++i) {
		int empty_window = 1;
		/* check each of the 32 bytes */
		for (j = 0; j < NSEC_WINDOW_BITS_SIZE; ++j) {
			if (nsecbits[i][j] != 0) {
				size[i] = j + 1;
				empty_window = 0;
			}
		}
		if (!empty_window) {
			used[window_count] = i;
			window_count++;
		}
	}

	for (i = 0; i < window_count; ++i) {
		total_size += sizeof(uint16_t) + size[used[i]];
	}

	r = alloc_rdata(total_size);
	ptr = (uint8_t *) (r + 1);

	/* now walk used and copy it */
	for (i = 0; i < window_count; ++i) {
		ptr[0] = used[i];
		ptr[1] = size[used[i]];
		memcpy(ptr + 2, &nsecbits[used[i]], size[used[i]]);
		ptr += size[used[i]] + 2;
	}

	return r;
}

/* Parse an int terminated in the specified range. */
static int
parse_int(const char *str,
	  char **end,
	  int *result,
	  const char *name,
	  int min,
	  int max)
{
	*result = (int) strtol(str, end, 10);
	if (*result < min || *result > max) {
		fprintf(stderr, "%s must be within the range [%d .. %d]",
				   name,
				   min,
				   max);
		return 0;
	} else {
		return 1;
	}
}

/* RFC1876 conversion routines */
static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
				1000000,10000000,100000000,1000000000};

/*
 * Converts ascii size/precision X * 10**Y(cm) to 0xXY.
 * Sets the given pointer to the last used character.
 *
 */
static uint8_t
precsize_aton (char *cp, char **endptr)
{
	unsigned int mval = 0, cmval = 0;
	uint8_t retval = 0;
	int exponent;
	int mantissa;

	while (isdigit((int)*cp))
		mval = mval * 10 + hexdigit_to_int(*cp++);

	if (*cp == '.') {	/* centimeters */
		cp++;
		if (isdigit((int)*cp)) {
			cmval = hexdigit_to_int(*cp++) * 10;
			if (isdigit((int)*cp)) {
				cmval += hexdigit_to_int(*cp++);
			}
		}
	}

	if(mval >= poweroften[7]) {
		/* integer overflow possible for *100 */
		mantissa = mval / poweroften[7];
		exponent = 9; /* max */
	}
	else {
		cmval = (mval * 100) + cmval;

		for (exponent = 0; exponent < 9; exponent++)
			if (cmval < poweroften[exponent+1])
				break;

		mantissa = cmval / poweroften[exponent];
	}
	if (mantissa > 9)
		mantissa = 9;

	retval = (mantissa << 4) | exponent;

	if (*cp == 'm') cp++;

	*endptr = cp;

	return (retval);
}

/*
 * Parses a specific part of rdata.
 *
 * Returns:
 *
 *	number of elements parsed
 *	zero on error
 *
 */
uint16_t *
zparser_conv_loc(char *str)
{
	uint16_t *r;
	uint32_t *p;
	int i;
	int deg, min, secs;	/* Secs is stored times 1000.  */
	uint32_t lat = 0, lon = 0, alt = 0;
	/* encoded defaults: version=0 sz=1m hp=10000m vp=10m */
	uint8_t vszhpvp[4] = {0, 0x12, 0x16, 0x13};
	char *start;
	double d;

	for(;;) {
		deg = min = secs = 0;

		/* Degrees */
		if (*str == '\0') {
			fprintf(stderr, "unexpected end of LOC data");
			return NULL;
		}

		if (!parse_int(str, &str, &deg, "degrees", 0, 180))
			return NULL;
		if (!isspace((int)*str)) {
			fprintf(stderr, "space expected after degrees");
			return NULL;
		}
		++str;

		/* Minutes? */
		if (isdigit((int)*str)) {
			if (!parse_int(str, &str, &min, "minutes", 0, 60))
				return NULL;
			if (!isspace((int)*str)) {
				fprintf(stderr, "space expected after minutes");
				return NULL;
			}
			++str;
		}

		/* Seconds? */
		if (isdigit((int)*str)) {
			start = str;
			if (!parse_int(str, &str, &i, "seconds", 0, 60)) {
				return NULL;
			}

			if (*str == '.' && !parse_int(str + 1, &str, &i, "seconds fraction", 0, 999)) {
				return NULL;
			}

			if (!isspace((int)*str)) {
				fprintf(stderr, "space expected after seconds");
				return NULL;
			}

			if (sscanf(start, "%lf", &d) != 1) {
				fprintf(stderr, "error parsing seconds");
			}

			if (d < 0.0 || d > 60.0) {
				fprintf(stderr, "seconds not in range 0.0 .. 60.0");
			}

			secs = (int) (d * 1000.0 + 0.5);
			++str;
		}

		switch(*str) {
		case 'N':
		case 'n':
			lat = ((uint32_t)1<<31) + (deg * 3600000 + min * 60000 + secs);
			break;
		case 'E':
		case 'e':
			lon = ((uint32_t)1<<31) + (deg * 3600000 + min * 60000 + secs);
			break;
		case 'S':
		case 's':
			lat = ((uint32_t)1<<31) - (deg * 3600000 + min * 60000 + secs);
			break;
		case 'W':
		case 'w':
			lon = ((uint32_t)1<<31) - (deg * 3600000 + min * 60000 + secs);
			break;
		default:
			fprintf(stderr, "invalid latitude/longtitude: '%c'", *str);
			return NULL;
		}
		++str;

		if (lat != 0 && lon != 0)
			break;

		if (!isspace((int)*str)) {
			fprintf(stderr, "space expected after latitude/longitude");
			return NULL;
		}
		++str;
	}

	/* Altitude */
	if (*str == '\0') {
		fprintf(stderr, "unexpected end of LOC data");
		return NULL;
	}

	if (!isspace((int)*str)) {
		fprintf(stderr, "space expected before altitude");
		return NULL;
	}
	++str;

	start = str;

	/* Sign */
	if (*str == '+' || *str == '-') {
		++str;
	}

	/* Meters of altitude... */
	(void) strtol(str, &str, 10);
	switch(*str) {
	case ' ':
	case '\0':
	case 'm':
		break;
	case '.':
		if (!parse_int(str + 1, &str, &i, "altitude fraction", 0, 99)) {
			return NULL;
		}
		if (!isspace((int)*str) && *str != '\0' && *str != 'm') {
			fprintf(stderr, "altitude fraction must be a number");
			return NULL;
		}
		break;
	default:
		fprintf(stderr, "altitude must be expressed in meters");
		return NULL;
	}
	if (!isspace((int)*str) && *str != '\0')
		++str;

	if (sscanf(start, "%lf", &d) != 1) {
		fprintf(stderr, "error parsing altitude");
	}

	alt = (uint32_t) (10000000.0 + d * 100 + 0.5);

	if (!isspace((int)*str) && *str != '\0') {
		fprintf(stderr, "unexpected character after altitude");
		return NULL;
	}

	/* Now parse size, horizontal precision and vertical precision if any */
	for(i = 1; isspace((int)*str) && i <= 3; i++) {
		vszhpvp[i] = precsize_aton(str + 1, &str);

		if (!isspace((int)*str) && *str != '\0') {
			fprintf(stderr, "invalid size or precision");
			return NULL;
		}
	}

	/* Allocate required space... */
	r = alloc_rdata(16);
	p = (uint32_t *) (r + 1);

	memmove(p, vszhpvp, 4);
	write_uint32(p + 1, lat);
	write_uint32(p + 2, lon);
	write_uint32(p + 3, alt);

	return r;
}

/*
 * Convert an APL RR RDATA element.
 */
uint16_t *
zparser_conv_apl_rdata(char *str)
{
	int negated = 0;
	uint16_t address_family;
	uint8_t prefix;
	uint8_t maximum_prefix;
	uint8_t length;
	uint8_t address[IP6ADDRLEN];
	char *colon = strchr(str, ':');
	char *slash = strchr(str, '/');
	int af;
	int rc;
	uint16_t rdlength;
	uint16_t *r;
	uint8_t *t;
	char *end;
	long p;

	if (!colon) {
		fprintf(stderr, "address family separator is missing");
		return NULL;
	}
	if (!slash) {
		fprintf(stderr, "prefix separator is missing");
		return NULL;
	}

	*colon = '\0';
	*slash = '\0';

	if (*str == '!') {
		negated = 1;
		++str;
	}

	if (strcmp(str, "1") == 0) {
		address_family = htons(1);
		af = AF_INET;
		length = sizeof(in_addr_t);
		maximum_prefix = length * 8;
	} else if (strcmp(str, "2") == 0) {
		address_family = htons(2);
		af = AF_INET6;
		length = IP6ADDRLEN;
		maximum_prefix = length * 8;
	} else {
		fprintf(stderr, "invalid address family '%s'", str);
		return NULL;
	}

	rc = inet_pton(af, colon + 1, address);
	if (rc == 0) {
		fprintf(stderr, "invalid address '%s'", colon + 1);
		return NULL;
	} else if (rc == -1) {
		fprintf(stderr, "inet_pton failed: %s", strerror(errno));
		return NULL;
	}

	/* Strip trailing zero octets.	*/
	while (length > 0 && address[length - 1] == 0)
		--length;


	p = strtol(slash + 1, &end, 10);
	if (p < 0 || p > maximum_prefix) {
		fprintf(stderr, "prefix not in the range 0 .. %d", maximum_prefix);
		return NULL;
	} else if (*end != '\0') {
		fprintf(stderr, "invalid prefix '%s'", slash + 1);
		return NULL;
	}
	prefix = (uint8_t) p;

	rdlength = (sizeof(address_family) + sizeof(prefix) + sizeof(length)
		    + length);
	r = alloc_rdata(rdlength);
	t = (uint8_t *) (r + 1);

	memcpy(t, &address_family, sizeof(address_family));
	t += sizeof(address_family);
	memcpy(t, &prefix, sizeof(prefix));
	t += sizeof(prefix);
	memcpy(t, &length, sizeof(length));
	if (negated) {
		*t |= APL_NEGATION_MASK;
	}
	t += sizeof(length);
	memcpy(t, address, length);

	return r;
}

/*
 * Below some function that also convert but not to wireformat
 * but to "normal" (int,long,char) types
 */

uint32_t
zparser_ttl2int(const char *ttlstr, int* error)
{
	/* convert a ttl value to a integer
	 * return the ttl in a int
	 * -1 on error
	 */

	uint32_t ttl;
	const char *t;

	ttl = strtottl(ttlstr, &t);
	if (*t != 0) {
		fprintf(stderr, "invalid TTL value: %s",ttlstr);
		*error = 1;
	}

	return ttl;
}


//RDATAADD

void
zadd_rdata_wireformat(uint16_t *data)
{
/*	if (parser->current_rrset.rdata_count >= MAXRDATALEN) {
		fprintf(stderr, "too many rdata elements");
	} else {*/
	dnslib_rdata_item_t *item = malloc(sizeof(dnslib_rdata_item_t));
	item->raw_data = (uint8_t*)data;
	dnslib_rdata_set_items(parser->current_rrset.rdata, item, 1);
}

/**
 * Used for TXT RR's to grow with undefined number of strings.
 */
void
zadd_rdata_txt_wireformat(uint16_t *data, int first)
{
//	dnslib_rdata_item_t *rd;
//
//	/* First STR in str_seq, allocate 65K in first unused rdata
//	 * else find last used rdata */
//	if (first) {
//		rd = &parser->current_rr.rdatas[parser->current_rr.rdata_count];
//		if ((rd->data = (uint16_t *) region_alloc(parser->rr_region,
//			sizeof(uint16_t) + 65535 * sizeof(uint8_t))) == NULL) {
//			fprintf(stderr, "Could not allocate memory for TXT RR");
//			return;
//		}
//		parser->current_rr.rdata_count++;
//		rd->data[0] = 0;
//	}
//	else
//		rd = &parser->current_rr.rdatas[parser->current_rr.rdata_count-1];
//
//	if ((size_t)rd->data[0] + (size_t)data[0] > 65535) {
//		fprintf(stderr, "too large rdata element");
//		return;
//	}
//
//	memcpy((uint8_t *)rd->data + 2 + rd->data[0], data + 1, data[0]);
//	rd->data[0] += data[0];
}

/**
 * Clean up after last call of zadd_rdata_txt_wireformat
 */
void
zadd_rdata_txt_clean_wireformat()
{
//	uint16_t *tmp_data;
//	rdata_atom_type *rd = &parser->current_rr.rdatas[parser->current_rr.rdata_count-1];
//	if ((tmp_data = (uint16_t *) region_alloc(parser->region,
//		rd->data[0] + 2)) != NULL) {
//		memcpy(tmp_data, rd->data, rd->data[0] + 2);
//		rd->data = tmp_data;
//	}
//	else {
//		/* We could not get memory in non-volatile region */
//		fprintf(stderr, "could not allocate memory for rdata");
//		return;
//	}
}

void
zadd_rdata_domain(dnslib_dname_t *domain)
{
//	if (parser->current_rr.rdata_count >= MAXRDATALEN) {
//		fprintf(stderr, "too many rdata elements");
//	} else {

//	dnslib_item_t *item = malloc(sizeof(dnslib_item_t));
//	item->dname = data;
//	dnslib_rdata_set_items(parser->current_rrset->rdata, items);
//
//		parser->current_rr.rdatas[parser->current_rr.rdata_count].domain
//			= domain;
//		++parser->current_rr.rdata_count;
//	}
}

void
parse_unknown_rdata(uint16_t type, uint16_t *wireformat)
{
//	buffer_type packet;
//	uint16_t size;
//	ssize_t rdata_count;
//	ssize_t i;
//	rdata_atom_type *rdatas;
//
//	if (wireformat) {
//		size = *wireformat;
//	} else {
//		return;
//	}
//
//	buffer_create_from(&packet, wireformat + 1, *wireformat);
//	rdata_count = rdata_wireformat_to_rdata_atoms(parser->region,
//						      parser->db->domains,
//						      type,
//						      size,
//						      &packet,
//						      &rdatas);
//	if (rdata_count == -1) {
//		fprintf(stderr, "bad unknown RDATA");
//		return;
//	}
//
//	for (i = 0; i < rdata_count; ++i) {
//		if (rdata_atom_is_domain(type, i)) {
//			zadd_rdata_domain(rdatas[i].domain);
//		} else {
//			zadd_rdata_wireformat(rdatas[i].data);
//		}
//	}
}


/*
 * Compares two rdata arrays.
 *
 * Returns:
 *
 *	zero if they are equal
 *	non-zero if not
 *
 */

// XXX we have dnslib_rdata_compare, but it is not working yet

//static int
//zrdatacmp(uint16_t type, rr_type *a, rr_type *b)
//{
//	int i = 0;
//
//	assert(a);
//	assert(b);
//
//	/* One is shorter than another */
//	if (a->rdata_count != b->rdata_count)
//		return 1;
//
//	/* Compare element by element */
//	for (i = 0; i < a->rdata_count; ++i) {
//		if (rdata_atom_is_domain(type, i)) {
//			if (rdata_atom_domain(a->rdatas[i])
//			    != rdata_atom_domain(b->rdatas[i]))
//			{
//				return 1;
//			}
//		} else {
//			if (rdata_atom_size(a->rdatas[i])
//			    != rdata_atom_size(b->rdatas[i]))
//			{
//				return 1;
//			}
//			if (memcmp(rdata_atom_data(a->rdatas[i]),
//				   rdata_atom_data(b->rdatas[i]),
//				   rdata_atom_size(a->rdatas[i])) != 0)
//			{
//				return 1;
//			}
//		}
//	}
//
//	/* Otherwise they are equal */
//	return 0;
//}

/*
 *
 * Opens a zone file.
 *
 * Returns:
 *
 *	- pointer to the parser structure
 *	- NULL on error and errno set
 *
 */
//static int
//zone_open(const char *filename, uint32_t ttl, uint16_t klass,
//	  const dname_type *origin)
//{
//	/* Open the zone file... */
//	if (strcmp(filename, "-") == 0) {
//		yyin = stdin;
//		filename = "<stdin>";
//	} else if (!(yyin = fopen(filename, "r"))) {
//		return 0;
//	}
//
//	/* Open the network database */
//	setprotoent(1);
//	setservent(1);
//
//	zparser_init(filename, ttl, klass, origin);
//
//	return 1;
//}


void
set_bitnsec(uint8_t bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
	    uint16_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	uint8_t window = index / 256;
	uint8_t bit = index % 256;

	bits[window][bit / 8] |= (1 << (7 - bit % 8));
}

int
process_rr(void)
{
	zdb_zone_t *zone = parser->current_zone;
	dnslib_rrset_t *current_rrset = &parser->current_rrset;
	dnslib_rrset_t *rrset;
	size_t max_rdlength;
	int i;
	dnslib_rrtype_descriptor_t *descriptor
		= dnslib_rrtype_descriptor_by_type(current_rrset->type);

	/* We only support IN class */
	if (current_rrset->rclass != DNSLIB_CLASS_IN) {
		fprintf(stderr, "only class IN is supported");
		return 0;
	}

	/* Make sure the maximum RDLENGTH does not exceed 65535 bytes.	*/
//	max_rdlength = rdata_maximum_wireformat_size(
//		descriptor, rr->rdata_count, rr->rdatas);

//	if (max_rdlength > MAX_RDLENGTH) {
//		fprintf(stderr, "maximum rdata length exceeds %d octets", MAX_RDLENGTH);
//		return 0;
//	}

	/* Do we have the zone already? */
	if (!zone)
	{
//		zone = (zdb_zone_t*) region_alloc(parser->region,
//							  sizeof(zdb_zone_t));

		//we still have zones from lnds...

		//our apex should also be SOA
		zone->apex = parser->default_apex;
//		zone->soa_rrset = NULL;
//		zone->soa_nx_rrset = NULL;
//		zone->ns_rrset = NULL;
//		zone->opts = NULL;
//		zone->is_secure = 0;
//		zone->updated = 1;

//XXX		zone->next = parser->db->zones;
//		parser->db->zones = zone;
		parser->current_zone = zone;
	}

	if (current_rrset->type == DNSLIB_RRTYPE_SOA) {
		/*
		 * This is a SOA record, start a new zone or continue
		 * an existing one.
		 */
		if (1==2)// (current_rrset->owner->is_apex) // this will not work, have to rethink
			//NSD's owner is of "our" node type
			//I'd say a global variable, soa_encountered or smth will work
			//without messing up our structures.
			fprintf(stderr, "this SOA record was already encountered");
		else if (current_rrset->owner == parser->default_apex) {
//XXX there is no such link in our structure			zone->apex = current_rrset->owner;
//			current_rrset->owner->is_apex = 1;
		}

		/* parser part */
		parser->current_zone = zone;
	}

/*	if (!dname_is_subdomain(domain_dname(rr->owner),
				domain_dname(zone->apex)))
	{
		fprintf(stderr, "out of zone data");
		return 0;
	}*/ //this does not have to be here for the time being

	/* Do we have this type of rrset already? */
	dnslib_node_t *node;
	node = zdb_find_name_in_zone(zone, current_rrset->owner); //XXX
	// check if node != NULL, else add then add rrset
	rrset = dnslib_node_get_rrset(node, current_rrset->type);
	if (!rrset) {
		rrset = dnslib_rrset_new(current_rrset->owner, current_rrset->type,
				current_rrset->rclass, current_rrset->ttl);

//		rrset->zone = zone;
		rrset->rdata = dnslib_rdata_new();
		//TODO create item, add it to the set


		/* Add it */
		dnslib_node_add_rrset(node, rrset);
	} else {
		if (current_rrset->type !=
			DNSLIB_RRTYPE_RRSIG && rrset->ttl !=
			current_rrset->ttl) {
			fprintf(stderr,
				"TTL does not match the TTL of the RRset");
		}

//		/* Search for possible duplicates... */
//		for (i = 0; i < rrset->rr_count; i++) {
//			if (!zrdatacmp(rr->type, rr, &rrset->rrs[i])) {
//				break;
//			}
//		}
//
//		/* Discard the duplicates... */
//		if (i < rrset->rr_count) {
//			return 0;
//		}

		/* Add it... */
//		rrset->rrs = (rr_type *) xrealloc(
//			rrset->rrs,
//			(rrset->rr_count + 1) * sizeof(rr_type));
//		rrset->rrs[rrset->rr_count] = *rr;
//		++rrset->rr_count;



		// TODO create item, add it to the rrset

	}

//	if(current_rrset->type == TYPE_DNAME && rrset->rr_count > 1) {
//		fprintf(stderr, "multiple DNAMEs at the same name");
//	}
//	if(current_rrset->type == TYPE_CNAME && rrset->rr_count > 1) {
//		fprintf(stderr, "multiple CNAMEs at the same name");
//	}
//	if((rr->type == TYPE_DNAME && domain_find_rrset(rr->owner, zone, TYPE_CNAME))
//	 ||(rr->type == TYPE_CNAME && domain_find_rrset(rr->owner, zone, TYPE_DNAME))) {
//		fprintf(stderr, "DNAME and CNAME at the same name");
//	}
//	if(domain_find_rrset(rr->owner, zone, TYPE_CNAME) &&
//		domain_find_non_cname_rrset(rr->owner, zone)) {
//		fprintf(stderr, "CNAME and other data at the same name");
//	}
//
//	if (rr->type == TYPE_RRSIG && rr_rrsig_type_covered(rr) == TYPE_SOA) {
//		rrset->zone->is_secure = 1;
//	}

	/* Check we have SOA */
//	if (zone->soa_rrset == NULL) {
//		if (rr->type == TYPE_SOA) {
//			if (rr->owner != zone->apex) {
//				fprintf(stderr,
//					"SOA record with invalid domain name");
//			} else {
//				zone->soa_rrset = rrset;
//			}
//		}
//	}
//	else if (rr->type == TYPE_SOA) {
//		fprintf(stderr, "duplicate SOA record discarded");
//		--rrset->rr_count;
//	}
//
//	/* Is this a zone NS? */
//	if (rr->type == TYPE_NS && rr->owner == zone->apex) {
//		zone->ns_rrset = rrset;
//	}
	if (vflag > 1 && totalrrs > 0 && (totalrrs % progress == 0)) {
		fprintf(stdout, "%ld\n", totalrrs);
	}
	++totalrrs;
	return 1;
}

/*
 * Find rrset type for any zone
 */
//static rrset_type*
//domain_find_rrset_any(domain_type *domain, uint16_t type)
//{
//	rrset_type *result = domain->rrsets;
//	while (result) {
//		if (rrset_rrtype(result) == type) {
//			return result;
//		}
//		result = result->next;
//	}
//	return NULL;
//}

/*
 * Check for DNAME type. Nothing is allowed below it
 */
//static void
//check_dname(namedb_type* db)
//{
//	domain_type* domain;
//	RBTREE_FOR(domain, domain_type*, db->domains->names_to_domains)
//	{
//		if(domain->is_existing) {
//			/* there may not be DNAMEs above it */
//			domain_type* parent = domain->parent;
//#ifdef NSEC3
//			if(domain_has_only_NSEC3(domain, NULL))
//				continue;
//#endif
//			while(parent) {
//				if(domain_find_rrset_any(parent, TYPE_DNAME)) {
//					fprintf(stderr, "While checking node %s,",
//						dname_to_string(domain_dname(domain), NULL));
//					fprintf(stderr, "DNAME at %s has data below it. "
//						"This is not allowed (rfc 2672).",
//						dname_to_string(domain_dname(parent), NULL));
//					exit(1);
//				}
//				parent = parent->parent;
//			}
//		}
//	}
//}

/*
 * Reads the specified zone into the memory
 * nsd_options can be NULL if no config file is passed.
 *
 */
static void
zone_read(const char *name, const char *zonefile, nsd_options_t* nsd_options)
{
	const dnslib_dname_t *dname;

//	dname = dname_parse(parser->region, name);
	
	dname = dnslib_dname_new_from_str(name, strlen(name), NULL);

	if (!dname) {
		fprintf(stderr, "incorrect zone name '%s'", name);
		return;
	}

//#ifndef ROOT_SERVER
//	/* Is it a root zone? Are we a root server then? Idiot proof. */
//	if (dname->label_count == 1) {
//		fprintf(stderr, "not configured as a root server");
//		return;
//	}
//#endif
//
	/* Open the zone file */
	if (!zone_open(zonefile, 3600, CLASS_IN, dname)) {
//		if(nsd_options) {
//			/* check for secondary zone, they can start with no zone info */
//			zone_options_t* zopt = zone_options_find(nsd_options, dname);
//			if(zopt && zone_is_slave(zopt)) {
//				zc_warning("slave zone %s with no zonefile '%s'(%s) will "
//					"force zone transfer.",
//					name, zonefile, strerror(errno));
//				return;
//			}
//		}
//		/* cannot happen with stdin - so no fix needed for zonefile */
		fprintf(stderr, "cannot open '%s': %s", zonefile, strerror(errno));
		return;
	}
//
//	/* Parse and process all RRs.  */
	yyparse();
//
//	/* check if zone file contained a correct SOA record */
//	if (parser->current_zone && parser->current_zone->soa_rrset
//		&& parser->current_zone->soa_rrset->rr_count!=0)
//	{
//		if(dname_compare(domain_dname(
//			parser->current_zone->soa_rrset->rrs[0].owner),
//			dname) != 0) {
//			fprintf(stderr, "zone configured as '%s', but SOA has owner '%s'.",
//				name, dname_to_string(
//				domain_dname(parser->current_zone->
//				soa_rrset->rrs[0].owner), NULL));
//		}
//	}
//
	fclose(yyin);
//
//	fflush(stdout);
	totalerrors += parser->errors;
//	parser->filename = NULL;
//}

int
main (int argc, char **argv)
{
//	struct namedb *db;
	zdb_database_t *db;
	char *origin = NULL;
	int c;
//	region_type *global_region;
//	region_type *rr_region;
//	const char* configfile= CONFIGFILE;
//	const char* zonesdir = NULL;
//	const char* singlefile = NULL;
//	nsd_options_t* nsd_options = NULL;
//
//	log_init("zonec");
//
//	global_region = region_create(xalloc, free);
//	rr_region = region_create(xalloc, free);
//	totalerrors = 0;
//
//	/* Parse the command line... */
//	while ((c = getopt(argc, argv, "d:f:vhCF:L:o:c:z:")) != -1) {
//		switch (c) {
//		case 'c':
//			configfile = optarg;
//			break;
//		case 'v':
//			++vflag;
//			break;
//		case 'f':
//			dbfile = optarg;
//			break;
//		case 'd':
//			zonesdir = optarg;
//			break;
//		case 'C':
//			configfile = 0;
//			break;
//#ifndef NDEBUG
//		case 'F':
//			sscanf(optarg, "%x", &nsd_debug_facilities);
//			break;
//		case 'L':
//			sscanf(optarg, "%d", &nsd_debug_level);
//			break;
//#endif /* NDEBUG */
//		case 'o':
//			origin = optarg;
//			break;
//		case 'z':
//			singlefile = optarg;
//			break;
//		case 'h':
//			usage();
//			exit(0);
//		case '?':
//		default:
//			usage();
//			exit(1);
//		}
//	}
//
//	argc -= optind;
//	argv += optind;
//
//	if (argc != 0) {
//		usage();
//		exit(1);
//	}
//
//	/* Read options */
//	if(configfile != 0) {
//		nsd_options = nsd_options_create(global_region);
//		if(!parse_options_file(nsd_options, configfile))
//		{
//			fprintf(stderr, "zonec: could not read config: %s\n", configfile);
//			exit(1);
//		}
//	}
//	if(nsd_options && zonesdir == 0) zonesdir = nsd_options->zonesdir;
//	if(zonesdir && zonesdir[0]) {
//		if (chdir(zonesdir)) {
//			fprintf(stderr, "zonec: cannot chdir to %s: %s\n", zonesdir, strerror(errno));
//			exit(1);
//		}
//	}
//	if(dbfile == 0) {
//		if(nsd_options && nsd_options->database) dbfile = nsd_options->database;
//		else dbfile = DBFILE;
//	}
//
	/* Create the database */
	if ((db = zdb_create()) == NULL) {
		fprintf(stderr, "zonec: error creating the database (%s): %s\n");
		exit(1);
	}

	parser = zparser_create(global_region, rr_region, db);
	if (!parser) {
		fprintf(stderr, "zonec: error creating the parser\n");
		exit(1);
	}
//
//	/* Unique pointers used to mark errors.	 */
//	error_dname = (dname_type *) region_alloc(global_region, 0);
//	error_domain = (domain_type *) region_alloc(global_region, 0);
//
//	if (singlefile || origin) {
//		/*
//		 * Read a single zone file with the specified origin
//		 */
//		if(!singlefile) {
//			fprintf(stderr, "zonec: must have -z zonefile when reading single zone.\n");
//			exit(1);
//		}
//		if(!origin) {
//			fprintf(stderr, "zonec: must have -o origin when reading single zone.\n");
//			exit(1);
//		}
//		if (vflag > 0)
//			fprintf(stdout, "zonec: reading zone \"%s\".\n", origin);
		zone_read(origin, singlefile, nsd_options);
//		if (vflag > 0)
//			fprintf(stdout, "zonec: processed %ld RRs in \"%s\".\n", totalrrs, origin);
//	} else {
//		zone_options_t* zone;
//		if(!nsd_options) {
//			fprintf(stderr, "zonec: no zones specified.\n");
//			exit(1);
//		}
//		/* read all zones */
//		RBTREE_FOR(zone, zone_options_t*, nsd_options->zone_options)
//		{
//			if (vflag > 0)
//				fprintf(stdout, "zonec: reading zone \"%s\".\n",
//					zone->name);
//			zone_read(zone->name, zone->zonefile, nsd_options);
//			if (vflag > 0)
//				fprintf(stdout,
//					"zonec: processed %ld RRs in \"%s\".\n",
//					totalrrs, zone->name);
//			totalrrs = 0;
//		}
//	}
//	check_dname(db);
//
//#ifndef NDEBUG
//	if (vflag > 0) {
//		fprintf(stdout, "global_region: ");
//		region_dump_stats(global_region, stdout);
//		fprintf(stdout, "\n");
//		fprintf(stdout, "db->region: ");
//		region_dump_stats(db->region, stdout);
//		fprintf(stdout, "\n");
//	}
//#endif /* NDEBUG */
//
//	/* Close the database */
//	if (namedb_save(db) != 0) {
//		fprintf(stderr, "zonec: error writing the database (%s): %s\n", db->filename, strerror(errno));
//		namedb_discard(db);
//		exit(1);
//	}
//
//	/* Print the total number of errors */
//	if (vflag > 0 || totalerrors > 0) {
//		fprintf(stderr, "\nzonec: done with %ld errors.\n",
//			totalerrors);
//	}
//
//	/* Disable this to save some time.  */
//#if 0
//	region_destroy(global_region);
//#endif
//
//	return totalerrors ? 1 : 0;
//}
