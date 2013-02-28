/*!
 * \file parser-util.c
 *
 * \author NLnet Labs
 *         Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * \brief utility functions for zone parser.
 *
 * \addtogroup zoneparser
 * @{
 */

/*
 * Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

//#include "common.h"
#include "common/base32hex.h"
#include "zcompile/parser-util.h"
#include "zcompile/zcompile.h"
#include "parser-descriptor.h"
#include "libknot/util/utils.h"
#include "zcompile/zcompile-error.h"

#define IP6ADDRLEN	(128/8)
#define	NS_INT16SZ	2
#define NS_INADDRSZ 4
#define NS_IN6ADDRSZ 16
#define APL_NEGATION_MASK      0x80U

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
int inet_pton(int af, const char *src, void *dst)
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

//int my_b32_pton(const char *src, uint8_t *target, size_t tsize)
//{
//	char ch;
//	size_t p = 0;

//	memset(target, '\0', tsize);
//	while ((ch = *src++)) {
//		uint8_t d;
//		size_t b;
//		size_t n;

//		if (p + 5 >= tsize * 8) {
//			return -1;
//		}

//		if (isspace(ch)) {
//			continue;
//		}

//		if (ch >= '0' && ch <= '9') {
//			d = ch - '0';
//		} else if (ch >= 'A' && ch <= 'V') {
//			d = ch - 'A' + 10;
//		} else if (ch >= 'a' && ch <= 'v') {
//			d = ch - 'a' + 10;
//		} else {
//			return -1;
//		}

//		b = 7 - p % 8;
//		n = p / 8;

//		if (b >= 4) {
//			target[n] |= d << (b - 4);
//		} else {
//			target[n] |= d >> (4 - b);
//			target[n+1] |= d << (b + 4);
//		}
//		p += 5;
//	}
//	return (p + 7) / 8;
//}


#define Assert(Cond) if (!(Cond)) abort()

static const char Base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char Pad64 = '=';

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
int inet_pton4(const char *src, uint8_t *dst)
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

			if (new > 255) {
				return (0);
			}
			*tp = new;
			if (! saw_digit) {
				if (++octets > 4) {
					return (0);
				}
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4) {
				return (0);
			}
			*++tp = 0;
			saw_digit = 0;
		} else {
			return (0);
		}
	}
	if (octets < 4) {
		return (0);
	}

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
int inet_pton6(const char *src, uint8_t *dst)
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
		if (*++src != ':') {
			return (0);
		}
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL) {
			pch = strchr((xdigits = xdigits_u), ch);
		}
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff) {
				return (0);
			}
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp) {
					return (0);
				}
				colonp = tp;
				continue;
			}
			if (tp + NS_INT16SZ > endp) {
				return (0);
			}
			*tp++ = (uint8_t)(val >> 8) & 0xff;
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
		if (tp + NS_INT16SZ > endp) {
			return (0);
		}
		*tp++ = (uint8_t)(val >> 8) & 0xff;
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
	if (tp != endp) {
		return (0);
	}
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


/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
//const char *inet_ntop(int af, const void *src, char *dst, size_t size)
//{
//	switch (af) {
//	case AF_INET:
//		return (inet_ntop4(src, dst, size));
//	case AF_INET6:
//		return (inet_ntop6(src, dst, size));
//	default:
//		errno = EAFNOSUPPORT;
//		return (NULL);
//	}
//	/* NOTREACHED */
//}

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
const char *inet_ntop4(const u_char *src, char *dst, size_t size)
{
	static const char fmt[] = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];
	int l;

	l = snprintf(tmp, size, fmt, src[0], src[1], src[2], src[3]);
	if (l <= 0 || l >= (int)size) {
		errno = ENOSPC;
		return (NULL);
	}
	knot_strlcpy(dst, tmp, size);
	return (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
const char *inet_ntop6(const u_char *src, char *dst, size_t size)
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
	struct {
		int base, len;
	} best, cur;
	best.base = cur.base =-1;
	best.len = cur.len = 0;
	u_int words[IN6ADDRSZ / INT16SZ];
	int i;
	int advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < IN6ADDRSZ; i++) {
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	}

	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1) {
				cur.base = i, cur.len = 1;
			} else {
				cur.len++;
			}
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len) {
					best = cur;
				}
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len) {
			best = cur;
		}
	}
	if (best.base != -1 && best.len < 2) {
		best.base = -1;
	}

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
				if (tp + 1 >= ep) {
					return (NULL);
				}
				*tp++ = ':';
			}
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0) {
			if (tp + 1 >= ep) {
				return (NULL);
			}
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 &&
				(best.len == 6 ||
				(best.len == 5 && words[5] == 0xffff))) {
			if (!inet_ntop4(src + 12, tp, (size_t)(ep - tp))) {
				return (NULL);
			}
			tp += strlen(tp);
			break;
		}
		advance = snprintf(tp, ep - tp, "%x", words[i]);
		if (advance <= 0 || advance >= ep - tp) {
			return (NULL);
		}
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) ==
	   (IN6ADDRSZ / INT16SZ)) {
		if (tp + 1 >= ep) {
			return (NULL);
		}
		*tp++ = ':';
	}
	if (tp + 1 >= ep) {
		return (NULL);
	}
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((size_t)(tp - tmp) > size) {
		errno = ENOSPC;
		return (NULL);
	}
	knot_strlcpy(dst, tmp, size);
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
void b64_initialize_rmap()
{
	int i;
	char ch;

	/* Null: end of string, stop parsing */
	b64rmap[0] = b64rmap_end;

	for (i = 1; i < 256; ++i) {
		ch = (char)i;
		/* Whitespaces */
		if (isspace(ch)) {
			b64rmap[i] = b64rmap_space;
		}
		/* Padding: stop parsing */
		else if (ch == Pad64) {
			b64rmap[i] = b64rmap_end;
		}
		/* Non-base64 char */
		else {
			b64rmap[i] = b64rmap_invalid;
		}
	}

	/* Fill reverse mapping for base64 chars */
	for (i = 0; Base64[i] != '\0'; ++i) {
		b64rmap[(uint8_t)Base64[i]] = i;
	}

	b64rmap_initialized = 1;
}

int b64_pton_do(char const *src, uint8_t *target, size_t targsize)
{
	int tarindex, state, ch;
	uint8_t ofs;

	state = 0;
	tarindex = 0;

	while (1) {
		ch = *src++;
		ofs = b64rmap[ch];

		if (ofs >= b64rmap_special) {
			/* Ignore whitespaces */
			if (ofs == b64rmap_space) {
				continue;
			}
			/* End of base64 characters */
			if (ofs == b64rmap_end) {
				break;
			}
			/* A non-base64 character. */
			return (-1);
		}

		switch (state) {
		case 0:
			if ((size_t)tarindex >= targsize) {
				return (-1);
			}
			target[tarindex] = ofs << 2;
			state = 1;
			break;
		case 1:
			if ((size_t)tarindex + 1 >= targsize) {
				return (-1);
			}
			target[tarindex]   |=  ofs >> 4;
			target[tarindex+1]  = (ofs & 0x0f)
					      << 4 ;
			tarindex++;
			state = 2;
			break;
		case 2:
			if ((size_t)tarindex + 1 >= targsize) {
				return (-1);
			}
			target[tarindex]   |=  ofs >> 2;
			target[tarindex+1]  = (ofs & 0x03)
					      << 6;
			tarindex++;
			state = 3;
			break;
		case 3:
			if ((size_t)tarindex >= targsize) {
				return (-1);
			}
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
				if (b64rmap[ch] != b64rmap_space) {
					break;
				}
			/* Make sure there is another trailing = sign. */
			if (ch != Pad64) {
				return (-1);
			}
			ch = *src++;		/* Skip the = */
			/* Fall through to "single trailing =" case. */
			/* FALLTHROUGH */

		case 3:		/* Valid, means two bytes of info */
			/*
			 * We know this char is an =.  Is there anything but
			 * whitespace after it?
			 */
			for ((void)NULL; ch != '\0'; ch = *src++)
				if (b64rmap[ch] != b64rmap_space) {
					return (-1);
				}

			/*
			 * Now make sure for cases 2 and 3 that the "extra"
			 * bits that slopped past the last full byte were
			 * zeros.  If we don't check them, they become a
			 * subliminal channel.
			 */
			if (target[tarindex] != 0) {
				return (-1);
			}
		}
	} else {
		/*
		 * We ended by seeing the end of the string.  Make sure we
		 * have no partial bytes lying around.
		 */
		if (state != 0) {
			return (-1);
		}
	}

	return (tarindex);
}


int b64_pton_len(char const *src)
{
	int tarindex, state, ch;
	uint8_t ofs;

	state = 0;
	tarindex = 0;

	while (1) {
		ch = *src++;
		ofs = b64rmap[ch];

		if (ofs >= b64rmap_special) {
			/* Ignore whitespaces */
			if (ofs == b64rmap_space) {
				continue;
			}
			/* End of base64 characters */
			if (ofs == b64rmap_end) {
				break;
			}
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
				if (b64rmap[ch] != b64rmap_space) {
					break;
				}
			/* Make sure there is another trailing = sign. */
			if (ch != Pad64) {
				return (-1);
			}
			ch = *src++;		/* Skip the = */
			/* Fall through to "single trailing =" case. */
			/* FALLTHROUGH */

		case 3:		/* Valid, means two bytes of info */
			/*
			 * We know this char is an =.  Is there anything but
			 * whitespace after it?
			 */
			for ((void)NULL; ch != '\0'; ch = *src++)
				if (b64rmap[ch] != b64rmap_space) {
					return (-1);
				}

		}
	} else {
		/*
		 * We ended by seeing the end of the string.  Make sure we
		 * have no partial bytes lying around.
		 */
		if (state != 0) {
			return (-1);
		}
	}

	return (tarindex);
}

int b64_pton(char const *src, uint8_t *target, size_t targsize)
{
	if (!b64rmap_initialized) {
		b64_initialize_rmap();
	}

	if (target) {
		return b64_pton_do(src, target, targsize);
	} else {
		return b64_pton_len(src);
	}
}

void set_bit(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	bits[index / 8] |= (1 << (7 - index % 8));
}

uint32_t strtoserial(const char *nptr, const char **endptr)
{
	uint32_t i = 0;
	uint32_t serial = 0;

	for (*endptr = nptr; **endptr; (*endptr)++) {
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

inline void write_uint32(void *dst, uint32_t data)
{
/*!< \todo Check what this means and delete if obsolete. */
#ifdef ALLOW_UNALIGNED_ACCESSES
	*(uint32_t *) dst = htonl(data);
#else
	uint8_t *p = (uint8_t *) dst;
	p[0] = (uint8_t)((data >> 24) & 0xff);
	p[1] = (uint8_t)((data >> 16) & 0xff);
	p[2] = (uint8_t)((data >> 8) & 0xff);
	p[3] = (uint8_t)(data & 0xff);
#endif
}

uint32_t strtottl(const char *nptr, const char **endptr)
{
	uint32_t i = 0;
	uint32_t seconds = 0;

	for (*endptr = nptr; **endptr; (*endptr)++) {
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

/* Number of days per month (except for February in leap years). */
static const int mdays[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static int is_leap_year(int year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int leap_days(int y1, int y2)
{
    --y1;
    --y2;
    return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}

/*
 * Code adapted from Python 2.4.1 sources (Lib/calendar.py).
 */
time_t mktime_from_utc(const struct tm *tm)
{
    int year = 1900 + tm->tm_year;
    time_t days = 365 * (year - 1970) + leap_days(1970, year);
    time_t hours;
    time_t minutes;
    time_t seconds;
    int i;

    for (i = 0; i < tm->tm_mon; ++i) {
	days += mdays[i];
    }
    if (tm->tm_mon > 1 && is_leap_year(year)) {
	++days;
    }
    days += tm->tm_mday - 1;

    hours = days * 24 + tm->tm_hour;
    minutes = hours * 60 + tm->tm_min;
    seconds = minutes * 60 + tm->tm_sec;

    return seconds;
}

/*!< Following functions are conversions from text to wire. */
//#define DEBUG_UNKNOWN_RDATA

#ifdef DEBUG_UNKNOWN_RDATA
#define dbg_rdata(msg...) fprintf(stderr, msg)
#define DBG_RDATA(cmds) do { cmds } while (0)
#else
#define dbg_rdata(msg...)
#define DBG_RDATA(cmds)
#endif



#define IP6ADDRLEN	(128/8)
#define	NS_INT16SZ	2
#define NS_INADDRSZ 4
#define NS_IN6ADDRSZ 16
#define APL_NEGATION_MASK      0x80U
#define APL_LENGTH_MASK	       (~APL_NEGATION_MASK)

//#define ZP_DEBUG

#ifdef ZP_DEBUG
#define dbg_zp(msg...) fprintf(stderr, msg)
#else
#define dbg_zp(msg...)
#endif


/*!
 * \brief Return data of raw data item.
 *
 * \param item Item.
 * \return uint16_t * Raw data.
 */
static inline uint16_t * rdata_atom_data(knot_rdata_item_t item)
{
	return (uint16_t *)(item.raw_data + 1);
}

/*!
 * \brief Return type of RRSet covered by given RRSIG.
 *
 * \param rrset RRSIG.
 * \return uint16_t Type covered.
 */
uint16_t rrsig_type_covered(knot_rrset_t *rrset)
{
	assert(rrset->rdata->items[0].raw_data[0] == sizeof(uint16_t));

	return ntohs(*(uint16_t *) rdata_atom_data(rrset->rdata->items[0]));
}

/*!
 * \brief Checks if item contains domain.
 *
 * \param type Type of RRSet.
 * \param index Index to check.
 *
 * \return > 1 if item is domain, 0 otherwise.
 */
static inline int rdata_atom_is_domain(uint16_t type, size_t index)
{
	const knot_rrtype_descriptor_t *descriptor
	= knot_rrtype_descriptor_by_type(type);
	return (index < descriptor->length
		&& (descriptor->wireformat[index] ==
		KNOT_RDATA_WF_COMPRESSED_DNAME  ||
		descriptor->wireformat[index] ==
		KNOT_RDATA_WF_LITERAL_DNAME  ||
		descriptor->wireformat[index] ==
		KNOT_RDATA_WF_UNCOMPRESSED_DNAME));
}

/*!
 * \brief Returns which wireformat type is on given index.
 *
 * \param type Type of RRSet.
 * \param index Index.
 *
 * \return uint8_t Wireformat type.
 */
static inline uint8_t rdata_atom_wireformat_type(uint16_t type, size_t index)
{
	const knot_rrtype_descriptor_t *descriptor =
		knot_rrtype_descriptor_by_type(type);
	assert(index < descriptor->length);
	return descriptor->wireformat[index];
}

typedef int (*printf_t)(const char *fmt, ...);

/*!
 * \brief Converts rdata wireformat to rdata items.
 *
 * \param wireformat Wireformat/.
 * \param rrtype RR type.
 * \param data_size Size of wireformat.
 * \param items created rdata items.
 *
 * \return Number of items converted.
 */
static ssize_t rdata_wireformat_to_rdata_atoms(const uint16_t *wireformat,
					uint16_t rrtype,
					const uint16_t data_size,
					knot_rdata_item_t **items)
{
	/*!< \todo This is so ugly, it makes me wanna puke. */
	uint16_t const *end =
		(uint16_t *)((uint8_t *)wireformat + (data_size));
	dbg_rdata("set end pointer: %p which means length: %d\n", end,
	          (uint8_t *)end - (uint8_t *)wireformat);
	dbg_rdata("Parsing following wf: ");
	size_t i;
	knot_rdata_item_t *temp_rdatas =
		malloc(sizeof(*temp_rdatas) * MAXRDATALEN);
	if (temp_rdatas == NULL) {
		ERR_ALLOC_FAILED;
		return KNOTDZCOMPILE_ENOMEM;
	}
	memset(temp_rdatas, 0, sizeof(*temp_rdatas) * MAXRDATALEN);

	knot_rrtype_descriptor_t *descriptor =
		knot_rrtype_descriptor_by_type(rrtype);

	assert(descriptor->length <= MAXRDATALEN);

	dbg_rdata("will be parsing %d items, total size: %d\n",
	          descriptor->length, data_size);

	for (i = 0; i < descriptor->length; ++i) {
		dbg_rdata("this particular item is type %d.\n",
		          rdata_atom_wireformat_type(rrtype, i));
		int is_domain = 0;
		int is_wirestore = 0;
		size_t length = 0;
		length = 0;
		bool required = descriptor->fixed_items;

		switch (rdata_atom_wireformat_type(rrtype, i)) {
		case KNOT_RDATA_WF_COMPRESSED_DNAME:
		case KNOT_RDATA_WF_UNCOMPRESSED_DNAME:
			dbg_rdata("Parsed item is a dname.\n");
			is_domain = 1;
			break;
		case KNOT_RDATA_WF_LITERAL_DNAME:
			dbg_rdata("Parsed item is a literal dname.\n");
			is_domain = 1;
			is_wirestore = 1;
			break;
		case KNOT_RDATA_WF_BYTE:
			dbg_rdata("Parsed item is a byte.\n");
			length = sizeof(uint8_t);
			break;
		case KNOT_RDATA_WF_SHORT:
			dbg_rdata("Parsed item is a short.\n");
			length = sizeof(uint16_t);
			break;
		case KNOT_RDATA_WF_LONG:
			dbg_rdata("Parsed item is a long.\n");
			length = sizeof(uint32_t);
			break;
		case KNOT_RDATA_WF_APL:
			dbg_rdata("APL data.\n");
		case KNOT_RDATA_WF_TEXT_SINGLE:
		case KNOT_RDATA_WF_TEXT:
			dbg_rdata("TEXT rdata.\n");
		case KNOT_RDATA_WF_BINARYWITHLENGTH:
			dbg_rdata("BINARYWITHLENGTH rdata.\n");
			/* Length is stored in the first byte.  */
			length = data_size;
			break;
		case KNOT_RDATA_WF_A:
			dbg_rdata("Parsed item is an IPv4 address.\n");
			length = sizeof(in_addr_t);
			break;
		case KNOT_RDATA_WF_AAAA:
			dbg_rdata("Parsed item is an IPv6 address.\n");
			length = IP6ADDRLEN;
			break;
		case KNOT_RDATA_WF_BINARY:
			/* Remaining RDATA is binary.  */
			dbg_rdata("BINARY: item %d: guessing length from pointers: %p %p. ",
			          i,
			          wireformat, end);
			length = (uint8_t *)end - (uint8_t *)wireformat;
			dbg_rdata("Result: %d.\n",
			          length);
			break;
//		case KNOT_RDATA_WF_APL:
//			length = (sizeof(uint16_t)    /* address family */
//				  + sizeof(uint8_t)   /* prefix */
//				  + sizeof(uint8_t)); /* length */
//			if ((uint8_t *)wireformat + length <= (uint8_t *)end) {
//				/* Mask out negation bit.  */
//				dbg_rdata("APL: length was %d. ", length);
//				length += (wireformat[data_size - 1]
//					   & APL_LENGTH_MASK);
//				dbg_rdata("APL: after masking: %d.\n", length);
//			}
//			break;
		case KNOT_RDATA_WF_IPSECGATEWAY:
			dbg_rdata("Parsed item is an IPSECGATEWAY address.\n");
			dbg_rdata("Gateway type: %d\n",
			          ((uint8_t *)rdata_atom_data(temp_rdatas[1]))[0]);
			switch (((uint8_t *)rdata_atom_data(temp_rdatas[1]))[0]) {
			/* gateway type */
			case IPSECKEY_NOGATEWAY:
				dbg_rdata("NOGATEWAY\n");
				length = 0;
				break;
			case IPSECKEY_IP4:
				dbg_rdata("IPv4\n");
				length = 4;
				break;
			case IPSECKEY_IP6:
				dbg_rdata("IPv6\n");
				length = IP6ADDRLEN;
				break;
			case IPSECKEY_DNAME:
				dbg_rdata("DNAME\n");
				is_domain = 1;
				is_wirestore = 1;
				break;
			default:
				dbg_rdata("Unknown IPSECKEY gateway!\n");
				free(temp_rdatas);
				return -1;
			} // switch
		}

		if (is_domain) {
			knot_dname_t *dname = NULL;
			/*
			 * Since we don't know how many dnames there are 
			 * in the whole wireformat we have to search for next
			 * '\0'.
			 */
			for (length = 0;
			     (length < ((uint8_t *)end - (uint8_t *)wireformat))
			     && (((uint8_t *)wireformat)[length] != '\0');
			     length++) {
				;
			}
			length++;
			dbg_rdata("item %d: length derived from position of "
			          "0: %d\n", i, length);

			if (!required && (wireformat == end)) {
				break;
			}

			dname = knot_dname_new_from_wire((uint8_t *)wireformat,
							 length,
							 NULL);

			if (dname == NULL) {
				dbg_rdata("malformed dname!\n");
				/*! \todo rdata purge */
				free(temp_rdatas);
				return KNOTDZCOMPILE_EBRDATA;
			}
			
			dbg_rdata("item %d: created dname: %s, length: %d\n", i,
			          knot_dname_to_str(dname), length);

			if (is_wirestore) {
				/*temp_rdatas[i].raw_data =
					(uint16_t *) region_alloc(
				region, sizeof(uint16_t) + dname->name_size);
				temp_rdatas[i].data[0] = dname->name_size;
				memcpy(temp_rdatas[i].data+1, dname_name(dname),
				dname->name_size); */
				temp_rdatas[i].raw_data =
					malloc(sizeof(uint16_t) +
					       sizeof(uint8_t) * dname->size);
				if (temp_rdatas[i].raw_data == NULL) {
					ERR_ALLOC_FAILED;
					/*! \todo rdata purge */
					free(temp_rdatas);
					return KNOTDZCOMPILE_ENOMEM;
				}

				temp_rdatas[i].raw_data[0] = dname->size;
				memcpy(temp_rdatas[i].raw_data + 1,
				       dname->name, dname->size);

				knot_dname_release(dname);
			} else {
				temp_rdatas[i].dname = dname;
			}

		} else {
			/*!< \todo This calculated length makes no sense! */
			dbg_rdata("item %d :length: %d calculated: %d (%p %p)\n", i, length,
			          end - wireformat,
			          wireformat, end);
			if ((uint8_t *)wireformat + length > (uint8_t *)end) {
				if (required) {
					/* Truncated RDATA.  */
					/*! \todo rdata purge */
					free(temp_rdatas);
					dbg_rdata("truncated rdata, end pointer is exceeded by %d octets.\n",
					          (wireformat + length) - end);
					return KNOTDZCOMPILE_EBRDATA;
				} else {
					break;
				}
			}

			assert(wireformat <= end); /*!< \todo remove! */
			dbg_rdata("calling init with: %p and length : %d\n",
			          wireformat, length);
			temp_rdatas[i].raw_data = alloc_rdata_init(wireformat,
			                                           length);
			if (temp_rdatas[i].raw_data == NULL) {
				ERR_ALLOC_FAILED;
				/*! \todo rdata purge */
				free(temp_rdatas);
				return -1;
			}

//			temp_rdatas[i].raw_data[0] = length;
//			memcpy(temp_rdatas[i].raw_data + 1, wireformat, length);

/*			temp_rdatas[i].data = (uint16_t *) region_alloc(
				region, sizeof(uint16_t) + length);
				temp_rdatas[i].data[0] = length;
				buffer_read(packet,
					    temp_rdatas[i].data + 1, length); */
		}
		dbg_rdata("%d: adding length: %d (remaining: %d)\n", i, length,
		          (uint8_t *)end - ((uint8_t *)wireformat + length));
//		hex_print(temp_rdatas[i].raw_data + 1, length);
		wireformat = (uint16_t *)((uint8_t *)wireformat + length);
//		wireformat = wireformat + length;
		dbg_rdata("wire: %p\n", wireformat);
		dbg_rdata("remaining now: %d\n",
		          end - wireformat);
	}

	dbg_rdata("%p %p\n", wireformat, (uint8_t *)wireformat);

	if (wireformat < end) {
		/* Trailing garbage.  */
		dbg_rdata("Garbage: w: %p e: %p %d\n", wireformat, end, end - wireformat);
		free(temp_rdatas);
		return KNOTDZCOMPILE_EBRDATA;
	}

	*items = temp_rdatas;
	/*	*rdatas = (rdata_atom_type *) region_alloc_init(
			region, temp_rdatas, i * sizeof(rdata_atom_type)); */
	dbg_rdata("wf_to_rdata_atoms: Succesfully converted %d items.\n",
	          i);
	return (ssize_t)i;
}

/* Taken from RFC 2535, section 7.  */
knot_lookup_table_t dns_algorithms[] = {
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
knot_lookup_table_t dns_certificate_types[] = {
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

extern uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE];
extern uint16_t nsec_highest_rcode;

/*!
 * \brief Allocate SIZE+sizeof(uint16_t) bytes and store SIZE in the first
 *        element.  Return a pointer to the allocation.
 *
 * \param size How many bytes to allocate.
 */
static uint16_t * alloc_rdata(size_t size)
{
	uint16_t *result = malloc(sizeof(uint16_t) + size);
	*result = size;
	return result;
}

uint16_t *alloc_rdata_init(const void *data, size_t size)
{
	uint16_t *result = malloc(sizeof(uint16_t) + size);
	if (result == NULL) {
		return NULL;
	}
	*result = size;
	memcpy(result + 1, data, size);
	return result;
}

/*
 * These are parser function for generic zone file stuff.
 */
uint16_t * zparser_conv_hex(const char *hex, size_t len)
{
	/* convert a hex value to wireformat */
	uint16_t *r = NULL;
	uint8_t *t;
	int i;

	if (len % 2 != 0) {
		zc_error_prev_line("number of hex digits "
		                   "must be a multiple of 2");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else if (len > MAX_RDLENGTH * 2) {
		zc_error_prev_line("hex data exceeds maximum rdata length (%d)",
			MAX_RDLENGTH);
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		/* the length part */

		r = alloc_rdata(len / 2);
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
		t = (uint8_t *)(r + 1);

		/* Now process octet by octet... */
		while (*hex) {
			*t = 0;
			for (i = 16; i >= 1; i -= 15) {
				if (isxdigit((int)*hex)) {
					*t += hexdigit_to_int(*hex) * i;
				} else {
					zc_error_prev_line(
						"illegal hex character '%c'",
						(int) *hex);
					parser->error_occurred =
						KNOTDZCOMPILE_EBRDATA;
					free(r);
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
uint16_t * zparser_conv_hex_length(const char *hex, size_t len)
{
	uint16_t *r = NULL;
	uint8_t *t;
	int i;
	if (len % 2 != 0) {
		zc_error_prev_line("number of hex digits must be a "
		                   "multiple of 2");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else if (len > 255 * 2) {
		zc_error_prev_line("hex data exceeds 255 bytes");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		uint8_t *l;

		/* the length part */
		r = alloc_rdata(len / 2 + 1);
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}

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
					zc_error_prev_line(
						"illegal hex character '%c'",
						(int) *hex);
					parser->error_occurred =
						KNOTDZCOMPILE_EBRDATA;
					free(r);
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

uint16_t * zparser_conv_time(const char *time)
{
	/* convert a time YYHM to wireformat */
	uint16_t *r = NULL;
	struct tm tm;

	/* Try to scan the time... */
	if (!strptime(time, "%Y%m%d%H%M%S", &tm)) {
		zc_error_prev_line("date and time is expected");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		uint32_t l = htonl(mktime_from_utc(&tm));
		r = alloc_rdata_init(&l, sizeof(l));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_services(const char *protostr, char *servicestr)
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
		zc_error_prev_line("unknown protocol '%s'", protostr);
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
		return NULL;
	}

	char *sp = 0;
	while ((word = strtok_r(servicestr, sep, &sp))) {
		struct servent *service = NULL;
		int port;

		service = getservbyname(word, proto->p_name);
		if (service) {
			/* Note: ntohs not ntohl!  Strange but true.  */
			port = ntohs((uint16_t) service->s_port);
//			printf("assigned port %d\n", port);
		} else {
//			printf("else\n");
			char *end;
			port = strtol(word, &end, 10);
			if (*end != '\0') {
				zc_error_prev_line(
					"unknown service '%s' for"
					" protocol '%s'",
					word, protostr);
				parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
				return NULL;
			}
		}

		if (port < 0 || port > 65535) {
			zc_error_prev_line("bad port number %d", port);
		} else {
			set_bit(bitmap, port);
			if (port > max_port) {
				max_port = port;
			}
		}
		servicestr = NULL;
	}

	r = alloc_rdata(sizeof(uint8_t) + max_port / 8 + 1);
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
		return NULL;
	}

	p = (uint8_t *)(r + 1);
	*p = proto->p_proto;
	memcpy(p + 1, bitmap, *r - 1);

	return r;
}

uint16_t * zparser_conv_serial(const char *serialstr)
{
	uint16_t *r = NULL;
	uint32_t serial;
	const char *t;

	serial = strtoserial(serialstr, &t);
	if (*t != '\0') {
		zc_error_prev_line("serial is expected");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		serial = htonl(serial);
		r = alloc_rdata_init(&serial, sizeof(serial));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_period(const char *periodstr)
{
	/* convert a time period (think TTL's) to wireformat) */
	uint16_t *r = NULL;
	uint32_t period;
	const char *end;

	/* Allocate required space... */
	period = strtottl(periodstr, &end);
	if (*end != '\0') {
		zc_error_prev_line("time period is expected");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		period = htonl(period);
		r = alloc_rdata_init(&period, sizeof(period));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_short(const char *text)
{
	uint16_t *r = NULL;
	uint16_t value;
	char *end;

	value = htons((uint16_t) strtol(text, &end, 10));
	if (*end != '\0') {
		zc_error_prev_line("integer value is expected");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		r = alloc_rdata_init(&value, sizeof(value));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_byte(const char *text)
{
	uint16_t *r = NULL;
	uint8_t value;
	char *end;

	value = (uint8_t) strtol(text, &end, 10);
	if (*end != '\0') {
		zc_error_prev_line("integer value is expected");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		r = alloc_rdata_init(&value, sizeof(value));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_algorithm(const char *text)
{
	const knot_lookup_table_t *alg;
	uint8_t id;

	alg = knot_lookup_by_name(dns_algorithms, text);
	if (alg) {
		id = (uint8_t) alg->id;
	} else {
		char *end;
		id = (uint8_t) strtol(text, &end, 10);
		if (*end != '\0') {
			zc_error_prev_line("algorithm is expected");
			parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
			return NULL;
		}
	}

	uint16_t *r = alloc_rdata_init(&id, sizeof(id));
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
		return NULL;
	}

	return r;
}

uint16_t * zparser_conv_certificate_type(const char *text)
{
	/* convert a algoritm string to integer */
	const knot_lookup_table_t *type;
	uint16_t id;

	type = knot_lookup_by_name(dns_certificate_types, text);
	if (type) {
		id = htons((uint16_t) type->id);
	} else {
		char *end;
		id = htons((uint16_t) strtol(text, &end, 10));
		if (*end != '\0') {
			zc_error_prev_line("certificate type is expected");
			parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
			return NULL;
		}
	}

	uint16_t *r = alloc_rdata_init(&id, sizeof(id));
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
		return NULL;
	}

	return r;
}

uint16_t * zparser_conv_a(const char *text)
{
	in_addr_t address;
	uint16_t *r = NULL;

	if (inet_pton(AF_INET, text, &address) != 1) {
		zc_error_prev_line("invalid IPv4 address '%s'", text);
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		r = alloc_rdata_init(&address, sizeof(address));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}

	return r;
}

uint16_t * zparser_conv_aaaa(const char *text)
{
	uint8_t address[IP6ADDRLEN];
	uint16_t *r = NULL;

	if (inet_pton(AF_INET6, text, address) != 1) {
		zc_error_prev_line("invalid IPv6 address '%s'", text);
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		r = alloc_rdata_init(address, sizeof(address));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_text(const char *text, size_t len)
{
	uint16_t *r = NULL;

	dbg_zp("Converting text: %s\n", text);

	if (len > 255) {
		zc_error_prev_line("text string is longer than 255 characters,"
			" try splitting it into multiple parts");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		uint8_t *p;
		r = alloc_rdata(len + 1);
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
		p = (uint8_t *)(r + 1);
		*p = len;
		memcpy(p + 1, text, len);
	}
	return r;
}

uint16_t * zparser_conv_dns_name(const uint8_t *name, size_t len)
{
	uint16_t *r = NULL;
	uint8_t *p = NULL;
	r = alloc_rdata(len);
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
		return NULL;
	}
	p = (uint8_t *)(r + 1);
	memcpy(p, name, len);

	return r;
}

uint16_t * zparser_conv_b32(const char *b32)
{
	uint8_t buffer[B64BUFSIZE];
	uint16_t *r = NULL;
	size_t i = B64BUFSIZE - 1;

	if (strcmp(b32, "-") == 0) {
		r = alloc_rdata_init("", 1);
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
		return r;
	}

	/*!< \todo BLEEDING EYES! */

	char b32_copy[strlen(b32) + 1];

	for (int i = 0; i < strlen(b32); i++) {
		b32_copy[i] = toupper(b32[i]);
	}

	/*!< \todo BLEEDING EYES! */
	b32_copy[strlen(b32)] = '\0';

	int32_t b32_ret = base32hex_decode((uint8_t *)b32_copy, strlen(b32_copy),
	                                   buffer + 1, i);

	i = b32_ret;

	if (b32_ret <= 0) {
		zc_error_prev_line("invalid base32 data");
		parser->error_occurred = 1;
	} else {
		buffer[0] = i; /* store length byte */
		r = alloc_rdata_init(buffer, i + 1);
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_b64(const char *b64)
{
	uint8_t buffer[B64BUFSIZE];
	uint16_t *r = NULL;
	int i;

	i = b64_pton(b64, buffer, B64BUFSIZE);
	if (i == -1) {
		zc_error_prev_line("invalid base64 data\n");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		r = alloc_rdata_init(buffer, i);
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_rrtype(const char *text)
{
	uint16_t *r = NULL;
	uint16_t type = knot_rrtype_from_string(text);

	if (type == 0) {
		zc_error_prev_line("unrecognized RR type '%s'", text);
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		type = htons(type);
		r = alloc_rdata_init(&type, sizeof(type));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_nxt(uint8_t nxtbits[])
{
	/* nxtbits[] consists of 16 bytes with some zero's in it
	 * copy every byte with zero to r and write the length in
	 * the first byte
	 */
	uint16_t i;
	uint16_t last = 0;

	for (i = 0; i < 16; i++) {
		if (nxtbits[i] != 0) {
			last = i + 1;
		}
	}

	uint16_t *r = alloc_rdata_init(nxtbits, last);
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
		return NULL;
	}

	return r;
}


/* we potentially have 256 windows, each one is numbered. empty ones
 * should be discarded
 */
uint16_t * zparser_conv_nsec(uint8_t nsecbits[NSEC_WINDOW_COUNT]
					     [NSEC_WINDOW_BITS_SIZE])
{
	/* nsecbits contains up to 64K of bits which represent the
	 * types available for a name. Walk the bits according to
	 * nsec++ draft from jakob
	 */
	uint16_t *r;
	uint8_t *ptr;
	size_t i, j;
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
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
		return NULL;
	}
	ptr = (uint8_t *)(r + 1);

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
static int parse_int(const char *str,
		     char **end,
		     int *result,
		     const char *name,
		     int min,
		     int max)
{
	long value;
	value = strtol(str, end, 10);
	if (value < min || value > max) {
		zc_error_prev_line("%s must be within the range [%d .. %d]",
			name,
			min,
			max);
		return 0;
	} else {
		*result = (int) value;
		return 1;
	}
}

/* RFC1876 conversion routines */
static uint32_t poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
				  1000000, 10000000, 100000000, 1000000000
				 };

/*
 * Converts ascii size/precision X * 10**Y(cm) to 0xXY.
 * Sets the given pointer to the last used character.
 *
 */
static uint8_t precsize_aton(char *cp, char **endptr)
{
	unsigned int mval = 0, cmval = 0;
	uint8_t retval = 0;
	int exponent;
	int mantissa;

	while (isdigit((int)*cp)) {
		mval = mval * 10 + hexdigit_to_int(*cp++);
	}

	if (*cp == '.') {	/* centimeters */
		cp++;
		if (isdigit((int)*cp)) {
			cmval = hexdigit_to_int(*cp++) * 10;
			if (isdigit((int)*cp)) {
				cmval += hexdigit_to_int(*cp++);
			}
		}
	}

	if (mval >= poweroften[7]) {
		/* integer overflow possible for *100 */
		mantissa = mval / poweroften[7];
		exponent = 9; /* max */
	} else {
		cmval = (mval * 100) + cmval;

		for (exponent = 0; exponent < 9; exponent++)
			if (cmval < poweroften[exponent+1]) {
				break;
			}

		mantissa = cmval / poweroften[exponent];
	}
	if (mantissa > 9) {
		mantissa = 9;
	}

	retval = (mantissa << 4) | exponent;

	if (*cp == 'm') {
		cp++;
	}

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
uint16_t * zparser_conv_loc(char *str)
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

	for (;;) {
		deg = min = secs = 0;

		/* Degrees */
		if (*str == '\0') {
			zc_error_prev_line("unexpected end of LOC data");
			return NULL;
		}

		if (!parse_int(str, &str, &deg, "degrees", 0, 180)) {
			return NULL;
		}
		if (!isspace((int)*str)) {
			zc_error_prev_line("space expected after degrees");
			return NULL;
		}
		++str;

		/* Minutes? */
		if (isdigit((int)*str)) {
			if (!parse_int(str, &str, &min, "minutes", 0, 60)) {
				return NULL;
			}
			if (!isspace((int)*str)) {
				zc_error_prev_line("space expected after minutes");
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

			if (*str == '.' && !parse_int(str + 1, &str, &i,
						      "seconds fraction",
						      0, 999)) {
				return NULL;
			}

			if (!isspace((int)*str)) {
				zc_error_prev_line("space expected after seconds");
				return NULL;
			}
			
			d = strtod(start, &start);
			if (errno != 0) {
				zc_error_prev_line("error parsing seconds");
			}

			if (d < 0.0 || d > 60.0) {
				zc_error_prev_line(
					"seconds not in range 0.0 .. 60.0");
			}

			secs = (int)(d * 1000.0 + 0.5);
			++str;
		}

		switch (*str) {
		case 'N':
		case 'n':
			lat = ((uint32_t)1 << 31) +
				(deg * 3600000 + min * 60000 + secs);
			break;
		case 'E':
		case 'e':
			lon = ((uint32_t)1 << 31) +
				(deg * 3600000 + min * 60000 + secs);
			break;
		case 'S':
		case 's':
			lat = ((uint32_t)1 << 31) -
				(deg * 3600000 + min * 60000 + secs);
			break;
		case 'W':
		case 'w':
			lon = ((uint32_t)1 << 31) -
				(deg * 3600000 + min * 60000 + secs);
			break;
		default:
			zc_error_prev_line(
				"invalid latitude/longtitude: '%c'", *str);
			return NULL;
		}
		++str;

		if (lat != 0 && lon != 0) {
			break;
		}

		if (!isspace((int)*str)) {
			zc_error_prev_line("space expected after"
				" latitude/longitude");
			return NULL;
		}
		++str;
	}

	/* Altitude */
	if (*str == '\0') {
		zc_error_prev_line("unexpected end of LOC data");
		return NULL;
	}

	if (!isspace((int)*str)) {
		zc_error_prev_line("space expected before altitude");
		return NULL;
	}
	++str;

	start = str;

	/* Sign */
	if (*str == '+' || *str == '-') {
		++str;
	}

	/* Meters of altitude... */
	int ret = strtol(str, &str, 10);
	UNUSED(ret); // Result checked in following switch

	switch (*str) {
	case ' ':
	case '\0':
	case 'm':
		break;
	case '.':
		if (!parse_int(str + 1, &str, &i, "altitude fraction", 0, 99)) {
			return NULL;
		}
		if (!isspace((int)*str) && *str != '\0' && *str != 'm') {
			zc_error_prev_line("altitude fraction must be a number");
			return NULL;
		}
		break;
	default:
		zc_error_prev_line("altitude must be expressed in meters");
		return NULL;
	}
	if (!isspace((int)*str) && *str != '\0') {
		++str;
	}
	
	d = strtod(start, &start);
	if (errno != 0) {
		zc_error_prev_line("error parsing altitued");
	}

	alt = (uint32_t)(10000000.0 + d * 100 + 0.5);

	if (!isspace((int)*str) && *str != '\0') {
		zc_error_prev_line("unexpected character after altitude");
		return NULL;
	}

	/* Now parse size, horizontal precision and vertical precision if any */
	for (i = 1; isspace((int)*str) && i <= 3; i++) {
		vszhpvp[i] = precsize_aton(str + 1, &str);

		if (!isspace((int)*str) && *str != '\0') {
			zc_error_prev_line("invalid size or precision");
			return NULL;
		}
	}

	/* Allocate required space... */
	r = alloc_rdata(16);
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	p = (uint32_t *)(r + 1);

	memmove(p, vszhpvp, 4);
	write_uint32(p + 1, lat);
	write_uint32(p + 2, lon);
	write_uint32(p + 3, alt);

	return r;
}

/*
 * Convert an APL RR RDATA element.
 */
uint16_t * zparser_conv_apl_rdata(char *str)
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
		zc_error_prev_line("address family separator is missing");
		return NULL;
	}
	if (!slash) {
		zc_error_prev_line("prefix separator is missing");
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
		zc_error_prev_line("invalid address family '%s'", str);
		return NULL;
	}

	rc = inet_pton(af, colon + 1, address);
	if (rc == 0) {
		zc_error_prev_line("invalid address '%s'", colon + 1);
		return NULL;
	} else if (rc == -1) {
		char ebuf[256] = {0};
		strerror_r(errno, ebuf, sizeof(ebuf));
		zc_error_prev_line("inet_pton failed: %s", ebuf);
		return NULL;
	}

	/* Strip trailing zero octets.	*/
	while (length > 0 && address[length - 1] == 0) {
		--length;
	}


	p = strtol(slash + 1, &end, 10);
	if (p < 0 || p > maximum_prefix) {
		zc_error_prev_line("prefix not in the range 0 .. %d",
			maximum_prefix);
		return NULL;
	} else if (*end != '\0') {
		zc_error_prev_line("invalid prefix '%s'", slash + 1);
		return NULL;
	}
	prefix = (uint8_t) p;

	rdlength = (sizeof(address_family) + sizeof(prefix) + sizeof(length)
		    + length);
	r = alloc_rdata(rdlength);
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	t = (uint8_t *)(r + 1);

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

uint32_t zparser_ttl2int(const char *ttlstr, int *error)
{
	/* convert a ttl value to a integer
	 * return the ttl in a int
	 * -1 on error
	 */

	uint32_t ttl;
	const char *t;

	ttl = strtottl(ttlstr, &t);
	if (*t != 0) {
		zc_error_prev_line("invalid TTL value: %s", ttlstr);
		*error = 1;
	}

	return ttl;
}

void zadd_rdata_wireformat(uint16_t *data)
{
	parser->temporary_items[parser->rdata_count].raw_data = data;
	parser->rdata_count++;
}

/**
 * Used for TXT RR's to grow with undefined number of strings.
 */
void zadd_rdata_txt_wireformat(uint16_t *data, int first)
{
	if (data == NULL) {
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
		return;
	}
	dbg_zp("Adding text!\n");
	knot_rdata_item_t *rd;

	/* First STR in str_seq, allocate 65K in first unused rdata
	 * else find last used rdata */
	if (first) {
		rd = &parser->temporary_items[parser->rdata_count];
		rd->raw_data = alloc_rdata(65535 * sizeof(uint8_t));
		if (rd->raw_data == NULL) {
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
		}
		parser->rdata_count++;
		rd->raw_data[0] = 0;
	} else {
		rd = &parser->temporary_items[parser->rdata_count-1];
	}

	if (rd == NULL || rd->raw_data == NULL) {
		return;
	}

	if ((size_t)rd->raw_data[0] + (size_t)data[0] > 65535) {
		zc_error_prev_line("too large rdata element");
		return;
	}

	memcpy((uint8_t *)rd->raw_data + 2 + rd->raw_data[0],
	       data + 1, data[0]);
	rd->raw_data[0] += data[0];
	free(data);
	dbg_zp("Item after add\n");
//	hex_print(rd->raw_data + 1, rd->raw_data[0]);
}

void zadd_rdata_domain(knot_dname_t *dname)
{
	knot_dname_retain(dname);
//	printf("Adding rdata name: %s %p\n", dname->name, dname);
	parser->temporary_items[parser->rdata_count].dname = dname;
	parser->rdata_count++;
}

void parse_unknown_rdata(uint16_t type, uint16_t *wireformat)
{
	dbg_rdata("parsing unknown rdata for type: %s (%d)\n",
	          knot_rrtype_to_string(type), type);
	uint16_t size;
	ssize_t rdata_count;
	ssize_t i;
	knot_rdata_item_t *items = NULL;

	if (wireformat) {
		size = *wireformat;
	} else {
		return;
	}

	rdata_count = rdata_wireformat_to_rdata_atoms(wireformat + 1, type,
						      size, &items);
	dbg_rdata("got %d items\n", rdata_count);
	if (rdata_count < 0) {
		dbg_rdata("wf to items returned error: %s (%d)\n",
		          error_to_str(knot_zcompile_error_msgs, rdata_count),
		          rdata_count);
		zc_error_prev_line("bad unknown RDATA\n");
		/*!< \todo leaks */
		return;
	}

	for (i = 0; i < rdata_count; ++i) {
		if (rdata_atom_is_domain(type, i)) {
			zadd_rdata_domain(items[i].dname);
		} else {
			//XXX won't this create size two times?
			zadd_rdata_wireformat((uint16_t *)items[i].raw_data);
		}
	}
	free(items);
	/* Free wireformat */
	free(wireformat);
	
	dbg_rdata("parse_unknown_rdata: Successfuly parsed unknown rdata.\n");
}

void set_bitnsec(uint8_t bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
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

/*! @} */
