/*!
 * \file parser-util.c
 *
 * \author NLnet Labs
 *         Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *         See LICENSE for the license.
 *
 * \brief utility functions for zone parser.
 *
 * \addtogroup zoneparser
 * @{
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

#include "parser-util.h"
#include "zoneparser.h"
#include "descriptor.h"
#include "utils.h"

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

int my_b32_pton(const char *src, uint8_t *target, size_t tsize)
{
	char ch;
	size_t p = 0;

	memset(target, '\0', tsize);
	while ((ch = *src++)) {
		uint8_t d;
		size_t b;
		size_t n;

		if (p + 5 >= tsize * 8) {
			return -1;
		}

		if (isspace(ch)) {
			continue;
		}

		if (ch >= '0' && ch <= '9') {
			d = ch - '0';
		} else if (ch >= 'A' && ch <= 'V') {
			d = ch - 'A' + 10;
		} else if (ch >= 'a' && ch <= 'v') {
			d = ch - 'a' + 10;
		} else {
			return -1;
		}

		b = 7 - p % 8;
		n = p / 8;

		if (b >= 4) {
			target[n] |= d << (b - 4);
		} else {
			target[n] |= d >> (4 - b);
			target[n+1] |= d << (b + 4);
		}
		p += 5;
	}
	return (p + 7) / 8;
}


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
	dnslib_strlcpy(dst, tmp, size);
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
	dnslib_strlcpy(dst, tmp, size);
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

