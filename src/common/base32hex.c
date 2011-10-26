/* base32hex.c -- Encode binary data using printable characters.
   Copyright (C) 1999, 2000, 2001, 2004, 2005, 2006, 2010 Free Software
   Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

/* Adapted from base32.{h,c}.  base32.{h,c} was adapted from
 * base64.{h,c} by Ondřej Surý.  base64.{h,c} was written by Simon
 * Josefsson.  Partially adapted from GNU MailUtils
 * (mailbox/filter_trans.c, as of 2004-11-28).  Improved by review
 * from Paul Eggert, Bruno Haible, and Stepan Kasal.
 *
 * See also RFC 4648 <http://www.ietf.org/rfc/rfc4648.txt>.
 *
 * Be careful with error checking.  Here is how you would typically
 * use these functions:
 *
 * bool ok = base32hex_decode_alloc (in, inlen, &out, &outlen);
 * if (!ok)
 *   FAIL: input was not valid base32hex
 * if (out == NULL)
 *   FAIL: memory allocation error
 * OK: data in OUT/OUTLEN
 *
 * size_t outlen = base32hex_encode_alloc (in, inlen, &out);
 * if (out == NULL && outlen == 0 && inlen != 0)
 *   FAIL: input too long
 * if (out == NULL)
 *   FAIL: memory allocation error
 * OK: data in OUT/OUTLEN.
 *
 */

/* Get prototype. */
#include "base32hex.h"

/* Get malloc. */
#include <stdlib.h>

/* Get UCHAR_MAX. */
#include <limits.h>

/* C89 compliant way to cast 'char' to 'unsigned char'. */
static inline unsigned char to_uchar(char ch)
{
	return ch;
}

/* Base32hex encode IN array of size INLEN into OUT array of size OUTLEN.
   If OUTLEN is less than BASE32HEX_LENGTH(INLEN), write as many bytes as
   possible.  If OUTLEN is larger than BASE32HEX_LENGTH(INLEN), also zero
   terminate the output buffer. */
void base32hex_encode(const char *in, size_t inlen, char *out, size_t outlen)
{
	static const char b32str[32] =
		"0123456789ABCDEFGHIJKLMNOPQRSTUV";

	while (inlen && outlen) {
		*out++ = b32str[(to_uchar(in[0]) >> 3) & 0x1f];
		if (!--outlen) {
			break;
		}
		*out++ = b32str[((to_uchar(in[0]) << 2)
		                + (--inlen ? to_uchar(in[1]) >> 6 : 0))
		                & 0x1f];
		if (!--outlen) {
			break;
		}
		*out++ =(inlen
		         ? b32str[(to_uchar(in[1]) >> 1) & 0x1f]
		         : '=');
		if (!--outlen) {
			break;
		}
		*out++ = (inlen
		         ? b32str[((to_uchar(in[1]) << 4)
		                   + (--inlen ? to_uchar(in[2]) >> 4 : 0))
		                   & 0x1f]
		         : '=');
		if (!--outlen) {
			break;
		}
		*out++ = (inlen
		          ? b32str[((to_uchar(in[2]) << 1)
		                   + (--inlen ? to_uchar(in[3]) >> 7 : 0))
		                   & 0x1f]
		          : '=');
		if (!--outlen) {
			break;
		}
		*out++ = (inlen
		          ? b32str[(to_uchar(in[3]) >> 2) & 0x1f]
		          : '=');
		if (!--outlen)
		{
			break;
		}
		*out++ = (inlen
		          ? b32str[((to_uchar(in[3]) << 3)
		                   + (--inlen ? to_uchar(in[4]) >> 5 : 0))
		                   & 0x1f]
		          : '=');
		if (!--outlen) {
			break;
		}
		*out++ = inlen ? b32str[to_uchar(in[4]) & 0x1f] : '=';
		if (!--outlen) {
			break;
		}
		if (inlen) {
			inlen--;
		}
		if (inlen) {
			in += 5;
		}
	}

	if (outlen) {
		*out = '\0';
	}
}

/* Allocate a buffer and store zero terminated base32hex encoded data
   from array IN of size INLEN, returning BASE32HEX_LENGTH(INLEN), i.e.,
   the length of the encoded data, excluding the terminating zero.  On
   return, the OUT variable will hold a pointer to newly allocated
   memory that must be deallocated by the caller.  If output string
   length would overflow, 0 is returned and OUT is set to NULL.  If
   memory allocation failed, OUT is set to NULL, and the return value
   indicates length of the requested memory block, i.e.,
   BASE32HEX_LENGTH(inlen) + 1. */
size_t base32hex_encode_alloc(const char *in, size_t inlen, char **out)
{
	size_t outlen = 1 + BASE32HEX_LENGTH (inlen);

	/* Check for overflow in outlen computation.
	 *
	 * If there is no overflow, outlen >= inlen.
	 *
	 * If the operation (inlen + 2) overflows then it yields at most +1, so
	 * outlen is 0.
	 *
	 * If the multiplication overflows, we lose at least half of the
	 * correct value, so the result is < ((inlen + 2) / 3) * 2, which is
	 * less than (inlen + 2) * 0.66667, which is less than inlen as soon as
	 * (inlen > 4).
	 */
	if (inlen > outlen)
	{
		*out = NULL;
		return 0;
	}

	*out = malloc(outlen);
	if (!*out) {
		return outlen;
	}

	base32hex_encode(in, inlen, *out, outlen);

	return outlen - 1;
}

/* With this approach this file works independent of the charset used
   (think EBCDIC).  However, it does assume that the characters in the
   Base32hex alphabet (A-Z2-7) are encoded in 0..255.  POSIX
   1003.1-2001 require that char and unsigned char are 8-bit
   quantities, though, taking care of that problem.  But this may be a
   potential problem on non-POSIX C99 platforms.

   IBM C V6 for AIX mishandles "#define B32(x) ...'x'...", so use "_"
   as the formal parameter rather than "x".  */
#define B32(_)					\
	((_) == '0' ? 0				\
	 : (_) == '1' ? 1			\
	 : (_) == '2' ? 2			\
	 : (_) == '3' ? 3			\
	 : (_) == '4' ? 4			\
	 : (_) == '5' ? 5			\
	 : (_) == '6' ? 6			\
	 : (_) == '7' ? 7			\
	 : (_) == '8' ? 8			\
	 : (_) == '9' ? 9			\
	 : (_) == 'A' ? 10			\
	 : (_) == 'B' ? 11			\
	 : (_) == 'C' ? 12			\
	 : (_) == 'D' ? 13			\
	 : (_) == 'E' ? 14			\
	 : (_) == 'F' ? 15			\
	 : (_) == 'G' ? 16			\
	 : (_) == 'H' ? 17			\
	 : (_) == 'I' ? 18			\
	 : (_) == 'J' ? 19			\
	 : (_) == 'K' ? 20			\
	 : (_) == 'L' ? 21			\
	 : (_) == 'M' ? 22			\
	 : (_) == 'N' ? 23			\
	 : (_) == 'O' ? 24			\
	 : (_) == 'P' ? 25			\
	 : (_) == 'Q' ? 26			\
	 : (_) == 'R' ? 27			\
	 : (_) == 'S' ? 28			\
	 : (_) == 'T' ? 29			\
	 : (_) == 'U' ? 30			\
	 : (_) == 'V' ? 31			\
	 : (_) == 'a' ? 10			\
	 : (_) == 'b' ? 11			\
	 : (_) == 'c' ? 12			\
	 : (_) == 'd' ? 13			\
	 : (_) == 'e' ? 14			\
	 : (_) == 'f' ? 15			\
	 : (_) == 'g' ? 16			\
	 : (_) == 'h' ? 17			\
	 : (_) == 'i' ? 18			\
	 : (_) == 'j' ? 19			\
	 : (_) == 'k' ? 20			\
	 : (_) == 'l' ? 21			\
	 : (_) == 'm' ? 22			\
	 : (_) == 'n' ? 23			\
	 : (_) == 'o' ? 24			\
	 : (_) == 'p' ? 25			\
	 : (_) == 'q' ? 26			\
	 : (_) == 'r' ? 27			\
	 : (_) == 's' ? 28			\
	 : (_) == 't' ? 29			\
	 : (_) == 'u' ? 30			\
	 : (_) == 'v' ? 31			\
	 : -1)

static const signed char b32[0x100] = {
	B32 (0), B32 (1), B32 (2), B32 (3),
	B32 (4), B32 (5), B32 (6), B32 (7),
	B32 (8), B32 (9), B32 (10), B32 (11),
	B32 (12), B32 (13), B32 (14), B32 (15),
	B32 (16), B32 (17), B32 (18), B32 (19),
	B32 (20), B32 (21), B32 (22), B32 (23),
	B32 (24), B32 (25), B32 (26), B32 (27),
	B32 (28), B32 (29), B32 (30), B32 (31),
	B32 (32), B32 (33), B32 (34), B32 (35),
	B32 (36), B32 (37), B32 (38), B32 (39),
	B32 (40), B32 (41), B32 (42), B32 (43),
	B32 (44), B32 (45), B32 (46), B32 (47),
	B32 (48), B32 (49), B32 (50), B32 (51),
	B32 (52), B32 (53), B32 (54), B32 (55),
	B32 (56), B32 (57), B32 (58), B32 (59),
	B32 (60), B32 (61), B32 (62), B32 (63),
	B32 (64), B32 (65), B32 (66), B32 (67),
	B32 (68), B32 (69), B32 (70), B32 (71),
	B32 (72), B32 (73), B32 (74), B32 (75),
	B32 (76), B32 (77), B32 (78), B32 (79),
	B32 (80), B32 (81), B32 (82), B32 (83),
	B32 (84), B32 (85), B32 (86), B32 (87),
	B32 (88), B32 (89), B32 (90), B32 (91),
	B32 (92), B32 (93), B32 (94), B32 (95),
	B32 (96), B32 (97), B32 (98), B32 (99),
	B32 (100), B32 (101), B32 (102), B32 (103),
	B32 (104), B32 (105), B32 (106), B32 (107),
	B32 (108), B32 (109), B32 (110), B32 (111),
	B32 (112), B32 (113), B32 (114), B32 (115),
	B32 (116), B32 (117), B32 (118), B32 (119),
	B32 (120), B32 (121), B32 (122), B32 (123),
	B32 (124), B32 (125), B32 (126), B32 (127),
	B32 (128), B32 (129), B32 (130), B32 (131),
	B32 (132), B32 (133), B32 (134), B32 (135),
	B32 (136), B32 (137), B32 (138), B32 (139),
	B32 (140), B32 (141), B32 (142), B32 (143),
	B32 (144), B32 (145), B32 (146), B32 (147),
	B32 (148), B32 (149), B32 (150), B32 (151),
	B32 (152), B32 (153), B32 (154), B32 (155),
	B32 (156), B32 (157), B32 (158), B32 (159),
	B32 (160), B32 (161), B32 (162), B32 (163),
	B32 (164), B32 (165), B32 (166), B32 (167),
	B32 (168), B32 (169), B32 (170), B32 (171),
	B32 (172), B32 (173), B32 (174), B32 (175),
	B32 (176), B32 (177), B32 (178), B32 (179),
	B32 (180), B32 (181), B32 (182), B32 (183),
	B32 (184), B32 (185), B32 (186), B32 (187),
	B32 (188), B32 (189), B32 (190), B32 (191),
	B32 (192), B32 (193), B32 (194), B32 (195),
	B32 (196), B32 (197), B32 (198), B32 (199),
	B32 (200), B32 (201), B32 (202), B32 (203),
	B32 (204), B32 (205), B32 (206), B32 (207),
	B32 (208), B32 (209), B32 (210), B32 (211),
	B32 (212), B32 (213), B32 (214), B32 (215),
	B32 (216), B32 (217), B32 (218), B32 (219),
	B32 (220), B32 (221), B32 (222), B32 (223),
	B32 (224), B32 (225), B32 (226), B32 (227),
	B32 (228), B32 (229), B32 (230), B32 (231),
	B32 (232), B32 (233), B32 (234), B32 (235),
	B32 (236), B32 (237), B32 (238), B32 (239),
	B32 (240), B32 (241), B32 (242), B32 (243),
	B32 (244), B32 (245), B32 (246), B32 (247),
	B32 (248), B32 (249), B32 (250), B32 (251),
	B32 (252), B32 (253), B32 (254), B32 (255)
};

#if UCHAR_MAX == 255
#define uchar_in_range(c) true
#else
#define uchar_in_range(c) ((c) <= 255)
#endif

/* Return true if CH is a character from the Base32hex alphabet, and
   false otherwise.  Note that '=' is padding and not considered to be
   part of the alphabet.  */
bool isbase32hex(char ch)
{
	return uchar_in_range(to_uchar(ch)) && 0 <= b32[to_uchar(ch)];
}

/* Decode base32hex encoded input array IN of length INLEN to output
   array OUT that can hold *OUTLEN bytes.  Return true if decoding was
   successful, i.e. if the input was valid base32hex data, false
   otherwise.  If *OUTLEN is too small, as many bytes as possible will
   be written to OUT.  On return, *OUTLEN holds the length of decoded
   bytes in OUT.  Note that as soon as any non-alphabet characters are
   encountered, decoding is stopped and false is returned.  This means
   that, when applicable, you must remove any line terminators that is
   part of the data stream before calling this function.  */
bool base32hex_decode(const char *in, size_t inlen, char *out, size_t *outlen)
{
	size_t outleft = *outlen;

	while (inlen >= 2) {
		if (!isbase32hex(in[0]) || !isbase32hex(in[1])) {
			break;
		}

		if (outleft) {
			*out++ = ((b32[to_uchar(in[0])] << 3)
			          | (b32[to_uchar(in[1])] >> 2));
			outleft--;
		}

		if (inlen == 2) {
			break;
		}

		if (in[2] == '=') {
			if (inlen != 8) {
				break;
			}
			
			if ((in[3] != '=') ||
			    (in[4] != '=') ||
			    (in[5] != '=') ||
			    (in[6] != '=') ||
			    (in[7] != '=')) {
				break;
			}
		} else {
			if (!isbase32hex(in[2]) || !isbase32hex(in[3])) {
				break;
			}

			if (outleft) {
				*out++ = ((b32[to_uchar(in[1])] << 6)
				          | ((b32[to_uchar(in[2])] << 1) & 0x3E)
				          | (b32[to_uchar(in[3])] >> 4));
				outleft--;
			}
			
			if (inlen == 4) {
				break;
			}
			
			if (in[4] == '=') {
				if (inlen != 8) {
					break;
				}
				
				if ((in[5] != '=') ||
				    (in[6] != '=') ||
				    (in[7] != '=')) {
					break;
				}
			} else {
				if (!isbase32hex (in[3]) || !isbase32hex(in[4])) {
					break;
				}
				
				if (outleft) {
					*out++ = ((b32[to_uchar(in[3])] << 4)
					        | (b32[to_uchar(in[4])] >> 1));
					outleft--;
				}

				if (inlen == 5) {
					break;
				}

				if (in[5] == '=') {
					if (inlen != 8) {
						break;
					}
					
					if ((in[6] != '=')
					    || (in[7] != '=')) {
						break;
					}
				} else {
					if (!isbase32hex (in[5])
					    || !isbase32hex (in[6])) {
						break;
					}
					
					if (outleft) {
						*out++ = ((b32[to_uchar(in[4])]
						           << 7)
						  | (b32[to_uchar(in[5])] << 2)
						  | (b32[to_uchar(in[6])]
						     >> 3));
						outleft--;
					}

					if (inlen == 7) {
						break;
					}

					if (in[7] == '=') {
						if (inlen != 8) {
							break;
						}
					} else {
						if (!isbase32hex (in[7])) {
							break;
						}
						
						if (outleft) {
							*out++ =
							  ((b32[to_uchar(in[6])]
							   << 5) | (b32[
							     to_uchar(in[7])]));
							outleft--;
						}
					}
				}
			}
		}
		
		in += 8;
		inlen -= 8;
	}
	
	*outlen -= outleft;
	
	if (inlen != 0) {
		return false;
	}

	return true;
}

/* Allocate an output buffer in *OUT, and decode the base32hex encoded
   data stored in IN of size INLEN to the *OUT buffer.  On return, the
   size of the decoded data is stored in *OUTLEN.  OUTLEN may be NULL,
   if the caller is not interested in the decoded length.  *OUT may be
   NULL to indicate an out of memory error, in which case *OUTLEN
   contains the size of the memory block needed.  The function returns
   true on successful decoding and memory allocation errors.  (Use the
   *OUT and *OUTLEN parameters to differentiate between successful
   decoding and memory error.)  The function returns false if the
   input was invalid, in which case *OUT is NULL and *OUTLEN is
   undefined. */
bool base32hex_decode_alloc(const char *in, size_t inlen, char **out,
                         size_t *outlen)
{
	/* This may allocate a few bytes too much, depending on input,
	   but it's not worth the extra CPU time to compute the exact amount.
	   The exact amount is 5 * inlen / 8, minus 1 if the input ends
	   with "=" and minus another 1 if the input ends with "==", etc.
	   Dividing before multiplying avoids the possibility of overflow.  */
	size_t needlen = 5 * (inlen / 8) + 4;

	*out = malloc(needlen);
	if (!*out) {
		return true;
	}

	if (!base32hex_decode(in, inlen, *out, &needlen)) {
		free (*out);
		*out = NULL;
		return false;
	}

	if (outlen) {
		*outlen = needlen;
	}

	return true;
}

#ifdef MAIN

#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "base32hex.h"

int main(int argc, char **argv) {
	int i = 1;
	size_t inlen, outlen, argvlen;
	char *out;
	char *in;
	bool ok;

	while (argc > 1) {
		argv++; argc--;
		argvlen = strlen(*argv);

		outlen = base32hex_encode_alloc(*argv, argvlen, &out);

		if (out == NULL && outlen == 0 && inlen != 0) {
			fprintf(stderr, "ERROR(encode): input too long: %zd\n",
			        outlen);
			return 1;
		}

		if (out == NULL) {
			fprintf(stderr, "ERROR(encode): memory allocation error"
			        "\n");
			return 1;
		}

		ok = base32hex_decode_alloc(out, outlen, &in, &inlen);

		if (!ok) {
			fprintf(stderr, "ERROR(decode): input was not valid "
			        "base32hex: `%s'\n", out);
			return 1;
		}

		if (in == NULL) {
			fprintf(stderr, "ERROR(decode): memory allocation "
			        "error\n");
		}

		if ((inlen != argvlen) ||
		    strcmp(*argv, in) != 0) {
			fprintf(stderr, "ERROR(encode/decode): input `%s' and "
			        "output `%s'\n", *argv, in);
			return 1;
		}
		printf("INPUT: `%s'\nENCODE: `%s'\nDECODE: `%s'\n", *argv, out,
		       in);
	}
}

#endif
