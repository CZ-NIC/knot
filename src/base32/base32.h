/* base32.h -- Encode binary data using printable characters.
   Copyright (C) 2004, 2005, 2006, 2010 Free Software Foundation, Inc.
   Written by Ondřej Surý & Simon Josefsson.

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

#ifndef BASE32_H
# define BASE32_H

/* Get size_t. */
# include <stddef.h>

/* Get bool. */
# include <stdbool.h>

/* This uses that the expression (n+(k-1))/k means the smallest
   integer >= n/k, i.e., the ceiling of n/k.  */
# define BASE32_LENGTH(inlen) ((((inlen) + 4) / 5) * 8)

extern bool isbase32 (char ch);

extern void base32_encode (const char *in, size_t inlen,
			   char *out, size_t outlen);

extern size_t base32_encode_alloc (const char *in, size_t inlen, char **out);

extern bool base32_decode (const char *in, size_t inlen,
			   char *out, size_t *outlen);

extern bool base32_decode_alloc (const char *in, size_t inlen,
				 char **out, size_t *outlen);

#endif /* BASE32_H */
