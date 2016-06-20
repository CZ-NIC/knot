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
/*!
 * \file token.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief String tokenizer and simple scanner.
 *
 * \addtogroup knot_utils
 * @{
 */

#pragma once

#include <stdio.h>

/*!
 * \brief Example of token table:
 *
 * \warning Table _must_ be lexicographically ordered.
 *
 * const char *tok_tbl[] = {
 * // LEN  STRING
 *   "\x4" "abcd",
 *   "\x5" "class",
 *   NULL // END
 * }
 */
/*! \brief String part of the token. */
#define TOK_S(x) ((x)+1)
/*! \brief Len of the token. */
#define TOK_L(x) ((unsigned char)(x)[0])

/*!
 * \brief Scan for matching token described by a match table.
 *
 * Table consists of strings, prefixed with 1B length.
 *
 * \param lp Pointer to current line.
 * \param tbl Match description table.
 * \param lpm Pointer to longest prefix match.
 * \retval index to matching record.
 * \retval -1 if no match is found, lpm may be set to longest prefix match.
 */
int tok_scan(const char* lp, const char **tbl, int *lpm);

/*!
 * \brief Find token from table in a line buffer.
 * \param lp Pointer to current line.
 * \param tbl Match description table.
 * \retval index to matching record.
 * \retval error code if no match is found
 */
int tok_find(const char *lp, const char **tbl);

/*!
 * \brief Return pointer to next non-blank character.
 * \param lp Pointer to current line.
 * \return ptr to next non-blank character.
 */
const char *tok_skipspace(const char *lp);

/*! @} */
