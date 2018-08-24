/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
/*!
 * \file
 *
 * \brief Simple parser (Yparser) of a YAML-inspired data format.
 *
 * \addtogroup yparser
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

/*! Maximal length of textual key value. */
#define YP_MAX_TXT_KEY_LEN	128
/*! Maximal length of textual data value. */
#define YP_MAX_TXT_DATA_LEN	32768

/*! Parser events indicating type of lastly parsed item. */
typedef enum {
	YP_ENULL = 0, /*!< No valid data. */
	YP_EKEY0,     /*!< First level item. */
	YP_EKEY1,     /*!< Second level item. */
	YP_EID,       /*!< Second level identifier. */
} yp_event_t;

/*! Context structure of yparser. */
typedef struct {
	/*! Current parser state (Ragel internals). */
	int cs;
	/*! Indication if the current item was already processed. */
	bool processed;
	/*! Current block indentation. */
	size_t indent;
	/*! Last id dash position. */
	size_t id_pos;

	/*! Input parameters. */
	struct {
		/*! Start of the block. */
		const char *start;
		/*! Current parser position. */
		const char *current;
		/*! End of the block. */
		const char *end;
		/*! Indication for the final block parsing. */
		bool eof;
	} input;

	/*! File input parameters. */
	struct {
		/*! File name. */
		char *name;
		/*! File descriptor. */
		int descriptor;
	} file;

	/*! [out] Current line number (error location). */
	size_t line_count;
	/*! [out] Current event. */
	yp_event_t event;
	/*! [out] Parsed key (zero terminated string). */
	char key[YP_MAX_TXT_KEY_LEN];
	/*! [out] Key length. */
	size_t key_len;
	/*! [out] Parsed data (zero terminated string). */
	char data[YP_MAX_TXT_DATA_LEN];
	/*! [out] Data length. */
	size_t data_len;
} yp_parser_t;

/*!
 * Initializes the parser.
 *
 * \param[in] parser Parser context.
 */
void yp_init(
	yp_parser_t *parser
);

/*!
 * Deinitializes the parser.
 *
 * \param[in] parser Parser context.
 */
void yp_deinit(
	yp_parser_t *parser
);

/*!
 * Sets the parser to parse given string.
 *
 * \param[in] parser Parser context.
 * \param[in] input The string to parse.
 * \param[in] size Length of the string.
 *
 * \return Error code, KNOT_EOK if success.
 */
int yp_set_input_string(
	yp_parser_t *parser,
	const char *input,
	size_t size
);

/*!
 * Sets the parser to parse given file.
 *
 * \param[in] parser Parser context.
 * \param[in] file_name The filename to parse.
 *
 * \return Error code, KNOT_EOK if success.
 */
int yp_set_input_file(
	yp_parser_t *parser,
	const char *file_name
);

/*!
 * Parses one item from the input.
 *
 * If the item has more values, this function returns for each value. The item
 * can also have no value.
 *
 * \param[in] parser Parser context.
 *
 * \return Error code, KNOT_EOK if success, KNOT_EOF if end of data.
 */
int yp_parse(
	yp_parser_t *parser
);

/*! @} */
