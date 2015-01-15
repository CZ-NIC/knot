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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <fcntl.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libknot/internal/yparser/yparser.h"
#include "libknot/internal/yparser/ypbody.h"
#include "libknot/errcode.h"

/*! Maximal input file block size. */
#define FILE_BLOCK_SIZE		5000000

static void init_parser(
	yp_parser_t *parser)
{
	memset(parser, 0, sizeof(*parser));

	parser->cs = _start_state();
	parser->file.path = strdup(".");
	parser->file.descriptor = -1;
	parser->line_count = 1;
}

static void purge_parser(
	yp_parser_t *parser)
{
	free(parser->file.path);

	// Cleanup the current file context if any.
	if (parser->file.descriptor != -1) {
		munmap((void *)parser->input.start,
		       parser->input.end - parser->input.start);
		free(parser->file.name);
		close(parser->file.descriptor);
	}
}

yp_parser_t* yp_create(
	void)
{
	yp_parser_t *parser = malloc(sizeof(yp_parser_t));
	if (parser == NULL) {
		return NULL;
	}

	init_parser(parser);

	return parser;
}

void yp_free(
	yp_parser_t *parser)
{
	if (parser == NULL) {
		return;
	}

	purge_parser(parser);
	free(parser);
}

int yp_set_input_string(
	yp_parser_t *parser,
	const char *input,
	size_t size)
{
	if (parser == NULL || input == NULL) {
		return KNOT_EINVAL;
	}

	// Initialize parser.
	purge_parser(parser);
	init_parser(parser);

	// Set the input string as a one block to parse.
	parser->input.start   = input;
	parser->input.current = input;
	parser->input.end     = input + size;
	parser->input.eof     = false;

	return KNOT_EOK;
}

static int remap_file_block(
	yp_parser_t *parser)
{
	// Compute the start of the following block.
	size_t new_start = parser->file.block_end;
	if (new_start >= parser->file.size) {
		return KNOT_EOK;
	}

	// Compute the end of the following block.
	size_t new_end = new_start + parser->file.block_size;
	if (new_end > parser->file.size) {
		new_end = parser->file.size;
	}

	size_t new_block_size = new_end - new_start;

	// Unmap the current file block.
	if (parser->input.start != NULL) {
		munmap((void *)parser->input.start,
		       parser->input.end - parser->input.start);
	}

	// Mmap the following file block.
	char *data = mmap(0, new_block_size, PROT_READ, MAP_SHARED,
	                  parser->file.descriptor, new_start);
	if (data == MAP_FAILED) {
		return KNOT_ENOMEM;
	}

	parser->file.block_end += new_block_size;

	// Set new block limits.
	parser->input.start   = data;
	parser->input.end     = parser->input.start + new_block_size;
	parser->input.current = parser->input.start;
	parser->input.eof     = false;

	return KNOT_EOK;
}

int yp_set_input_file(
	yp_parser_t *parser,
	const char *file_name)
{
	long page_size;
	struct stat file_stat;

	if (parser == NULL || file_name == NULL) {
		return KNOT_EINVAL;
	}

	// Initialize parser.
	purge_parser(parser);
	init_parser(parser);

	// Getting OS page size.
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) {
		return KNOT_ESYSTEM;
	}

	// Try to open the file.
	parser->file.descriptor = open(file_name, O_RDONLY);
	if (parser->file.descriptor == -1) {
		return KNOT_EFILE;
	}

	// Getting file information.
	if (fstat(parser->file.descriptor, &file_stat) == -1) {
		close(parser->file.descriptor);
		return KNOT_EFILE;
	}

	// Check for directory.
	if (S_ISDIR(file_stat.st_mode)) {
		close(parser->file.descriptor);
		return KNOT_EFILE;
	}

	// Get absolute path of the file.
	char *full_name = realpath(file_name, NULL);
	if (full_name != NULL) {
		free(parser->file.path);
		parser->file.path = strdup(dirname(full_name));
		free(full_name);
	} else {
		close(parser->file.descriptor);
		return KNOT_EFILE;
	}

	parser->file.name = strdup(file_name);
	parser->file.size = file_stat.st_size;
	// Block size adjustment to the multiple of page size.
	parser->file.block_size = (FILE_BLOCK_SIZE / page_size) * page_size;
	parser->file.block_end = 0;

	return remap_file_block(parser);
}

int yp_parse(
	yp_parser_t *parser)
{
	if (parser == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EPARSEFAIL;

	// Run the parser until found new item, error or end of input.
	do {
		// Check for the end of the current block.
		if (parser->input.current == parser->input.end) {
			// Remap the block if not end of input file.
			if (parser->file.descriptor != -1 &&
			    parser->file.block_end < parser->file.size) {
				ret = remap_file_block(parser);
			// Set the parser to final parsing.
			} else if (!parser->input.eof) {
				parser->input.eof = true;
				ret = KNOT_EOK;
			// End of parsing.
			} else {
				ret = KNOT_EOF;
			}

			if (ret != KNOT_EOK) {
				return ret;
			}
		}

		// Parse the next item.
		ret = _parse(parser);
	} while (ret == KNOT_EFEWDATA);

	return ret;
}
