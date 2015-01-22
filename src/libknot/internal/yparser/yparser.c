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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libknot/internal/yparser/yparser.h"
#include "libknot/internal/yparser/ypbody.h"
#include "libknot/errcode.h"

static void init_parser(
	yp_parser_t *parser)
{
	memset(parser, 0, sizeof(*parser));

	parser->cs = _start_state();
	parser->file.descriptor = -1;
	parser->line_count = 1;
}

static void purge_parser(
	yp_parser_t *parser)
{
	// Cleanup the current file context if any.
	if (parser->file.descriptor != -1) {
		munmap((void *)parser->input.start,
		       parser->input.end - parser->input.start);
		close(parser->file.descriptor);
		free(parser->file.name);
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

	// Initialize the parser.
	purge_parser(parser);
	init_parser(parser);

	// Set the parser input limits.
	parser->input.start   = input;
	parser->input.current = input;
	parser->input.end     = input + size;
	parser->input.eof     = false;

	return KNOT_EOK;
}

int yp_set_input_file(
	yp_parser_t *parser,
	const char *file_name)
{
	if (parser == NULL || file_name == NULL) {
		return KNOT_EINVAL;
	}

	// Initialize the parser.
	purge_parser(parser);
	init_parser(parser);

	// Try to open the file.
	parser->file.descriptor = open(file_name, O_RDONLY);
	if (parser->file.descriptor == -1) {
		return KNOT_EFILE;
	}

	// Check for regular file input.
	struct stat file_stat;
	if (fstat(parser->file.descriptor, &file_stat) == -1 ||
	    !S_ISREG(file_stat.st_mode)) {
		close(parser->file.descriptor);
		return KNOT_EFILE;
	}

	// Map the file to the memory.
	const char *start = mmap(0, file_stat.st_size, PROT_READ, MAP_SHARED,
	                         parser->file.descriptor, 0);
	if (start == MAP_FAILED) {
		close(parser->file.descriptor);
		return KNOT_ENOMEM;
	}

	parser->file.name = strdup(file_name);

	// Set the parser input limits.
	parser->input.start   = start;
	parser->input.current = start;
	parser->input.end     = start + file_stat.st_size;
	parser->input.eof     = false;

	return KNOT_EOK;
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
		// Check for the end of the input.
		if (parser->input.current == parser->input.end) {
			if (parser->input.eof) {
				// End of parsing.
				return KNOT_EOF;
			} else {
				// Set the parser to final parsing.
				parser->input.eof = true;
			}
		}

		// Parse the next item.
		ret = _parse(parser);
	} while (ret == KNOT_EFEWDATA);

	return ret;
}
