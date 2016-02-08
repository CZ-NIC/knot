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

#include "libknot/yparser/yparser.h"
#include "libknot/errcode.h"

extern int _yp_start_state;
extern int _yp_parse(yp_parser_t *parser);

void yp_init(
	yp_parser_t *parser)
{
	if (parser == NULL) {
		return;
	}

	memset(parser, 0, sizeof(*parser));

	parser->cs = _yp_start_state;
	parser->file.descriptor = -1;
	parser->line_count = 1;
}

void yp_deinit(
	yp_parser_t *parser)
{
	if (parser == NULL) {
		return;
	}

	if (parser->file.descriptor != -1) {
		munmap((void *)parser->input.start,
		       parser->input.end - parser->input.start);
		close(parser->file.descriptor);
		free(parser->file.name);
	}
}

int yp_set_input_string(
	yp_parser_t *parser,
	const char *input,
	size_t size)
{
	if (parser == NULL || input == NULL) {
		return KNOT_EINVAL;
	}

	// Reinitialize the parser.
	yp_deinit(parser);
	yp_init(parser);

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

	// Reinitialize the parser.
	yp_deinit(parser);
	yp_init(parser);

	// Try to open the file.
	parser->file.descriptor = open(file_name, O_RDONLY);
	if (parser->file.descriptor == -1) {
		return knot_map_errno();
	}

	// Check for regular file input.
	struct stat file_stat;
	if (fstat(parser->file.descriptor, &file_stat) == -1) {
		close(parser->file.descriptor);
		return knot_map_errno();
	} else if (!S_ISREG(file_stat.st_mode)) {
		close(parser->file.descriptor);
		return KNOT_EFILE;
	}

	char *start = NULL;

	// Check for empty file (cannot mmap).
	if (file_stat.st_size > 0) {
		// Map the file to the memory.
		start = mmap(0, file_stat.st_size, PROT_READ, MAP_SHARED,
		             parser->file.descriptor, 0);
		if (start == MAP_FAILED) {
			close(parser->file.descriptor);
			return KNOT_ENOMEM;
		}

		// Try to set the mapped memory advise to sequential.
		(void)madvise(start, file_stat.st_size, MADV_SEQUENTIAL);

		parser->input.eof = false;
	} else {
		parser->input.eof = true;
	}

	parser->file.name = strdup(file_name);

	// Set the parser input limits.
	parser->input.start   = start;
	parser->input.current = start;
	parser->input.end     = start + file_stat.st_size;

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
		ret = _yp_parse(parser);
	} while (ret == KNOT_EFEWDATA);

	return ret;
}
