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

#include <config.h>
#include <stdint.h>			// uint32_t
#include <stdlib.h>			// calloc
#include <stdio.h>			// sprintf
#include <fcntl.h>			// open
#include <libgen.h>			// dirname
#include <stdbool.h>			// bool
#include <string.h>			// strdup
#include <math.h>			// pow
#include <sys/mman.h>			// mmap
#include <sys/types.h>			// (OpenBSD)
#include <sys/socket.h>			// AF_INET (BSD)
#include <sys/stat.h>			// fstat
#include <netinet/in.h>			// in_addr (BSD)
#include <arpa/inet.h>			// inet_pton
#include <unistd.h>			// sysconf

#include "zscanner/scanner.h"
#include "zscanner/functions.h"
#include "libknot/descriptor.h"

/*! \brief Mmap block size in bytes. This value is then adjusted to the
 *         multiple of memory pages which fit in.
 */
#define BLOCK_SIZE		30000000

/*! \brief Last artificial block which ensures final newline character. */
#define NEWLINE_BLOCK		"\n"

/*! \brief Shorthand for setting warning data. */
#define WARN(code) { s->error_code = code; }
/*! \brief Shorthand for setting error data. */
#define ERR(code) { s->error_code = code; s->stop = true; }

/*!
 * \brief Empty function which is called if no callback function is specified.
 */
static inline void noop(zs_scanner_t *s)
{
	(void)s;
}

/*!
 * \brief Writes record type number to r_data.
 *
 * \param type		Type number.
 * \param rdata_tail	Position where to write type number to.
 */
static inline void type_num(const uint16_t type, uint8_t **rdata_tail)
{
	*((uint16_t *)*rdata_tail) = htons(type);
	*rdata_tail += 2;
}

/*!
 * \brief Sets bit to bitmap window.
 *
 * \param type		Type number.
 * \param s		Scanner context.
 */
static inline void window_add_bit(const uint16_t type, zs_scanner_t *s) {
	uint8_t win      = type / 256;
	uint8_t bit_pos  = type % 256;
	uint8_t byte_pos = bit_pos / 8;

	((s->windows[win]).bitmap)[byte_pos] |= 128 >> (bit_pos % 8);

	if ((s->windows[win]).length < byte_pos + 1) {
		(s->windows[win]).length = byte_pos + 1;
	}

	if (s->last_window < win) {
		s->last_window = win;
	}
}

// Include scanner file (in Ragel).
%%{
	machine zone_scanner;

	include "scanner_body.rl";

	write data;
}%%

__attribute__((visibility("default")))
zs_scanner_t* zs_scanner_create(const char     *origin,
                                const uint16_t rclass,
                                const uint32_t ttl,
                                void (*process_record)(zs_scanner_t *),
                                void (*process_error)(zs_scanner_t *),
                                void *data)
{
	char settings[1024];

	if (origin == NULL) {
		return NULL;
	}

	zs_scanner_t *s = calloc(1, sizeof(zs_scanner_t));
	if (s == NULL) {
		return NULL;
	}

	// Nonzero initial scanner state.
	s->cs = zone_scanner_start;

	// Disable processing during parsing of settings.
	s->process_record = &noop;
	s->process_error = &noop;

	// Create ORIGIN directive and parse it using scanner to set up origin.
	const char *format;
	size_t origin_len = strlen(origin);
	if (origin_len > 0 && origin[origin_len - 1] != '.') {
		format = "$ORIGIN %s.\n";
	} else {
		format = "$ORIGIN %s\n";
	}
	int ret = snprintf(settings, sizeof(settings), format, origin);
	if (ret <= 0 || (size_t)ret >= sizeof(settings) ||
	    zs_scanner_parse(s, settings, settings + ret, true) != 0) {
		zs_scanner_free(s);
		return NULL;
	}

	// Set scanner defaults.
	s->default_class = rclass;
	s->default_ttl = ttl;
	s->process_record = process_record ? process_record : &noop;
	s->process_error = process_error ? process_error : &noop;
	s->data = data;
	s->path = strdup(".");
	s->line_counter = 1;

	return s;
}

__attribute__((visibility("default")))
void zs_scanner_free(zs_scanner_t *s)
{
	if (s != NULL) {
		free(s->path);
		free(s);
	}
}

static void parse_block(zs_scanner_t *s,
                        const char   *start,
                        const char   *end,
                        const bool   is_eof)
{
	// Necessary scanner variables.
	const char *p = start;
	const char *pe = end;
	char       *eof = NULL;
	int        stack[RAGEL_STACK_SIZE];

	// Auxiliary variables which are used in scanner body.
	struct in_addr  addr4;
	struct in6_addr addr6;
	uint32_t timestamp;
	int16_t  window;
	int      ret;

	// Next 2 variables are for better performance.
	// Restoring r_data pointer to next free space.
	uint8_t *rdata_tail = s->r_data + s->r_data_tail;
	// Initialization of the last r_data byte.
	uint8_t *rdata_stop = s->r_data + MAX_RDATA_LENGTH - 1;

	// Restoring scanner states.
	int cs  = s->cs;
	int top = s->top;
	memcpy(stack, s->stack, sizeof(stack));

	// End of file check.
	if (is_eof) {
		eof = (char *)pe;
	}

	// Writing scanner body (in C).
	%% write exec;

	// Check if scanner state machine is in uncovered state.
	if (cs == zone_scanner_error) {
		ERR(ZS_UNCOVERED_STATE);
		s->error_counter++;

		// Fill error context data.
		for (s->buffer_length = 0;
		     ((p + s->buffer_length) < pe) &&
		     (s->buffer_length < sizeof(s->buffer) - 1);
		     s->buffer_length++)
		{
			// Only rest of the current line.
			if (*(p + s->buffer_length) == '\n') {
				break;
			}
			s->buffer[s->buffer_length] = *(p + s->buffer_length);
		}

		// Ending string in buffer.
		s->buffer[s->buffer_length++] = 0;

		// Processing error.
		s->process_error(s);

		return;
	}

	// Check unclosed multiline record.
	if (is_eof && s->multiline) {
		ERR(ZS_UNCLOSED_MULTILINE);
		s->error_counter++;
		s->process_error(s);
	}

	// Storing scanner states.
	s->cs  = cs;
	s->top = top;
	memcpy(s->stack, stack, sizeof(stack));

	// Storing r_data pointer.
	s->r_data_tail = rdata_tail - s->r_data;
}

__attribute__((visibility("default")))
int zs_scanner_parse(zs_scanner_t *s,
                     const char   *start,
                     const char   *end,
                     const bool   final_block)
{
	if (s == NULL || start == NULL || end == NULL) {
		return -1;
	}

	// Parse input block.
	parse_block(s, start, end, false);

	// Parse trailing artificial block (newline char) if not stop.
	if (final_block && !s->stop) {
		parse_block(s, NEWLINE_BLOCK, NEWLINE_BLOCK + 1, true);
	}

	// Check if any errors has occured.
	if (s->error_counter > 0) {
		return -1;
	}

	return 0;
}

__attribute__((visibility("default")))
int zs_scanner_parse_file(zs_scanner_t *s,
                          const char   *file_name)
{
	long		page_size;
	uint64_t	n_blocks;
	uint64_t	block_id;
	uint64_t	default_block_size;
	struct stat	file_stat;

	if (s == NULL || file_name == NULL) {
		return -1;
	}

	// Getting OS page size.
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) {
		ERR(ZS_SYSTEM);
		return -1;
	}

	// Copying file name.
	s->file.name = strdup(file_name);

	// Opening the zone file.
	s->file.descriptor = open(file_name, O_RDONLY);
	if (s->file.descriptor == -1) {
		ERR(ZS_FILE_OPEN);
		free(s->file.name);
		return -1;
	}

	// Get absolute path of the zone file.
	char *full_name = realpath(file_name, NULL);
	if (full_name != NULL) {
		free(s->path);
		s->path = strdup(dirname(full_name));
		free(full_name);
	} else {
		ERR(ZS_FILE_PATH);
		close(s->file.descriptor);
		free(s->file.name);
		return -1;
	}

	// Getting file information.
	if (fstat(s->file.descriptor, &file_stat) == -1) {
		ERR(ZS_FILE_FSTAT);
		close(s->file.descriptor);
		free(s->file.name);
		return -1;
	}

	// Check for directory.
	if (S_ISDIR(file_stat.st_mode)) {
		ERR(ZS_FILE_DIR);
		close(s->file.descriptor);
		free(s->file.name);
		return -1;
	}

	// Check for empty file.
	if (file_stat.st_size == 0) {
		close(s->file.descriptor);
		free(s->file.name);
		return 0;
	}

	// Block size adjustment to multiple of page size.
	default_block_size = (BLOCK_SIZE / page_size) * page_size;

	// Number of blocks which cover the whole file (ceiling operation).
	n_blocks = 1 + ((file_stat.st_size - 1) / default_block_size);

	// Loop over zone file blocks.
	for (block_id = 0; block_id < n_blocks; block_id++) {
		// Current block start to scan.
		uint64_t scanner_start = block_id * default_block_size;
		// Current block size to scan.
		uint64_t block_size = default_block_size;
		// Last data block mark.
		bool final_block = false;
		// Mmapped data.
		char *data;

		// The last block is probably shorter.
		if (block_id == (n_blocks - 1)) {
			block_size = file_stat.st_size - scanner_start;
			final_block = true;
		}

		// Zone file block mapping.
		data = mmap(0, block_size, PROT_READ, MAP_SHARED,
		            s->file.descriptor, scanner_start);
		if (data == MAP_FAILED) {
			ERR(ZS_FILE_MMAP);
			close(s->file.descriptor);
			free(s->file.name);
			return -1;
		}

		// Scan zone file block.
		(void)zs_scanner_parse(s, data, data + block_size, final_block);

		// Zone file block unmapping.
		if (munmap(data, block_size) == -1) {
			ERR(ZS_FILE_MMAP);
			close(s->file.descriptor);
			free(s->file.name);
			return -1;
		}

		// Stop parsing if required.
		if (s->stop) {
			break;
		}
	}

	close(s->file.descriptor);
	free(s->file.name);

	// Check for scanner return.
	if (s->error_counter > 0) {
		return -1;
	}

	return 0;
}
