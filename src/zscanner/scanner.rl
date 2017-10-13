/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <math.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "zscanner/scanner.h"
#include "zscanner/functions.h"
#include "libknot/descriptor.h"

/*! \brief Shorthand for setting warning data. */
#define WARN(err_code) { s->error.code = err_code; }
/*! \brief Shorthand for setting error data. */
#define ERR(err_code) { WARN(err_code); s->error.fatal = true; }
/*! \brief Shorthand for error reset. */
#define NOERR { WARN(ZS_OK); s->error.fatal = false; }

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
int zs_init(
	zs_scanner_t *s,
	const char *origin,
	const uint16_t rclass,
	const uint32_t ttl)
{
	if (s == NULL) {
		return -1;
	}

	memset(s, 0, sizeof(*s));

	// Nonzero initial scanner state.
	s->cs = %%{ write start; }%%;

	// Reset the file descriptor.
	s->file.descriptor = -1;

	// Use the root zone as origin if not specified.
	if (origin == NULL || strlen(origin) == 0) {
		origin = ".";
	}
	size_t origin_len = strlen(origin);

	// Prepare a zone settings header.
	const char *format;
	if (origin[origin_len - 1] != '.') {
		format = "$ORIGIN %s.\n";
	} else {
		format = "$ORIGIN %s\n";
	}

	char settings[1024];
	int ret = snprintf(settings, sizeof(settings), format, origin);
	if (ret <= 0 || ret >= sizeof(settings)) {
		ERR(ZS_ENOMEM);
		return -1;
	}

	// Parse the settings to set up the scanner origin.
	if (zs_set_input_string(s, settings, ret) != 0 ||
	    zs_parse_all(s) != 0) {
		return -1;
	}

	// Set scanner defaults.
	s->path = strdup(".");
	if (s->path == NULL) {
		ERR(ZS_ENOMEM);
		return -1;
	}
	s->default_class = rclass;
	s->default_ttl = ttl;
	s->line_counter = 1;

	s->state = ZS_STATE_NONE;
	s->process.automatic = false;

	return 0;
}

static void input_deinit(
	zs_scanner_t *s)
{
	// Deinit the file input.
	if (s->file.descriptor != -1) {
		// Unmap the file content.
		if (s->input.start != NULL) {
			munmap((void *)s->input.start,
			       s->input.end - s->input.start);
		}

		// Close the opened file.
		close(s->file.descriptor);
		s->file.descriptor = -1;
		free(s->file.name);
		s->file.name = NULL;
	}

	// Unset the input limits.
	s->input.start   = NULL;
	s->input.current = NULL;
	s->input.end     = NULL;
	s->input.eof     = false;
}

__attribute__((visibility("default")))
void zs_deinit(
	zs_scanner_t *s)
{
	if (s == NULL) {
		return;
	}

	input_deinit(s);
	free(s->path);
}

static int set_input_string(
	zs_scanner_t *s,
	const char *input,
	size_t size,
	bool final_block)
{
	if (s == NULL) {
		return -1;
	}

	if (input == NULL) {
		ERR(ZS_EINVAL);
		return -1;
	}

	// Keep previous input file context if final block parsing.
	if (!final_block) {
		// Deinit possibly opened file.
		input_deinit(s);
	}

	// Set the scanner input limits.
	s->input.start   = input;
	s->input.current = input;
	s->input.end     = input + size;

	if (final_block) {
		s->input.eof = true;
	}

	return 0;
}

__attribute__((visibility("default")))
int zs_set_input_string(
	zs_scanner_t *s,
	const char *input,
	size_t size)
{
	return set_input_string(s, input, size, false);
}

__attribute__((visibility("default")))
int zs_set_input_file(
	zs_scanner_t *s,
	const char *file_name)
{
	if (s == NULL) {
		return -1;
	}

	if (file_name == NULL) {
		ERR(ZS_EINVAL);
		return -1;
	}

	// Deinit possibly opened file.
	input_deinit(s);

	// Try to open the file.
	s->file.descriptor = open(file_name, O_RDONLY);
	if (s->file.descriptor == -1) {
		ERR(ZS_FILE_OPEN);
		return -1;
	}

	// Check for regular file input.
	struct stat file_stat;
	if (fstat(s->file.descriptor, &file_stat) == -1 ||
	    !S_ISREG(file_stat.st_mode)) {
		ERR(ZS_FILE_INVALID);
		input_deinit(s);
		return -1;
	}

	// Check for empty file (cannot mmap).
	if (file_stat.st_size > 0) {
		// Map the file to the memory.
		char *start = mmap(0, file_stat.st_size, PROT_READ, MAP_SHARED,
		                   s->file.descriptor, 0);
		if (start == MAP_FAILED) {
			ERR(ZS_FILE_MMAP);
			input_deinit(s);
			return -1;
		}

		// Try to set the mapped memory advise to sequential.
		(void)madvise(start, file_stat.st_size, MADV_SEQUENTIAL);

		// Set the scanner input limits.
		s->input.start   = start;
		s->input.current = start;
		s->input.end     = start + file_stat.st_size;
	}

	// Get absolute path of the zone file.
	char *full_name = realpath(file_name, NULL);
	if (full_name != NULL) {
		free(s->path);
		s->path = strdup(dirname(full_name));
		free(full_name);
		if (s->path == NULL) {
			ERR(ZS_ENOMEM);
			input_deinit(s);
			return -1;
		}
	} else {
		ERR(ZS_FILE_PATH);
		input_deinit(s);
		return -1;
	}

	s->file.name = strdup(file_name);
	if (s->file.name == NULL) {
		ERR(ZS_ENOMEM);
		input_deinit(s);
		return -1;
	}

	return 0;
}

__attribute__((visibility("default")))
int zs_set_processing(
	zs_scanner_t *s,
	void (*process_record)(zs_scanner_t *),
	void (*process_error)(zs_scanner_t *),
	void *data)
{
	if (s == NULL) {
		return -1;
	}

	s->process.record = process_record;
	s->process.error = process_error;
	s->process.data = data;

	return 0;
}

typedef enum {
	WRAP_NONE,     // Initial state.
	WRAP_DETECTED, // Input block end is a first '\' in rdata.
	WRAP_PROCESS   // Parsing of auxiliary block = "\".
} wrap_t;

static void parse(
	zs_scanner_t *s,
	wrap_t *wrap)
{
	// Restore scanner input limits (Ragel internals).
	const char *p = s->input.current;
	const char *pe = s->input.end;
	const char *eof = s->input.eof ? pe : NULL;

	// Restore state variables (Ragel internals).
	int cs  = s->cs;
	int top = s->top;
	int stack[RAGEL_STACK_SIZE];
	memcpy(stack, s->stack, sizeof(stack));

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

	// Write scanner body (in C).
	%% write exec;

	// Check if the scanner state machine is in an uncovered state.
	bool extra_error = false;
	if (cs == %%{ write error; }%%) {
		ERR(ZS_UNCOVERED_STATE);
		extra_error = true;
	// Check for an unclosed multiline record.
	} else if (s->input.eof && s->multiline) {
		ERR(ZS_UNCLOSED_MULTILINE);
		extra_error = true;
	}

	// Treat the extra error.
	if (extra_error) {
		s->error.counter++;
		s->state = ZS_STATE_ERROR;

		// Copy the error context just for the part of the current line.
		s->buffer_length = 0;
		while (p < pe && *p != '\n' && s->buffer_length < 50) {
			s->buffer[s->buffer_length++] = *p++;
		}
		s->buffer[s->buffer_length++] = 0;

		// Execute the error callback.
		if (s->process.automatic && s->process.error != NULL) {
			s->process.error(s);
		}

		return;
	}

	// Storing scanner states.
	s->cs  = cs;
	s->top = top;
	memcpy(s->stack, stack, sizeof(stack));

	// Store the current parser position.
	s->input.current = p;

	// Storing r_data pointer.
	s->r_data_tail = rdata_tail - s->r_data;

	if (*wrap == WRAP_DETECTED) {
		if (set_input_string(s, "\\", 1, true) != 0) {
			return;
		}

		*wrap = WRAP_PROCESS;
		parse(s, wrap);
	} else {
		*wrap = WRAP_NONE;
	}
}

__attribute__((visibility("default")))
int zs_parse_record(
	zs_scanner_t *s)
{
	if (s == NULL) {
		return -1;
	}

	// Check if parsing is possible.
	switch (s->state) {
	case ZS_STATE_NONE:
	case ZS_STATE_DATA:
	case ZS_STATE_INCLUDE:
		break;
	case ZS_STATE_ERROR:
		if (s->error.fatal) {
			return -1;
		}
		break;
	default:
		// Return if stop or end of file.
		return 0;
	}

	// Check for the end of the input.
	if (s->input.current != s->input.end) {
		// Try to parse another item.
		s->state = ZS_STATE_NONE;
		wrap_t wrap = WRAP_NONE;
		parse(s, &wrap);

		// Finish if nothing was parsed.
		if (s->state == ZS_STATE_NONE) {
			// Parse the final block.
			if (set_input_string(s, "\n", 1, true) != 0) {
				return -1;
			}
			parse(s, &wrap);
			if (s->state == ZS_STATE_NONE) {
				s->state = ZS_STATE_EOF;
			}
		}
	} else {
		s->state = ZS_STATE_EOF;
	}

	return 0;
}

__attribute__((visibility("default")))
int zs_parse_all(
	zs_scanner_t *s)
{
	if (s == NULL) {
		return -1;
	}

	s->process.automatic = true;

	// Parse input block.
	wrap_t wrap = WRAP_NONE;
	parse(s, &wrap);

	// Parse trailing newline-char block if it makes sense.
	if (s->state != ZS_STATE_STOP && !s->error.fatal) {
		if (set_input_string(s, "\n", 1, true) != 0) {
			return -1;
		}
		parse(s, &wrap);
	}

	// Check if any errors have occurred.
	if (s->error.counter > 0) {
		return -1;
	}

	return 0;
}
