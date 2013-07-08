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
#include "zscanner/file_loader.h"

#include <inttypes.h>			// PRIu64
#include <unistd.h>			// sysconf
#include <stdio.h>			// sprintf
#include <stdlib.h>			// free
#include <stdbool.h>			// bool
#include <string.h>			// strlen
#include <fcntl.h>			// open
#include <sys/stat.h>			// fstat
#include <sys/mman.h>			// mmap

#include "common/errcode.h"		// error codes

/*! \brief Mmap block size in bytes. */
#define BLOCK_SIZE      30000000

/*!
 * \brief Processes zone settings block.
 *
 * Before zone file processing via scanner it's necessary to process first
 * settings block using this function. Settings block contains ORIGIN and
 * TTL directive.
 *
 * \param fl		File loader structure.
 *
 * \retval  0		if success.
 * \retval -1		if error.
 */
static int load_settings(file_loader_t *fl)
{
	int		ret;
	char		*settings_name;
	scanner_t	*settings_scanner;

	// Creating name for zone defaults.
	size_t buf_len = strlen(fl->file_name) + 100;
	settings_name = malloc(buf_len);
	ret = snprintf(settings_name, buf_len, "ZONE DEFAULTS <%s>",
		       fl->file_name);
	if (ret < 0 || (size_t)ret >= buf_len) {
		free(settings_name);
		return -1;
	}

	// Temporary scanner for zone settings.
	settings_scanner = scanner_create(settings_name);

	// Use parent processing functions.
	settings_scanner->process_record = fl->scanner->process_record;
	settings_scanner->process_error  = fl->scanner->process_error;

	// Scanning zone settings.
	ret = scanner_process(fl->settings_buffer,
			      fl->settings_buffer + fl->settings_length,
			      true,
			      settings_scanner);

	// If no error occured, then copy scanned settings to actual context.
	if (ret == 0) {
		memcpy(fl->scanner->zone_origin,
		       settings_scanner->zone_origin,
		       settings_scanner->zone_origin_length);
		fl->scanner->zone_origin_length =
			settings_scanner->zone_origin_length;
		fl->scanner->default_ttl = settings_scanner->default_ttl;
	}

	// Destroying temporary scanner.
	scanner_free(settings_scanner);

	free(settings_name);

	return ret;
}

file_loader_t* file_loader_create(const char	 *file_name,
				  const char	 *zone_origin,
				  const uint16_t default_class,
				  const uint32_t default_ttl,
				  void (*process_record)(const scanner_t *),
				  void (*process_error)(const scanner_t *),
				  void *data)
{
	int ret;

	// Creating zeroed structure.
	file_loader_t *fl = calloc(1, sizeof(file_loader_t));

	if (fl == NULL) {
		return NULL;
	}

	// Copying file name.
	fl->file_name = strdup(file_name);

	// Opening zone file.
	fl->fd = open(fl->file_name, O_RDONLY);

	if (fl->fd == -1) {
		free(fl->file_name);
		free(fl);
		return NULL;
	}

	// Creating zone scanner.
	fl->scanner = scanner_create(file_name);

	// Setting processing functions and data pointer.
	fl->scanner->process_record = process_record;
	fl->scanner->process_error  = process_error;
	fl->scanner->data = data;

	// Default class initialization.
	fl->scanner->default_class = default_class;

	// Filling zone settings buffer.
	ret = snprintf(fl->settings_buffer,
		       sizeof(fl->settings_buffer),
		       "$ORIGIN %s\n"
		       "$TTL %u\n",
		       zone_origin, default_ttl);
	if (ret <= 0 || (size_t)ret >= sizeof(fl->settings_buffer)) {
		file_loader_free(fl);
		return NULL;
	}

	fl->settings_length = ret;

	return fl;
}

void file_loader_free(file_loader_t *fl)
{
	close(fl->fd);
	free(fl->file_name);
	scanner_free(fl->scanner);
	free(fl);
}

int file_loader_process(file_loader_t *fl)
{
	int		ret;
	char		*data;		// Mmaped data.
	bool		is_last_block;
	long		page_size;
	uint64_t	n_blocks;
	uint64_t	block_id;
	uint64_t	default_block_size;
	uint64_t	scanner_start;	// Current block start to scan.
	uint64_t	block_size;	// Current block size to scan.
	struct stat	file_stat;

	// Last block - secure termination of zone file.
	char *zone_termination = "\n";

	// Getting OS page size.
	page_size = sysconf(_SC_PAGESIZE);

	// Getting file information.
	if (fstat(fl->fd, &file_stat) == -1) {
		return FLOADER_EFSTAT;
	}

	// Check for directory.
	if (S_ISDIR(file_stat.st_mode)) {
		return FLOADER_EDIRECTORY;
	}

	// Check for empty file.
	if (file_stat.st_size == 0) {
		return FLOADER_EEMPTY;
	}

	// Block size adjustment to multiple of page size.
	default_block_size = (BLOCK_SIZE / page_size) * page_size;

	// Number of blocks which cover the whole file (ceiling operation).
	n_blocks = 1 + ((file_stat.st_size - 1) / default_block_size);

	// Process settings using scanner (like initial ORIGIN and TTL).
	ret = load_settings(fl);

	if (ret != 0) {
		return FLOADER_EDEFAULTS;
	}

	// Loop over zone file blocks.
	for (block_id = 0; block_id < n_blocks; block_id++) {
		scanner_start = block_id * default_block_size;
		is_last_block = false;
		block_size = default_block_size;

		// The last block is probably shorter.
		if (block_id == (n_blocks - 1)) {
			block_size = file_stat.st_size - scanner_start;
			is_last_block = true;
		}

		// Zone file block mapping.
		data = mmap(0,
			    block_size,
			    PROT_READ,
			    MAP_SHARED,
			    fl->fd,
			    scanner_start);

		if (data == MAP_FAILED) {
			return FLOADER_EMMAP;
		}

		// Scan zone file.
		ret = scanner_process(data,
				      data + block_size,
				      false,
				      fl->scanner);

		// Artificial last block containing newline char only.
		if (is_last_block == true && fl->scanner->stop == 0) {
			ret = scanner_process(zone_termination,
					      zone_termination + 1,
					      true,
					      fl->scanner);
		}

		// Zone file block unmapping.
		if (munmap(data, block_size) == -1) {
			return FLOADER_EMUNMAP;
		}
	}

	// Check for scanner return.
	if (ret != 0) {
		return FLOADER_ESCANNER;
	}

	return KNOT_EOK;
}
