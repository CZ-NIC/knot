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

#include <inttypes.h>			// PRIu64
#include <unistd.h>			// sysconf
#include <stdio.h>			// sprintf
#include <stdlib.h>			// free
#include <stdbool.h>			// bool
#include <string.h>			// strlen
#include <fcntl.h>			// open
#include <sys/stat.h>			// fstat
#include <sys/mman.h>			// mmap

#include "zscanner/loader.h"
#include "zscanner/error.h"

/*! \brief Mmap block size in bytes. This value is then adjusted to the
 *         multiple of memory pages which fit in.
 */
#define BLOCK_SIZE      30000000

zs_loader_t* zs_loader_create(const char     *file_name,
                              const char     *origin,
                              const uint16_t rclass,
                              const uint32_t ttl,
                              void (*process_record)(zs_scanner_t *),
                              void (*process_error)(zs_scanner_t *),
                              void *data)
{
	// Creating zeroed structure.
	zs_loader_t *fl = calloc(1, sizeof(zs_loader_t));
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
	fl->scanner = zs_scanner_create(fl->file_name, origin, rclass, ttl,
	                                process_record, process_error, data);
	if (fl->scanner == NULL) {
		close(fl->fd);
		free(fl->file_name);
		free(fl);
		return NULL;
	}

	return fl;
}

void zs_loader_free(zs_loader_t *fl)
{
	close(fl->fd);
	free(fl->file_name);
	zs_scanner_free(fl->scanner);
	free(fl);
}

int zs_loader_process(zs_loader_t *fl)
{
	int		ret = 0;
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
		return ZS_LOADER_FSTAT;
	}

	// Check for directory.
	if (S_ISDIR(file_stat.st_mode)) {
		return ZS_LOADER_DIRECTORY;
	}

	// Check for empty file.
	if (file_stat.st_size == 0) {
		return ZS_LOADER_EMPTY;
	}

	// Block size adjustment to multiple of page size.
	default_block_size = (BLOCK_SIZE / page_size) * page_size;

	// Number of blocks which cover the whole file (ceiling operation).
	n_blocks = 1 + ((file_stat.st_size - 1) / default_block_size);

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
			return ZS_LOADER_MMAP;
		}

		// Scan zone file.
		ret = zs_scanner_process(data,
		                         data + block_size,
		                         false,
		                         fl->scanner);

		// Artificial last block containing newline char only.
		if (is_last_block == true && fl->scanner->stop == 0) {
			ret = zs_scanner_process(zone_termination,
			                         zone_termination + 1,
			                         true,
			                         fl->scanner);
		}

		// Zone file block unmapping.
		if (munmap(data, block_size) == -1) {
			return ZS_LOADER_MUNMAP;
		}
	}

	// Check for scanner return.
	if (ret != 0) {
		return ZS_LOADER_SCANNER;
	}

	return ZS_OK;
}
