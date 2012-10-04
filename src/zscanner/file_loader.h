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
 * \file file_loader.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief Zone file loader.
 *
 * \addtogroup zone_scanner
 * @{
 */

#ifndef _ZSCANNER__FILE_LOADER_H_
#define _ZSCANNER__FILE_LOADER_H_

#include <stdint.h>			// uint32_t

#include "common/descriptor_new.h"	// KNOT_CLASS_IN
#include "zscanner/scanner.h"		// scanner_t

#define SETTINGS_BUFFER_LENGTH		 1024

#define DEFAULT_TTL			 3600
#define DEFAULT_CLASS		KNOT_CLASS_IN


/*!
 * \brief Structure for zone file loader (each include file has one).
 */
typedef struct {
	int	  fd;		/*!< File descriptor. */
	char	  *file_name;	/*!< Zone file name. */
	scanner_t *scanner;	/*!< Zone scanner data. */
	char	  settings_buffer[SETTINGS_BUFFER_LENGTH];
	uint32_t  settings_length;
} file_loader_t;

file_loader_t* file_loader_create(const char	 *file_name,
				  const char	 *zone_origin,
				  const uint16_t default_class,
				  const uint32_t default_ttl,
				  void (*process_record)(const scanner_t *),
				  void (*process_error)(const scanner_t *),
				  void *data);

void file_loader_free(file_loader_t *file_loader);

int file_loader_process(file_loader_t *file_loader);


#endif // _ZSCANNER__FILE_LOADER_H_

/*! @} */
