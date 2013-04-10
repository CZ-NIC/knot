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

#include "common/descriptor.h"		// KNOT_CLASS_IN
#include "zscanner/scanner.h"		// scanner_t

/*! \brief Settings block size in bytes. */
#define SETTINGS_BUFFER_LENGTH		 1024
/*! \brief Default ttl value. */
#define DEFAULT_TTL			 3600
/*! \brief Default class value. */
#define DEFAULT_CLASS		KNOT_CLASS_IN

/*! \brief Structure for zone file loader (each included file has one). */
typedef struct {
	/*!< File descriptor. */
	int	  fd;
	/*!< Zone file name this loader belongs to. */
	char	  *file_name;
	/*!< Zone scanner context stucture. */
	scanner_t *scanner;
	/*!< Zone settings buffer. */
	char	  settings_buffer[SETTINGS_BUFFER_LENGTH];
	/*!< Length of zone settings buffer. */
	uint32_t  settings_length;
} file_loader_t;

/*!
 * \brief Creates file loader structure.
 *
 * \param file_name		Name of file to process.
 * \param zone_origin		Initial zone origin (used in settings block).
 * \param default_class		Default class value.
 * \param default_ttl		Default ttl value (used in settings block).
 * \param process_record	Processing callback function.
 * \param process_error 	Error callback function.
 * \param data			Arbitrary data useful in callback functions.
 *
 * \retval file_loader		if success.
 * \retval 0			if error.
 */
file_loader_t* file_loader_create(const char	 *file_name,
				  const char	 *zone_origin,
				  const uint16_t default_class,
				  const uint32_t default_ttl,
				  void (*process_record)(const scanner_t *),
				  void (*process_error)(const scanner_t *),
				  void *data);

/*!
 * \brief Destroys file loader structure.
 *
 * \param file_loader	File loader structure.
 */
void file_loader_free(file_loader_t *file_loader);

/*!
 * \brief Processes zone file.
 *
 * Launches zone file processing using zone scanner. For each correctly
 * recognized record data process_record callback function is called. If any
 * syntax error occures, then process_error callback function is called.
 *
 * \note Zone scanner error code and other information are stored in
 * fl.scanner context.
 *
 * \param file_loader	File loader structure.
 *
 * \retval KNOT_EOK	if success.
 * \retval error_code   if error.
 */
int file_loader_process(file_loader_t *file_loader);


#endif // _ZSCANNER__FILE_LOADER_H_

/*! @} */
