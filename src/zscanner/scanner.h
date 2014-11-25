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
 * \file scanner.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief Zone scanner core interface.
 *
 * \addtogroup zone_scanner
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "zscanner/error.h"

/*! \brief Maximal length of rdata. */
#define MAX_RDATA_LENGTH		65535
/*! \brief Maximal length of rdata item. */
#define MAX_ITEM_LENGTH			255
/*! \brief Maximal length of domain name. */
#define MAX_DNAME_LENGTH		255
/*! \brief Maximal length of domain name label. */
#define MAX_LABEL_LENGTH		63
/*! \brief Maximal number or rdata items. */
#define MAX_RDATA_ITEMS			64

/*! \brief Number of bitmap windows. */
#define BITMAP_WINDOWS			256

/*! \brief Length of ipv4 address in wire format. */
#define INET4_ADDR_LENGTH		4
/*! \brief Length of ipv6 address in wire format. */
#define INET6_ADDR_LENGTH		16

/*! \brief Ragel call stack size (see Ragel internals). */
#define RAGEL_STACK_SIZE		16

/*! \brief Latitude value for equator (2^31). */
#define LOC_LAT_ZERO	(uint32_t)2147483648
/*! \brief Longitude value for meridian (2^31). */
#define LOC_LONG_ZERO	(uint32_t)2147483648
/*! \brief Zero level altitude value. */
#define LOC_ALT_ZERO	(uint32_t)10000000

/*! \brief Auxiliary structure for storing bitmap window items (see RFC4034). */
typedef struct {
	uint8_t bitmap[32];
	uint8_t length;
} window_t;

/*! \brief Auxiliary structure for storing one APL record (see RFC3123). */
typedef struct {
	uint8_t  excl_flag;
	uint16_t addr_family;
	uint8_t  prefix_length;
} apl_t;

/*! \brief Auxiliary structure for storing LOC information (see RFC1876). */
typedef struct {
	uint32_t d1, d2;
	uint32_t m1, m2;
	uint32_t s1, s2;
	uint32_t alt;
	uint64_t siz, hp, vp;
	int8_t   lat_sign, long_sign, alt_sign;
} loc_t;

/*!
 * \brief Context structure for zone scanner.
 *
 * This structure contains folowing items:
 *  - Copies of Ragel internal variables. The scanner can be called many times
 *    on smaller parts of zone file/memory. So it is necessary to preserve
 *    internal values between subsequent scanner callings.
 *  - Auxiliary variables which are used during processing zone data.
 *  - Pointers to callback functions and pointer to any arbitrary data which
 *    can be used in callback functions.
 *  - Zone file and error information.
 *  - Output variables (r_ prefix) containing all parts of zone record. These
 *    data are usefull during processing via callback function.
 */
typedef struct scanner zs_scanner_t; // Forward declaration due to arguments.
struct scanner {
	/*! Current state (Ragel internals). */
	int      cs;
	/*! Stack top (Ragel internals). */
	int      top;
	/*! Call stack (Ragel internals). */
	int      stack[RAGEL_STACK_SIZE];

	/*! Indicates whether current record is multiline. */
	bool     multiline;
	/*! Auxiliary number for all numeric operations. */
	uint64_t number64;
	/*! Auxiliary variable for time and other numeric operations. */
	uint64_t number64_tmp;
	/*! Auxiliary variable for float numeric operations. */
	uint32_t decimals;
	/*! Auxiliary variable for float numeric operations. */
	uint32_t decimal_counter;

	/*! Auxiliary variable for item length (label, base64, ...). */
	uint32_t item_length;
	/*! Auxiliary index for item length position in array. */
	uint32_t item_length_position;
	/*! Auxiliary pointer to item length. */
	uint8_t *item_length_location;
	/*! Auxiliary buffer for data storing. */
	uint8_t  buffer[MAX_RDATA_LENGTH];
	/*! Auxiliary buffer length. */
	uint32_t buffer_length;
	/*! Auxiliary buffer for current included file name. */
	char     include_filename[MAX_RDATA_LENGTH + 1];

	/*! Auxiliary array of bitmap window blocks. */
	window_t windows[BITMAP_WINDOWS];
	/*! Last window block which is used (-1 means no window). */
	int16_t  last_window;
	/*! Auxiliary apl structure. */
	apl_t    apl;
	/*! Auxiliary loc structure. */
	loc_t    loc;

	/*! Pointer to the actual dname storage (origin/owner/rdata). */
	uint8_t  *dname;
	/*! Pointer to the actual dname length storage. */
	uint32_t *dname_length;
	/*!
	 * Temporary dname length which is copied to dname_length after
	 * dname processing.
	 */
	uint32_t dname_tmp_length;
	/*! Position of the last free r_data byte. */
	uint32_t r_data_tail;

	/*! Wire format of the current origin (ORIGIN directive sets this). */
	uint8_t  zone_origin[MAX_DNAME_LENGTH];
	/*! Length of the current origin. */
	uint32_t zone_origin_length;
	/*! Value of the default class. */
	uint16_t default_class;
	/*! Value of the current default ttl (TTL directive sets this). */
	uint32_t default_ttl;

	/*! Callback function for correct zone record. */
	void (*process_record)(zs_scanner_t *);
	/*! Callback function for wrong situations. */
	void (*process_error)(zs_scanner_t *);
	/*! Arbitrary data useful inside callback functions. */
	void *data;

	/*! Absolute path for relative includes. */
	char     *path;
	/*! Zone data line counter. */
	uint64_t line_counter;
	/*! Last occured error/warning code. */
	int      error_code;
	/*! Errors/warnings counter. */
	uint64_t error_counter;
	/*!
	 * Indicates serious warning which is considered as an error and
	 * forces zone processing to stop.
	 */
	bool     stop;

	struct {
		/*! Zone file name. */
		char *name;
		/*!< File descriptor. */
		int  descriptor;
	} file;

	/*!
	 * Owner of the current record.
	 *
	 * \note The double length of the r_owner is due to dname length
	 *       check is after concatenation of relative and origin dnames.
	 */
	uint8_t  r_owner[2 * MAX_DNAME_LENGTH];
	/*! Length of the current record owner. */
	uint32_t r_owner_length;
	/*! Class of the current record. */
	uint16_t r_class;
	/*! TTL of the current record. */
	uint32_t r_ttl;
	/*! Type of the current record data. */
	uint16_t r_type;
	/*! Current rdata. */
	uint8_t  r_data[MAX_RDATA_LENGTH];
	/*! Length of the current rdata. */
	uint32_t r_data_length;

	/*
	 * Example: a. IN 60 MX 1 b.
	 *
	 *          r_owner = 016100
	 *          r_owner_length = 3
	 *          r_class = 1
	 *          r_ttl = 60
	 *          r_type = 15
	 *          r_data = 0001016200
	 *          r_data_length = 5
	 */
};

/*!
 * \brief Creates zone scanner structure.
 *
 * \param origin		Initial zone origin.
 * \param rclass		Zone class value.
 * \param ttl			Initial ttl value.
 * \param process_record	Processing callback function.
 * \param process_error 	Error callback function.
 * \param data			Arbitrary data useful in callback functions.
 *
 * \retval scanner		if success.
 * \retval NULL			if error.
 */
zs_scanner_t* zs_scanner_create(const char     *origin,
                                const uint16_t rclass,
                                const uint32_t ttl,
                                void (*process_record)(zs_scanner_t *),
                                void (*process_error)(zs_scanner_t *),
                                void *data);

/*!
 * \brief Destroys zone scanner structure.
 *
 * \param scanner	Zone scanner structure.
 */
void zs_scanner_free(zs_scanner_t *scanner);

/*!
 * \brief Parser memory block with zone data.
 *
 * For each correctly recognized record data process_record callback function
 * is called. If any syntax error occures, then process_error callback
 * function is called.
 *
 * \note Zone scanner error code and other information are stored in
 *       the scanner structure.
 *
 * \param scanner	Zone scanner.
 * \param start		First byte of the zone data to parse.
 * \param end		Last byte of the zone data to parse.
 * \param final_block	Indicates if the current block is final i.e. no
 * 			other blocks will be processed.
 *
 * \retval  0		if success.
 * \retval -1		if error.
 */
int zs_scanner_parse(zs_scanner_t *scanner,
                     const char   *start,
                     const char   *end,
                     const bool   final_block);

/*!
 * \brief Parses specified zone file.
 *
 * \note Zone scanner error code and other information are stored in
 *       the scanner structure. If error and error_count == 0, there is
 *       a more general problem with loading and this error is not processed
 *       with process_error!
 *
 * \param scanner	Zone scanner.
 * \param file_name	Name of file to process.
 *
 * \retval  0		if success.
 * \retval -1		if error.
 */
int zs_scanner_parse_file(zs_scanner_t *scanner,
                          const char   *file_name);
/*! @} */
