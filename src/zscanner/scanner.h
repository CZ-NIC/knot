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
 * \brief Zone scanner.
 *
 * \addtogroup zone_scanner
 * @{
 */

#ifndef _ZSCANNER__SCANNER_H_
#define _ZSCANNER__SCANNER_H_

#include <stdint.h>    // uint32_t
#include <stdbool.h>   // bool
#include <arpa/inet.h> // htons

#define MAX_RDATA_LENGTH    65535
#define MAX_ITEM_LENGTH       255
#define MAX_DNAME_LENGTH      255
#define MAX_LABEL_LENGTH       63
#define MAX_RDATA_ITEMS        64

#define BITMAP_WINDOWS        256

#define INET4_ADDR_LENGTH       4
#define INET6_ADDR_LENGTH      16

#define RAGEL_STACK_SIZE        16 // Each nested call needs one.

#define ASCII_0                48

#define LOC_LAT_ZERO   (uint32_t)2147483648 // 2^31 - equator.
#define LOC_LONG_ZERO  (uint32_t)2147483648 // 2^31 - meridian.
#define LOC_ALT_ZERO   (uint32_t)  10000000 // Base altitude.

// Forward declaration for function arguments inside structure.
struct scanner;
typedef struct scanner scanner_t;

typedef struct {
    uint8_t bitmap[32];
    uint8_t length;
} window_t;

typedef struct {
    uint8_t  excl_flag;
    uint16_t addr_family;
    uint8_t  prefix_length;
} apl_t;

typedef struct {
    uint32_t d1, d2;
    uint32_t m1, m2;
    uint32_t s1, s2;
    uint32_t alt;
    uint64_t siz, hp, vp;
    int8_t   lat_sign, long_sign, alt_sign;
} loc_t;

/*!
 * \brief Context structure for Ragel scanner.
 */
struct scanner {
    /*!< Scanner internals (See Ragel manual). */
    int      cs;
    int      top;
    int      stack[RAGEL_STACK_SIZE];

    /*!< Data start shift of incompletely scanned token. */
    uint32_t token_shift;
    uint32_t r_data_tail; /*!< Position of actual r_data byte. */

    uint16_t r_type_tmp; /*!< Used between scanner calls. */

    /*!< Zone file name. */
    char     *file_name;
    /*!< Zone file line counter. */
    uint64_t line_counter;

    int      error_code;
    uint64_t error_counter;
    bool     stop;

    void (*process_record)(const scanner_t *);
    void (*process_error)(const scanner_t *);

    /*!< Indicates if actual record is multiline. */
    bool     multiline;
    /*!< Auxiliary number for all numeric operations. */
    uint64_t number64;
    /*!< Auxiliary variables for float numeric operations. */
    uint64_t number64_tmp;
    uint32_t decimals;
    uint32_t decimal_counter;

    /*!< Auxiliary variable for item length (label, base64, ...). */
    uint32_t item_length;
    /*!< Auxiliary index for item length position in array. */
    uint32_t item_length_position;
    /*!< Auxiliary pointer to item length. */
    uint8_t *item_length_location;
    /*!< Auxiliary buffer for data storing. */
    uint8_t  buffer[MAX_RDATA_LENGTH];
    /*!< Auxiliary buffer length. */
    uint32_t buffer_length;

    char     include_filename[MAX_RDATA_LENGTH];

    /*!< Bitmap window blocks. */
    window_t windows[BITMAP_WINDOWS];
    /*!< Last window block which is used (-1 means any window). */
    int16_t  last_window;

    apl_t    apl;
    loc_t    loc;

    uint8_t  *dname;  /*!< Pointer to actual dname (origin/owner/rdata). */
    uint32_t *dname_length; /*!< Pointer to actual dname length. */
    uint32_t dname_tmp_length; /*!< Temporary dname length which is copied to dname_length after dname processing. */

    uint8_t  zone_origin[MAX_DNAME_LENGTH]; /*!< Wire format of the origin. */
    uint32_t zone_origin_length;
    uint16_t default_class;
    uint32_t default_ttl;

                // Dname overflow check is after (relative + origin) check.
    uint8_t  r_owner[2 * MAX_DNAME_LENGTH];
    uint32_t r_owner_length;
    uint16_t r_class;
    uint32_t r_ttl;
    uint16_t r_type;
    uint8_t  r_data[MAX_RDATA_LENGTH];
    uint32_t r_data_length;
    uint16_t r_data_items[MAX_RDATA_ITEMS];
    uint32_t r_data_items_count;
};

scanner_t* scanner_create(const char *file_name);

void scanner_free(scanner_t *scanner);

int scanner_process(char      *start,
                    char      *end,
                    bool      is_last_block,
                    scanner_t *scanner);

#endif // _ZSCANNER__SCANNER_H_

/*! @} */
