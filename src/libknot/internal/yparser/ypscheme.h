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
/*!
 * \file
 *
 * Scheme layer for Yparser.
 *
 * \addtogroup yparser
 *
 * @{
 */

#pragma once

#include <stdint.h>

#include "libknot/internal/utils.h"
#include "libknot/internal/yparser/yparser.h"

/*! Maximal length of item name. */
#define YP_MAX_ITEM_NAME_LEN	64
/*! Maximal length of binary identifier name (maximal dname length). */
#define YP_MAX_ID_LEN		255
/*! Maximal length of binary data (rough limit). */
#define YP_MAX_DATA_LEN		32768
/*! Integer item nil definition. */
#define YP_NIL			INT64_MIN

/*! Helper macros for item variables definition. */
#define YP_VNONE	.var.i = { 0 }
#define YP_VINT		.var.i
#define YP_VBOOL	.var.b
#define YP_VOPT		.var.o
#define YP_VSTR		.var.s
#define YP_VADDR	.var.a
#define YP_VDNAME	.var.d
#define YP_VB64		.var.d
#define YP_VDATA	.var.d
#define YP_VREF		.var.r
#define YP_VGRP		.var.g

/*! Scheme item name is a char string with a leading byte (string length). */
typedef char yp_name_t;

/*! Scheme item type. */
typedef enum {
	YP_TNONE = 0, /*!< Unspecified. */
	YP_TINT,      /*!< Integer. */
	YP_TBOOL,     /*!< Boolean. */
	YP_TOPT,      /*!< Option from the list. */
	YP_TSTR,      /*!< String. */
	YP_TADDR,     /*!< Address (address[@port]). */
	YP_TNET,      /*!< Network (address[/mask]). */
	YP_TDNAME,    /*!< Domain name. */
	YP_TB64,      /*!< Base64 encoded string. */
	YP_TDATA,     /*!< Customized data. */
	YP_TREF,      /*!< Reference to another item. */
	YP_TGRP,      /*!< Group of sub-items. */
} yp_type_t;

/*! Scheme item flags. */
typedef enum {
	YP_FNONE  = 0,     /*!< Unspecified. */
	YP_FMULTI = 1 << 0 /*!< Multivalued item. */
} yp_flag_t;

/*! Scheme item style. */
typedef enum {
	YP_SNONE    = 0,      /*!< Unspecified. */
	YP_SSIZE    = 1 << 0, /*!< Size unit (B, K, M, G) (in, out). */
	YP_STIME    = 1 << 1, /*!< Time unit (s, m, h, d) (in, out). */
	YP_SUNIT    = YP_SSIZE | YP_STIME, /*!< Unit (in, out). */
	YP_SNOQUOTE = 1 << 2  /*!< Unquoted value (out). */
} yp_style_t;

typedef struct yp_item yp_item_t;

/*! Scheme item variables (type dependent). */
typedef union {
	/*! Integer variables. */
	struct {
		/*! Minimal value. */
		int64_t min;
		/*! Maximal value. */
		int64_t max;
		/*! Default value. */
		int64_t dflt;
		/*! Possible unit type. */
		yp_style_t unit;
	} i;
	/*! Boolen variables. */
	struct {
		/*! Default value. */
		bool dflt;
	} b;
	/*! Option variables. */
	struct {
		/*! List of options (maximal value is 255). */
		lookup_table_t const *opts;
		/*! Default value. */
		unsigned dflt;
	} o;
	/*! String variables. */
	struct {
		/*! Default value. */
		char const *dflt;
	} s;
	/*! Address variables. */
	struct {
		/*! Default port. */
		uint16_t dflt_port;
		/*! Default socket. */
		char const *dflt_socket;
	} a;
	/*! Customized data variables. */
	struct {
		/*! Length of default data. */
		size_t dflt_len;
		/*! Default data. */
		uint8_t const *dflt;
		/*! Text to binary transformation function. */
		int (*to_bin)(char const *, size_t, uint8_t *, size_t *);
		/*! Binary to text transformatio function. */
		int (*to_txt)(uint8_t const *, size_t, char *, size_t *);
	} d;
	/*! Reference variables. */
	struct {
		/*! Referenced group name. */
		yp_name_t const *ref_name;
		/*! Referenced item (dynamic value). */
		yp_item_t const *ref;
	} r;
	/*! Group variables. */
	struct {
		/*! List of sub-items. */
		yp_item_t const *sub_items;
		/*! ID item of sub-items (dynamic value). */
		yp_item_t const *id;
	} g;
} yp_var_t;

/*! Scheme item specification. */
struct yp_item {
	/*! Item name. */
	const yp_name_t *name;
	/*! Item type. */
	yp_type_t type;
	/*! Item parameters. */
	yp_var_t var;
	/*! Item flags. */
	yp_flag_t flags;
	/*! Arbitrary data/callbacks. */
	const void *misc[3];
	/*! Item group subitems (name=NULL terminated array). */
	yp_item_t *sub_items;
};

/*! Context parameters for check operations. */
typedef struct {
	/*! Used scheme. */
	const yp_item_t *scheme;
	/*! Current key0 item. */
	const yp_item_t *key0;
	/*! Current key1 item. */
	const yp_item_t *key1;
	/*! Current parser event. */
	yp_event_t event;
	/*! Current binary id. */
	uint8_t id[YP_MAX_ID_LEN];
	/*! Current binary id length. */
	size_t id_len;
	/*! Current item data. */
	uint8_t data[YP_MAX_DATA_LEN];
	/*! Current item data length. */
	size_t data_len;
} yp_check_ctx_t;

/*!
 * Copies the scheme and reinitializes dynamic parameters.
 *
 * \param[out] dst New copy of the scheme.
 * \param[in] srt Source scheme.
 *
 * \return Error code, KNOT_EOK if success.
 */
int yp_scheme_copy(
	yp_item_t **dst,
	const yp_item_t *src
);

/*!
 * Deallocates the scheme.
 *
 * \param[in] scheme A scheme returned by #yp_scheme_copy().
 */
void yp_scheme_free(
	yp_item_t *scheme
);

/*!
 * Tries to find given parent_name/name in the scheme.
 *
 * \param[in] name Name of the item.
 * \param[in] parent_name Name of the parent item (NULL if no parent).
 * \param[in] scheme Scheme.
 *
 * \return Item, NULL if not found or error.
 */
const yp_item_t* yp_scheme_find(
	const yp_name_t *name,
	const yp_name_t *parent_name,
	const yp_item_t *scheme
);

/*!
 * Prepares a context for item check against the scheme.
 *
 * \param[in] scheme Scheme.
 *
 * \return Context, NULL if error.
 */
yp_check_ctx_t* yp_scheme_check_init(
	const yp_item_t *scheme
);

/*!
 * Checks the current parser output against the scheme.
 *
 * If the item is correct, context also contains binary value of the item.
 *
 * \param[in,out] ctx New copy of the scheme.
 * \param[in] parser Parser context.
 *
 * \return Error code, KNOT_EOK if success.
 */
int yp_scheme_check_parser(
	yp_check_ctx_t *ctx,
	const yp_parser_t *parser
);

/*!
 * Deallocates the context.
 *
 * \param[in] ctx Context returned by #yp_scheme_check_init().
 */
void yp_scheme_check_deinit(
	yp_check_ctx_t *ctx
);

// TODO: check from string.
// TODO: scheme add/remove item.

/*! @} */
