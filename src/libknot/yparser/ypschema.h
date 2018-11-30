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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
/*!
 * \file
 *
 * \brief Schema layer for Yparser.
 *
 * \addtogroup yparser
 * @{
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#include "libknot/yparser/yparser.h"
#include "libknot/lookup.h"

struct wire_ctx;

/*! Maximal length of item name. */
#define YP_MAX_ITEM_NAME_LEN	64
/*! Maximal length of binary identifier name (maximal dname length). */
#define YP_MAX_ID_LEN		255
/*! Maximal length of binary data (rough limit). */
#define YP_MAX_DATA_LEN		32768
/*! Integer item nil definition. */
#define YP_NIL			INT64_MIN
/*! Maximal number of miscellaneous callbacks/pointers. */
#define YP_MAX_MISC_COUNT	4
/*! Maximal node stack depth. */
#define YP_MAX_NODE_DEPTH	2

#define YP_TXT_BIN_PARAMS 	struct wire_ctx *in, struct wire_ctx *out, const uint8_t *stop
#define YP_BIN_TXT_PARAMS	struct wire_ctx *in, struct wire_ctx *out

/*! Helper macros for item variables definition. */
#define YP_VNONE	.var.i = { 0 }
#define YP_VINT		.var.i
#define YP_VBOOL	.var.b
#define YP_VOPT		.var.o
#define YP_VSTR		.var.s
#define YP_VADDR	.var.a
#define YP_VNET		.var.d
#define YP_VDNAME	.var.d
#define YP_VHEX		.var.d
#define YP_VB64		.var.d
#define YP_VDATA	.var.d
#define YP_VREF		.var.r
#define YP_VGRP		.var.g

/*! Schema item name is a char string with a leading byte (string length). */
typedef char yp_name_t;

/*! Schema item type. */
typedef enum {
	YP_TNONE = 0, /*!< Unspecified. */
	YP_TINT,      /*!< Integer. */
	YP_TBOOL,     /*!< Boolean. */
	YP_TOPT,      /*!< Option from the list. */
	YP_TSTR,      /*!< String. */
	YP_THEX,      /*!< String or hexadecimal string if "0x" prefix. */
	YP_TADDR,     /*!< Address (address[\@port] or UNIX socket path). */
	YP_TNET,      /*!< Network address range (address[/mask] or address-address). */
	YP_TDNAME,    /*!< Domain name. */
	YP_TB64,      /*!< Base64 encoded string. */
	YP_TDATA,     /*!< Customized data. */
	YP_TREF,      /*!< Reference to another item. */
	YP_TGRP,      /*!< Group of sub-items. */
} yp_type_t;

/*! Schema item flags. */
typedef enum {
	YP_FNONE  = 0,       /*!< Unspecified. */
	YP_FMULTI = 1 <<  0, /*!< Multivalued item. */
	YP_FALLOC = 1 <<  1, /*!< Allocated item. */
	YP_FUSR1  = 1 <<  5, /*!< User-defined flag1. */
	YP_FUSR2  = 1 <<  6, /*!< User-defined flag2. */
	YP_FUSR3  = 1 <<  7, /*!< User-defined flag3. */
	YP_FUSR4  = 1 <<  8, /*!< User-defined flag4. */
	YP_FUSR5  = 1 <<  9, /*!< User-defined flag5. */
	YP_FUSR6  = 1 << 10, /*!< User-defined flag6. */
	YP_FUSR7  = 1 << 11, /*!< User-defined flag7. */
	YP_FUSR8  = 1 << 12, /*!< User-defined flag8. */
	YP_FUSR9  = 1 << 13, /*!< User-defined flag9. */
	YP_FUSR10 = 1 << 14, /*!< User-defined flag10. */
	YP_FUSR11 = 1 << 15, /*!< User-defined flag11. */
	YP_FUSR12 = 1 << 16, /*!< User-defined flag12. */
	YP_FUSR13 = 1 << 17, /*!< User-defined flag13. */
	YP_FUSR14 = 1 << 18, /*!< User-defined flag14. */
	YP_FUSR15 = 1 << 19, /*!< User-defined flag15. */
	YP_FUSR16 = 1 << 20, /*!< User-defined flag16. */
} yp_flag_t;

/*! Schema item style. */
typedef enum {
	YP_SNONE    = 0,      /*!< Unspecified. */
	YP_SSIZE    = 1 << 0, /*!< Size unit (B, K, M, G) (in, out). */
	YP_STIME    = 1 << 1, /*!< Time unit (s, m, h, d) (in, out). */
	YP_SUNIT    = YP_SSIZE | YP_STIME, /*!< Unit (in, out). */
	YP_SNOQUOTE = 1 << 2  /*!< Unquoted value (out). */
} yp_style_t;

typedef struct yp_item yp_item_t;

/*! Schema item variables (type dependent). */
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
		/*! Text to binary transformation function. */
		int (*to_bin)(YP_TXT_BIN_PARAMS);
		/*! Binary to text transformation function. */
		int (*to_txt)(YP_BIN_TXT_PARAMS);
	} i;
	/*! Boolen variables. */
	struct {
		/*! Default value. */
		bool dflt;
	} b;
	/*! Option variables. */
	struct {
		/*! List of options (maximal value is 255). */
		struct knot_lookup const *opts;
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
		int (*to_bin)(YP_TXT_BIN_PARAMS);
		/*! Binary to text transformation function. */
		int (*to_txt)(YP_BIN_TXT_PARAMS);
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

/*! Schema item specification. */
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
	const void *misc[YP_MAX_MISC_COUNT];
	/*! Parent item. */
	yp_item_t *parent;
	/*! Item group subitems (name=NULL terminated array). */
	yp_item_t *sub_items;
};

typedef struct yp_node yp_node_t;
struct yp_node {
	/*! Parent node. */
	yp_node_t *parent;
	/*! Node item descriptor. */
	const yp_item_t *item;
	/*! Current binary id length. */
	size_t id_len;
	/*! Current binary id. */
	uint8_t id[YP_MAX_ID_LEN];
	/*! Current item data length. */
	size_t data_len;
	/*! Current item data. */
	uint8_t data[YP_MAX_DATA_LEN];
};

/*! Context parameters for check operations. */
typedef struct {
	/*! Used schema. */
	yp_item_t **schema;
	/*! Index of the current node. */
	size_t current;
	/*! Node stack. */
	yp_node_t nodes[YP_MAX_NODE_DEPTH];
} yp_check_ctx_t;

/*!
 * Copies the schema and reinitializes dynamic parameters.
 *
 * \param[out] dst New copy of the schema.
 * \param[in] src Source schema.
 *
 * \return Error code, KNOT_EOK if success.
 */
int yp_schema_copy(
	yp_item_t **dst,
	const yp_item_t *src
);

/*!
 * Merges two schemas.
 *
 * \param[out] dst Merged schema.
 * \param[in] src1 Source schema1.
 * \param[in] src2 Source schema2.
 *
 * \return Error code, KNOT_EOK if success.
 */
int yp_schema_merge(
	yp_item_t **dst,
	const yp_item_t *src1,
	const yp_item_t *src2
);

/*!
 * Purges dynamic items from the schema.
 *
 * \param[in] schema Schema to purge.
 */
void yp_schema_purge_dynamic(
	yp_item_t *schema
);

/*!
 * Deallocates the schema.
 *
 * \param[in] schema A schema returned by #yp_schema_copy().
 */
void yp_schema_free(
	yp_item_t *schema
);

/*!
 * Tries to find given parent_name/name in the schema.
 *
 * \param[in] name Name of the item.
 * \param[in] parent_name Name of the parent item (NULL if no parent).
 * \param[in] schema Schema.
 *
 * \return Item, NULL if not found or error.
 */
const yp_item_t* yp_schema_find(
	const yp_name_t *name,
	const yp_name_t *parent_name,
	const yp_item_t *schema
);

/*!
 * Prepares a context for item check against the schema.
 *
 * \param[in] schema Schema.
 *
 * \return Context, NULL if error.
 */
yp_check_ctx_t* yp_schema_check_init(
	yp_item_t **schema
);

/*!
 * Checks the current parser output against the schema.
 *
 * If the item is correct, context also contains binary value of the item.
 *
 * \param[in,out] ctx Check context.
 * \param[in] parser Parser context.
 *
 * \return Error code, KNOT_EOK if success.
 */
int yp_schema_check_parser(
	yp_check_ctx_t *ctx,
	const yp_parser_t *parser
);

/*!
 * Checks the string data against the schema.
 *
 * Description: key0[id].key1 data
 *
 * If the item is correct, context also contains binary value of the item.
 *
 * \param[in,out] ctx Check context.
 * \param[in] key0 Key0 item name.
 * \param[in] key1 Key1 item name.
 * \param[in] id Item identifier.
 * \param[in] data Item data (NULL means no data provided).
 *
 * \return Error code, KNOT_EOK if success.
 */
int yp_schema_check_str(
	yp_check_ctx_t *ctx,
	const char *key0,
	const char *key1,
	const char *id,
	const char *data
);

/*!
 * Deallocates the context.
 *
 * \param[in,out] ctx Check context.
 */
void yp_schema_check_deinit(
	yp_check_ctx_t *ctx
);

/*! @} */
