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
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>	
#include <arpa/inet.h>

#include "knot/knot.h"
#include "knot/other/debug.h"
#include "libknot/libknot.h"
#include "libknot/dnssec/key.h"
#include "common/base32hex.h"
#include "common/crc.h"
#include "common/descriptor.h"
#include "common/mempattern.h"
#include "libknot/rdata.h"
#include "libknot/dnssec/zone-nsec.h"

#include "knot/zone/semantic-check.h"

static char *error_messages[(-ZC_ERR_UNKNOWN) + 1] = {
	[-ZC_ERR_MISSING_SOA] = "SOA record missing in zone!",
	[-ZC_ERR_MISSING_NS_DEL_POINT] = "NS record missing in zone apex or in "
	                "delegation point!",

	[-ZC_ERR_RRSIG_RDATA_TYPE_COVERED] =
	"RRSIG: Type covered RDATA field is wrong!",
	[-ZC_ERR_RRSIG_RDATA_TTL] =
	"RRSIG: TTL RDATA field is wrong!",
	[-ZC_ERR_RRSIG_RDATA_EXPIRATION] =
	"RRSIG: Expired signature!",
	[-ZC_ERR_RRSIG_RDATA_LABELS] =
	"RRSIG: Labels RDATA field is wrong!",
	[-ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER] =
	"RRSIG: Signer name is different than in DNSKEY!",
	[-ZC_ERR_RRSIG_NO_DNSKEY] =
	"RRSIG: Missing DNSKEY for RRSIG!",
	[-ZC_ERR_RRSIG_RDATA_SIGNED_WRONG] =
	"RRSIG: Key error!",
	[-ZC_ERR_RRSIG_NO_RRSIG] =
	"RRSIG: No RRSIG!",
	[-ZC_ERR_RRSIG_SIGNED] =
	"RRSIG: Signed RRSIG!",
	[-ZC_ERR_RRSIG_OWNER] =
	"RRSIG: Owner name RDATA field is wrong!",
	[-ZC_ERR_RRSIG_CLASS] =
	"RRSIG: Class is wrong!",
	[-ZC_ERR_RRSIG_TTL] =
	"RRSIG: TTL is wrong!",

	[-ZC_ERR_NO_NSEC] =
	"NSEC: Missing NSEC record",
	[-ZC_ERR_NSEC_RDATA_BITMAP] =
	"NSEC: Wrong NSEC bitmap!",
	[-ZC_ERR_NSEC_RDATA_MULTIPLE] =
	"NSEC: Multiple NSEC records!",
	[-ZC_ERR_NSEC_RDATA_CHAIN] =
	"NSEC: NSEC chain is not coherent!",
	[-ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC] =
	"NSEC: NSEC chain is not cyclic!",

	[-ZC_ERR_NSEC3_UNSECURED_DELEGATION] =
	"NSEC3: Zone contains unsecured delegation!",
	[-ZC_ERR_NSEC3_NOT_FOUND] =
	"NSEC3: Could not find previous NSEC3 record in the zone!",
	[-ZC_ERR_NSEC3_UNSECURED_DELEGATION_OPT] =
	"NSEC3: Unsecured delegation is not part "
	"of the Opt-Out span!",
	[-ZC_ERR_NSEC3_RDATA_TTL] =
	"NSEC3: Original TTL RDATA field is wrong!",
	[-ZC_ERR_NSEC3_RDATA_CHAIN] =
	"NSEC3: NSEC3 chain is not coherent!",
	[-ZC_ERR_NSEC3_RDATA_BITMAP] =
	"NSEC3: NSEC3 bitmap error!",
	[-ZC_ERR_NSEC3_EXTRA_RECORD] =
	"NSEC3: NSEC3 node contains extra record. This is valid, however Knot "
	"will not serve this record properly.",

	[-ZC_ERR_CNAME_EXTRA_RECORDS] =
	"CNAME: Node with CNAME record has other records!",
	[-ZC_ERR_DNAME_CHILDREN] =
	"DNAME: Node with DNAME record has children!",
	[-ZC_ERR_CNAME_EXTRA_RECORDS_DNSSEC] =
	"CNAME: Node with CNAME record has other "
	"records than RRSIG and NSEC/NSEC3!",
	[-ZC_ERR_CNAME_MULTIPLE] = "CNAME: Multiple CNAME records!",
	[-ZC_ERR_DNAME_MULTIPLE] = "DNAME: Multiple DNAME records!",
	[-ZC_ERR_CNAME_WILDCARD_SELF] = "CNAME wildcard "
				  "pointing to itself!",
	[-ZC_ERR_DNAME_WILDCARD_SELF] = "DNAME wildcard "
				  "pointing to itself!",

	/* ^
	   | Important errors (to be logged on first occurence and counted) */


	/* Below are errors of lesser importance, to be counted unless
	   specified otherwise */

	[-ZC_ERR_GLUE_NODE] =
	"GLUE: Node with glue record missing!",
	[-ZC_ERR_GLUE_RECORD] =
	"GLUE: Record with glue address missing!",
};

err_handler_t *handler_new(int log_cname, int log_glue, int log_rrsigs,
                           int log_nsec, int log_nsec3)
{
	err_handler_t *handler = xmalloc(sizeof(err_handler_t));

	memset(handler->errors, 0, sizeof(uint) * (-ZC_ERR_UNKNOWN + 1));
	
	handler->error_count = 0;
	handler->options.log_cname = log_cname;
	handler->options.log_glue = log_glue;
	handler->options.log_rrsigs = log_rrsigs;
	handler->options.log_nsec = log_nsec;
	handler->options.log_nsec3 = log_nsec3;

	return handler;
}

/*!
 * \brief Prints error message with node information.
 *
 * \note If \a node is NULL, only total number of errors is printed.
 *
 * \param handler Error handler.
 * \param node Node with semantic error in it.
 * \param error Type of error.
 */
static void log_error_from_node(err_handler_t *handler,
				const knot_node_t *node,
				int error, const char *data)
{
	if (error > (int)ZC_ERR_GLUE_RECORD) {
		log_zone_warning("Unknown error.\n");
		return;
	}
	
	char buffer[1024] = {0};
	size_t offset = 0;
	
	if (node != NULL) {
		handler->error_count++;
		char *name =
			knot_dname_to_str(knot_node_owner(node));
		offset += snprintf(buffer, 1024,
		                   "Semantic warning in node: %s: ", name);
		if (error_messages[-error] != NULL) {
			offset += snprintf(buffer + offset, 1024 - offset,
			                   "%s", error_messages[-error]);
			if (data == NULL) {
				offset += snprintf(buffer + offset,
				                   1024 - offset, "\n");
			} else {
				offset += snprintf(buffer + offset,
				                   1024 - offset, " %s\n", data);
			}
			log_zone_warning("%s", buffer);
		} else {
			log_zone_warning("Unknown error (%d).\n", error);
		}
		free(name);
	} else {
		log_zone_warning("Total number of warnings is: %d for error: %s",
			handler->errors[-error],
			error_messages[-error]);
	}
}

int err_handler_handle_error(err_handler_t *handler, const knot_node_t *node,
                             int error, const char *data)
{
	assert(handler && node);
	if ((error != 0) &&
	    (error > ZC_ERR_GLUE_GENERAL_ERROR)) {
		return KNOT_EINVAL;
	}

	/* 
	 * A missing SOA can only occur once, so there needn't be 
	 * an option for it.
	 */

	if ((error != 0) &&
	    (error < ZC_ERR_GENERIC_GENERAL_ERROR)) {
		/* The two errors before SOA were handled */
		log_error_from_node(handler, node, error, data);
		return KNOT_EOK;
	} else if ((error < ZC_ERR_RRSIG_GENERAL_ERROR) &&
		   ((handler->errors[-error] == 0) ||
		   (handler->options.log_rrsigs))) {
		log_error_from_node(handler, node, error, data);
	} else if ((error > ZC_ERR_RRSIG_GENERAL_ERROR) &&
		   (error < ZC_ERR_NSEC_GENERAL_ERROR) &&
		   ((handler->errors[-error] == 0) ||
		    (handler->options.log_nsec))) {
		log_error_from_node(handler, node, error, data);
	} else if ((error > ZC_ERR_NSEC_GENERAL_ERROR) &&
		   (error < ZC_ERR_NSEC3_GENERAL_ERROR) &&
		   ((handler->errors[-error] == 0) ||
		    (handler->options.log_nsec3))) {
		log_error_from_node(handler, node, error, data);
	} else if ((error > ZC_ERR_NSEC3_GENERAL_ERROR) &&
		   (error < ZC_ERR_CNAME_GENERAL_ERROR) &&
		   ((handler->errors[-error] == 0) ||
		    (handler->options.log_cname))) {
		log_error_from_node(handler, node, error, data);
	} else if ((error > ZC_ERR_CNAME_GENERAL_ERROR) &&
		   (error < ZC_ERR_GLUE_GENERAL_ERROR) &&
		    handler->options.log_glue) {
		log_error_from_node(handler, node, error, data);
	}

	handler->errors[-error]++;

	return KNOT_EOK;
}

void err_handler_log_all(err_handler_t *handler)
{
	if (handler == NULL) {
		return;
	}

	for (int i = ZC_ERR_UNKNOWN; i < ZC_ERR_GLUE_GENERAL_ERROR; i++) {
		if (handler->errors[-i] > 0) {
			log_error_from_node(handler, NULL, i, NULL);
		}
	}
}

/*!
 * \brief Check whether DNSKEY rdata are valid.
 *
 * \param rdata DNSKEY rdata to be checked.
 *
 * \retval KNOT_EOK when rdata are OK.
 * \retval ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER when rdata are not OK.
 */
static int check_dnskey_rdata(const knot_rrset_t *rrset, size_t rdata_pos)
{
	/* check that Zone key bit it set - position 7 in net order */
	const uint16_t mask = 1 << 8; //0b0000000100000000;

	uint16_t flags =
		knot_wire_read_u16(knot_rrset_get_rdata(rrset, rdata_pos));

	if (flags & mask) {
		return KNOT_EOK;
	} else {
		/* This error does not exactly fit, but it's better
		 * than a new one */
		return ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER;
	}
}

/*!
 * \brief Semantic check - RRSIG rdata.
 *
 * \param rdata_rrsig RRSIG rdata to be checked.
 * \param rrset RRSet containing the rdata.
 * \param dnskey_rrset RRSet containing zone's DNSKEY
 *
 * \retval KNOT_EOK if rdata are OK.
 *
 * \return Appropriate error code if error was found.
 */
static int check_rrsig_rdata(err_handler_t *handler,
                             const knot_node_t *node,
                             const knot_rrset_t *rrsig,
                             size_t rr_pos,
                             const knot_rrset_t *rrset,
                             const knot_rrset_t *dnskey_rrset)
{
	/* Prepare additional info string. */
	char info_str[50] = { '\0' };
	char type_str[16] = { '\0' };
	knot_rrtype_to_string(knot_rrset_type(rrset), type_str, sizeof(type_str));
	int ret = snprintf(info_str, sizeof(info_str), "Record type: %s", type_str);
	if (ret < 0 || ret >= sizeof(info_str)) {
		return KNOT_ENOMEM;
	}

	if (knot_rrset_rdata_rr_count(rrsig) == 0) {
		err_handler_handle_error(handler, node, ZC_ERR_RRSIG_NO_RRSIG,
		                         info_str);
		return KNOT_EOK;
	}

	if (knot_rdata_rrsig_type_covered(rrsig, 0) !=
	    knot_rrset_type(rrset)) {
		/* zoneparser would not let this happen
		 * but to be on the safe side
		 */
		err_handler_handle_error(handler, node,
		                         ZC_ERR_RRSIG_RDATA_TYPE_COVERED,
		                         info_str);
	}

	/* label number at the 2nd index should be same as owner's */
	uint8_t labels_rdata = knot_rdata_rrsig_labels(rrsig, rr_pos);

	int tmp = knot_dname_labels(knot_rrset_owner(rrset), NULL) - labels_rdata;

	if (tmp != 0) {
		/* if name has wildcard, label must not be included */
		if (!knot_dname_is_wildcard(knot_rrset_owner(rrset))) {
			err_handler_handle_error(handler, node,
			                         ZC_ERR_RRSIG_RDATA_LABELS,
			                         info_str);
		} else {
			if (abs(tmp) != 1) {
				err_handler_handle_error(handler, node,
				             ZC_ERR_RRSIG_RDATA_LABELS,
				                         info_str);
			}
		}
	}

	/* check original TTL */
	uint32_t original_ttl =
		knot_rdata_rrsig_original_ttl(rrsig, rr_pos);

	if (original_ttl != knot_rrset_ttl(rrset)) {
		err_handler_handle_error(handler, node, ZC_ERR_RRSIG_RDATA_TTL,
		                         info_str);
	}

	/* Check for expired signature. */
	if (knot_rdata_rrsig_sig_expiration(rrsig, rr_pos) < time(NULL)) {
		err_handler_handle_error(handler, node,
		                         ZC_ERR_RRSIG_RDATA_EXPIRATION,
		                         info_str);
	}

	/* Check if DNSKEY exists. */
	if (!dnskey_rrset) {
		err_handler_handle_error(handler, node,
		                         ZC_ERR_RRSIG_NO_DNSKEY, info_str);
	}

	/* signer's name is same as in the zone apex */
	const knot_dname_t *signer_name =
		knot_rdata_rrsig_signer_name(rrsig, rr_pos);

	/* dnskey is in the apex node */
	if (dnskey_rrset &&
	    knot_dname_cmp(signer_name, knot_rrset_owner(dnskey_rrset)) != 0
	) {
		err_handler_handle_error(handler, node,
		                         ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER,
		                         info_str);
	}

	/* Compare algorithm, key tag and signer's name with DNSKEY rrset
	 * one of the records has to match. Signer name has been checked
	 * before */
	
	int match = 0;
	uint8_t rrsig_alg = knot_rdata_rrsig_algorithm(rrsig, rr_pos);
	uint16_t key_tag_rrsig = knot_rdata_rrsig_key_tag(rrsig, rr_pos);
	for (uint16_t i = 0; i < knot_rrset_rdata_rr_count(dnskey_rrset) &&
	     !match; ++i) {
		uint8_t dnskey_alg =
			knot_rdata_dnskey_alg(dnskey_rrset, i);
		if (rrsig_alg != dnskey_alg) {
			continue;
		}
		
		/* Calculate keytag. */
		uint16_t dnskey_key_tag =
			knot_keytag(knot_rrset_get_rdata(dnskey_rrset, i),
		                    rrset_rdata_item_size(dnskey_rrset, i));
		if (key_tag_rrsig != dnskey_key_tag) {
			continue;
		}
		
		/* Final step - check DNSKEY validity. */
		if (check_dnskey_rdata(dnskey_rrset, i) == KNOT_EOK) {
			match = 1;
		} else {
			err_handler_handle_error(handler, node,
			                         ZC_ERR_RRSIG_RDATA_SIGNED_WRONG,
			                         "DNSKEY RDATA not matching");
		}
	}
	
	if (!match) {
		err_handler_handle_error(handler, node,
		                         ZC_ERR_RRSIG_NO_DNSKEY, info_str);
	}

	return KNOT_EOK;
}

/*!
 * \brief Semantic check - RRSet's RRSIG.
 *
 * \param rrset RRSet containing RRSIG.
 * \param dnskey_rrset
 * \param nsec3 NSEC3 active.
 *
 * \retval KNOT_EOK on success.
 *
 * \return Appropriate error code if error was found.
 */
static int check_rrsig_in_rrset(err_handler_t *handler,
                                const knot_node_t *node,
                                const knot_rrset_t *rrset,
                                const knot_rrset_t *dnskey_rrset)
{
	if (handler == NULL || node == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}
	
	/* Prepare additional info string. */
	char info_str[50];
	int ret = snprintf(info_str, sizeof(info_str), "Record type: %d.",
	                   knot_rrset_type(rrset));
	if (ret < 0 || ret >= sizeof(info_str)) {
		return KNOT_ENOMEM;
	}
	
	const knot_rrset_t *rrsigs = knot_rrset_rrsigs(rrset);

	if (rrsigs == NULL) {
		err_handler_handle_error(handler, node,
		                         ZC_ERR_RRSIG_NO_RRSIG,
		                         info_str);
		return KNOT_EOK;
	}

	/* signed rrsig - nonsense */
	if (knot_rrset_rrsigs(rrsigs) != NULL) {
		err_handler_handle_error(handler, node,
		                         ZC_ERR_RRSIG_SIGNED,
		                         info_str);
		/* Safe to continue, nothing is malformed. */
	}

	/* Different owner, class, ttl */

	if (knot_dname_cmp(knot_rrset_owner(rrset),
				 knot_rrset_owner(rrsigs)) != 0) {
		err_handler_handle_error(handler, node,
		                         ZC_ERR_RRSIG_OWNER,
		                         info_str);
	}

	if (knot_rrset_class(rrset) != knot_rrset_class(rrsigs)) {
		err_handler_handle_error(handler, node,
		                         ZC_ERR_RRSIG_CLASS,
		                         info_str);
	}

	if (knot_rrset_ttl(rrset) != knot_rrset_ttl(rrsigs)) {
		err_handler_handle_error(handler, node,
		                         ZC_ERR_RRSIG_TTL,
		                         info_str);
	}

	if (knot_rrset_rdata_rr_count(rrsigs) == 0) {
		/* Nothing to check, and should not happen. */
		return KNOT_EOK;
	}
	
	for (uint16_t i = 0; i < knot_rrset_rdata_rr_count(rrsigs); ++i) {
		int ret = check_rrsig_rdata(handler, node, rrsigs, i, rrset,
		                            dnskey_rrset);
		if (ret != KNOT_EOK) {
			dbg_semcheck("Could not check RRSIG properly (%s).\n",
			             knot_strerror(ret));
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Returns bit on index from array in network order. Taken from NSD.
 *
 * \param bits Array in network order.
 * \param index Index to return from array.
 *
 * \return int Bit on given index.
 */
static int get_bit(uint8_t *bits, size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * leftmost bit.
	 */
	return bits[index / 8] & (1 << (7 - index % 8));
}

/*!
 * \brief Converts NSEC bitmap to array of integers. (Inspired by NSD code)
 *
 * \param item Item containing the bitmap.
 * \param array Array to be created.
 * \param count Count of items in array.
 *
 * \retval KNOT_OK on success.
 * \retval KNOT_NOMEM on memory error.
 */
static int rdata_nsec_to_type_array(const knot_rrset_t *rrset, size_t pos,
				    uint16_t **array, size_t *count)
{
	assert(*array == NULL);
	assert(rrset->type == KNOT_RRTYPE_NSEC || rrset->type == KNOT_RRTYPE_NSEC3);
	
	uint8_t *data = NULL;
	uint16_t rr_bitmap_size = 0;
	if (rrset->type == KNOT_RRTYPE_NSEC) {
		knot_rdata_nsec_bitmap(rrset, pos, &data, &rr_bitmap_size);
	} else {
		knot_rdata_nsec3_bitmap(rrset, pos, &data, &rr_bitmap_size);
	}
	if (data == NULL) {
		return KNOT_EMALF;
	}
	
	*count = 0;
	int increment = 0;
	for (int i = 0; i < rr_bitmap_size; i += increment) {
		increment = 0;
		uint8_t window = data[i];
		increment++;

		uint8_t bitmap_size = data[i + increment];
		increment++;

		uint8_t *bitmap =
			malloc(sizeof(uint8_t) * (bitmap_size));
		if (bitmap == NULL) {
			ERR_ALLOC_FAILED;
			free(*array);
			return KNOT_ENOMEM;
		}

		memcpy(bitmap, data + i + increment,
		       bitmap_size);

		increment += bitmap_size;

		for (int j = 0; j < bitmap_size * 8; j++) {
			if (get_bit(bitmap, j)) {
				(*count)++;
				void *tmp = realloc(*array,
						    sizeof(uint16_t) *
						    *count);
				if (tmp == NULL) {
					ERR_ALLOC_FAILED;
					free(bitmap);
					free(*array);
					return KNOT_ENOMEM;
				}
				*array = tmp;
				(*array)[*count - 1] = j + window * 256;
			}
		}
		free(bitmap);
	}

	return KNOT_EOK;
}

/* should write error, not return values !!! */

/*!
 * \brief Semantic check - check node's NSEC node.
 *
 * \param zone Current zone.
 * \param node Node to be checked.
 * \param handler Error handler
 *
 * \retval KNOT_EOK if no error was found.
 *
 * \return Appropriate error code if error was found.
 */
static int check_nsec3_node_in_zone(knot_zone_contents_t *zone,
                                    knot_node_t *node, err_handler_t *handler)
{
	assert(handler);
	const knot_node_t *nsec3_node = knot_node_nsec3_node(node);

	if (nsec3_node == NULL) {
		/* I know it's probably not what RFCs say, but it will have to
		 * do for now. */
		if (knot_node_rrset(node, KNOT_RRTYPE_DS) != NULL) {
			err_handler_handle_error(handler, node,
					ZC_ERR_NSEC3_UNSECURED_DELEGATION,
			                         NULL);
			return KNOT_EOK;
		} else {
			/* Unsecured delegation, check whether it is part of
			 * opt-out span */
			const knot_node_t *nsec3_previous;
			const knot_node_t *nsec3_node;

			if (knot_zone_contents_find_nsec3_for_name(zone,
						knot_node_owner(node),
						&nsec3_node,
						&nsec3_previous) != 0) {
				err_handler_handle_error(handler, node,
						 ZC_ERR_NSEC3_NOT_FOUND, NULL);
				return KNOT_EOK;
			}

			if (nsec3_node == NULL) {
				/* Probably should not ever happen */
				return KNOT_ERROR;
			}

			assert(nsec3_previous);

			const knot_rrset_t *previous_rrset =
				knot_node_rrset(nsec3_previous,
						KNOT_RRTYPE_NSEC3);

			assert(previous_rrset);

			/* check for Opt-Out flag */
			uint8_t flags =
				knot_rdata_nsec3_flags(previous_rrset, 0);
			uint8_t opt_out_mask = 1;

			if (!(flags & opt_out_mask)) {
				err_handler_handle_error(handler, node,
					ZC_ERR_NSEC3_UNSECURED_DELEGATION_OPT,
				                         NULL);
				/* We cannot continue from here. */
				return KNOT_EOK;
			}
		}
	}

	const knot_rrset_t *nsec3_rrset =
		knot_node_rrset(nsec3_node, KNOT_RRTYPE_NSEC3);

	assert(nsec3_rrset);

	const knot_rrset_t *soa_rrset =
		knot_node_rrset(knot_zone_contents_apex(zone),
	                        KNOT_RRTYPE_SOA);
	assert(soa_rrset);
	uint32_t minimum_ttl = knot_rdata_soa_minimum(soa_rrset);

	if (knot_rrset_ttl(nsec3_rrset) != minimum_ttl) {
			err_handler_handle_error(handler, node,
						 ZC_ERR_NSEC3_RDATA_TTL, NULL);
	}

	/* Result is a dname, it can't be larger */
	const knot_node_t *apex = knot_zone_contents_apex(zone);
	uint8_t *next_dname_str = NULL;
	uint8_t next_dname_size = 0;
	knot_rdata_nsec3_next_hashed(nsec3_rrset, 0, &next_dname_str,
	                             &next_dname_size);
	knot_dname_t *next_dname = knot_nsec3_hash_to_dname(next_dname_str,
	                                                    next_dname_size,
	                                                    apex->owner);
	if (next_dname == NULL) {
		log_zone_warning("Could not create new dname!\n");
		return KNOT_ERROR;
	}

	if (knot_zone_contents_find_nsec3_node(zone, next_dname) == NULL) {
		err_handler_handle_error(handler, node,
					 ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
	}

	/* Directly discard. */
	knot_dname_free(&next_dname);
	
	size_t arr_size;
	uint16_t *array = NULL;
	/* TODO only works for one NSEC3 RR. */
	int ret = rdata_nsec_to_type_array(nsec3_rrset, 0, &array, &arr_size);
	if (ret != KNOT_EOK) {
		dbg_semcheck("semchecks: check_nsec3_node: Could not "
		             "convert NSEC to type array. Reason: %s\n",
		             knot_strerror(ret));
		return ret;
	}
	
	uint16_t type = 0;
	for (int j = 0; j < arr_size; j++) {
		/* test for each type's presence */
		type = array[j];
		if (type == KNOT_RRTYPE_RRSIG) {
		       continue;
		}
		
		if (knot_node_rrset(node,
				      type) == NULL) {
			err_handler_handle_error(handler, node,
						 ZC_ERR_NSEC3_RDATA_BITMAP,
			                         NULL);
		}
	}
	
	/* Check that the node only contains NSEC3 and RRSIG. */
	const knot_rrset_t **rrsets = knot_node_rrsets_no_copy(nsec3_node);
	if (rrsets == NULL) {
		return KNOT_ENOMEM;
	}
	
	for (int i = 0; i < knot_node_rrset_count(nsec3_node); i++) {
		uint16_t type = knot_rrset_type(rrsets[i]);
		if (!(type == KNOT_RRTYPE_NSEC3 ||
		    type == KNOT_RRTYPE_RRSIG)) {
			err_handler_handle_error(handler, nsec3_node,
			                         ZC_ERR_NSEC3_EXTRA_RECORD,
			                         NULL);
		}
	}

	free(array);

	return KNOT_EOK;
}

struct sem_check_param {
	int node_count;
};

/*!
 * \brief Used only to count number of nodes in zone tree.
 *
 * \param node Node to be counted
 * \param data Count casted to void *
 */
static int count_nodes_in_tree(knot_node_t *node, void *data)
{
	struct sem_check_param *param = (struct sem_check_param *)data;
	param->node_count++;

	return KNOT_EOK;
}

static int zone_is_secure(const knot_zone_contents_t *z)
{
	const knot_rrset_t *soa_rr =
		knot_node_rrset(knot_zone_contents_apex(z),
	                        KNOT_RRTYPE_SOA);
	return (soa_rr && soa_rr->rrsigs ? 1 : 0);
}

static int sem_check_node_mandatory(knot_zone_contents_t *zone,
                                    knot_node_t *node, int level,
                                    err_handler_t *handler, int *fatal_error)
{
	const knot_rrset_t *cname_rrset =
			knot_node_rrset(node, KNOT_RRTYPE_CNAME);
	if (cname_rrset != NULL) {
		/* No DNSSEC and yet there is more than one rrset in node */
		if (level == 1 &&
		                knot_node_rrset_count(node) != 1) {
			*fatal_error = 1;
			err_handler_handle_error(handler, node,
			                         ZC_ERR_CNAME_EXTRA_RECORDS,
			                         NULL);
		} else if (knot_node_rrset_count(node) != 1) {
			/* With DNSSEC node can contain RRSIG or NSEC */
			if (!(knot_node_rrset(node, KNOT_RRTYPE_RRSIG) ||
			      knot_node_rrset(node, KNOT_RRTYPE_NSEC)) ||
			    knot_node_rrset_count(node) > 3) {
				*fatal_error = 1;
				err_handler_handle_error(handler, node,
				ZC_ERR_CNAME_EXTRA_RECORDS_DNSSEC, NULL);
			}
		}

		if (knot_rrset_rdata_rr_count(cname_rrset) != 1) {
			*fatal_error = 1;
			err_handler_handle_error(handler, node,
			                         ZC_ERR_CNAME_MULTIPLE, NULL);
		}
	}

	const knot_rrset_t *dname_rrset =
		knot_node_rrset(node, KNOT_RRTYPE_DNAME);
	if (dname_rrset != NULL) {
		if (knot_node_rrset(node, KNOT_RRTYPE_CNAME)) {
			*fatal_error = 1;
			err_handler_handle_error(handler, node,
			                         ZC_ERR_CNAME_EXTRA_RECORDS,
			                         NULL);
		}
		
		if (node->children != 0) {
			/*
			 * With DNSSEC and node being zone apex,
			 * NSEC3 and its RRSIG can be present.
			 */
			
			/* The NSEC3 tree can thus only have one node. */
			struct sem_check_param param;
			param.node_count = 0;
			int ret_apply =
				knot_zone_contents_nsec3_apply_inorder(zone,
				count_nodes_in_tree,
				&param);
			if (ret_apply != KNOT_EOK || param.node_count != 1) {
				*fatal_error = 1;
				err_handler_handle_error(handler, node,
				                         ZC_ERR_DNAME_CHILDREN,
				                         NULL);
				/*
				 * Valid case: Node is apex, it has NSEC3 node
				 * and that node has only one RRSet.
				 */
			} else if (!((knot_zone_contents_apex(zone) == node) &&
			           knot_node_nsec3_node(node) &&
			           knot_node_rrset_count(knot_node_nsec3_node(
			                                 node)) == 1)) {
				*fatal_error = 1;
				err_handler_handle_error(handler, node,
				                         ZC_ERR_DNAME_CHILDREN,
				                         NULL);
			}
		}
	}
	
	return KNOT_EOK;
}

static int sem_check_node_optional(knot_zone_contents_t *zone,
                                   knot_node_t *node, err_handler_t *handler)
{
	if (knot_node_is_deleg_point(node) || knot_zone_contents_apex(zone) ==
	                node) {
		const knot_rrset_t *ns_rrset =
				knot_node_rrset(node, KNOT_RRTYPE_NS);
		if (ns_rrset == NULL || ns_rrset->rdata_count == 0) {
			err_handler_handle_error(handler, node,
			                         ZC_ERR_MISSING_NS_DEL_POINT,
			                         NULL);
			return KNOT_EOK;
		}
		//FIXME this should be an error as well ! (i guess)

		/* TODO How about multiple RRs? */
		knot_dname_t *ns_dname =
			knot_dname_copy(knot_rdata_ns_name(ns_rrset,
		                             0));
		if (ns_dname == NULL) {
			return KNOT_ENOMEM;
		}

		const knot_node_t *glue_node =
				knot_zone_contents_find_node(zone, ns_dname);
		
		if (knot_dname_is_sub(ns_dname,
			      knot_node_owner(knot_zone_contents_apex(zone)))) {
			if (glue_node == NULL) {
				/* Try wildcard ([1]* + suffix). */
				knot_dname_t wildcard[KNOT_DNAME_MAXLEN];
				memcpy(wildcard, "\x1""*", 2);
				knot_dname_to_wire(wildcard + 2,
				                   knot_wire_next_label(ns_dname, NULL),
				                   sizeof(wildcard));
				const knot_node_t *wildcard_node = 
					knot_zone_contents_find_node(zone,
				                                     wildcard);
				if (wildcard_node == NULL) {
					err_handler_handle_error(handler, node,
							 ZC_ERR_GLUE_NODE,
							NULL );
				} else {
					/* Look for A or AAAA. */
					if ((knot_node_rrset(wildcard_node,
					    KNOT_RRTYPE_A) == NULL) &&
					    (knot_node_rrset(wildcard_node,
					    KNOT_RRTYPE_AAAA) == NULL)) {
						err_handler_handle_error(handler, node,
								 ZC_ERR_GLUE_RECORD,
								 NULL);
					}
				}	
			} else {
				if ((knot_node_rrset(glue_node,
					       KNOT_RRTYPE_A) == NULL) &&
				    (knot_node_rrset(glue_node,
					       KNOT_RRTYPE_AAAA) == NULL)) {
					err_handler_handle_error(handler, node,
							 ZC_ERR_GLUE_RECORD,
							 NULL);
				}
			}
		}
		knot_dname_free(&ns_dname);
	}
	return KNOT_EOK;
}

/*!
 * \brief Run semantic checks for node without DNSSEC-related types.
 *
 * \param zone Current zone.
 * \param node Node to be checked.
 * \param do_checks Level of checks to be done.
 * \param handler Error handler.
 *
 * \retval KNOT_EOK if no error was found.
 *
 * \return Appropriate error code if error was found.
 */
int sem_check_node_plain(knot_zone_contents_t *zone,
                         knot_node_t *node,
                         int do_checks,
                         err_handler_t *handler,
                         int only_mandatory,
                         int *fatal_error)
{
	assert(handler);
	if (do_checks == -1) {
		/* Determine level for our own. */
		do_checks = (zone_is_secure(zone) ? 2 : 1);
	}
	
	if (only_mandatory == 1) {
		/* Check CNAME and DNAME, else no-op. */
		return sem_check_node_mandatory(zone, node, do_checks, handler,
		                                fatal_error);
	} else {
		/*
		 * This is an extra run, so we do not need to check mandatory
		 * things, since they've already been checked during parsing.
		 */
		return sem_check_node_optional(zone, node, handler);
	}
}

/*!
 * \brief Run semantic checks for node with DNSSEC-related types.
 *
 * \param zone Current zone.
 * \param node Node to be checked.
 * \param last_node Last node in canonical order.
 * \param handler Error handler.
 * \param nsec3 NSEC3 used.
 *
 * \retval KNOT_EOK if no error was found.
 *
 * \return Appropriate error code if error was found.
 */
static int semantic_checks_dnssec(knot_zone_contents_t *zone,
				  knot_node_t *node,
				  knot_node_t **last_node,
				  err_handler_t *handler,
				  char nsec3)
{
	assert(handler);
	assert(node);
	char auth = !knot_node_is_non_auth(node);
	char deleg = knot_node_is_deleg_point(node);
	uint rrset_count = knot_node_rrset_count(node);
	const knot_rrset_t **rrsets = knot_node_rrsets_no_copy(node);
	const knot_rrset_t *dnskey_rrset =
		knot_node_rrset(knot_zone_contents_apex(zone),
				  KNOT_RRTYPE_DNSKEY);

	int ret = 0;

	for (int i = 0; i < rrset_count; i++) {
		const knot_rrset_t *rrset = rrsets[i];
		if (auth && !deleg &&
		    (ret = check_rrsig_in_rrset(handler, node,
		                                rrset, dnskey_rrset)) != 0) {
			err_handler_handle_error(handler, node, ret, NULL);
		}

		if (!nsec3 && auth) {
			/* check for NSEC record */
			const knot_rrset_t *nsec_rrset =
					knot_node_rrset(node,
							  KNOT_RRTYPE_NSEC);

			if (nsec_rrset == NULL) {
				err_handler_handle_error(handler, node,
							 ZC_ERR_NO_NSEC, NULL);
			} else {
				/* check NSEC/NSEC3 bitmap */
				size_t count;
				uint16_t *array = NULL;
				
				int ret = rdata_nsec_to_type_array(nsec_rrset,
				                                   0,
				                                   &array,
				                                   &count);
				if (ret != KNOT_EOK) {
					dbg_semcheck("semchecks: "
					             "Could not create type "
					             "array. Reason: %s.\n",
					             knot_strerror(ret));
					return ret;
				}

				uint16_t type = 0;
				for (int j = 0; j < count; j++) {
					/* test for each type's presence */
					type = array[j];
					if (type == KNOT_RRTYPE_RRSIG) {
						continue;
					}
					if (knot_node_rrset(node,
							      type) == NULL) {
					err_handler_handle_error(
						handler,
						node,
						ZC_ERR_NSEC_RDATA_BITMAP, NULL);
					}
				}
				free(array);
			}

			/* Test that only one record is in the
				 * NSEC RRSet */

			if (knot_rrset_rdata_rr_count(nsec_rrset) != 1) {
				err_handler_handle_error(handler,
						 node,
						 ZC_ERR_NSEC_RDATA_MULTIPLE,
				                NULL);
			}

			/*
			 * Test that NSEC chain is coherent.
			 * We have already checked that every
			 * authoritative node contains NSEC record
			 * so checking should only be matter of testing
			 * the next link in each node.
			 */

			if (nsec_rrset != NULL) {
				const knot_dname_t *next_domain =
					knot_rdata_nsec_next(nsec_rrset, 0);
				assert(next_domain);

				if (knot_zone_contents_find_node(zone,
				                                 next_domain) ==
				    NULL) {
					err_handler_handle_error(handler,
						node,
						ZC_ERR_NSEC_RDATA_CHAIN, NULL);
				}

				if (knot_dname_cmp(next_domain,
				    knot_node_owner(knot_zone_contents_apex(zone)))
					== 0) {
					/* saving the last node */
					*last_node = node;
				}

			}
		} else if (nsec3 && (auth || deleg)) { /* nsec3 */
			int ret = check_nsec3_node_in_zone(zone, node,
			                                   handler);
			if (ret != KNOT_EOK) {
				dbg_semcheck("semchecks: check_dnssec: "
				              "Checking of NSEC3 node "
				              "failed. Reason: %s.\n",
				              knot_strerror(ret));
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Function called by zone traversal function. Used to call
 *        knot_zone_save_enclosers.
 *
 * \param node Node to be searched.
 * \param data Arguments.
 */
static int do_checks_in_tree(knot_node_t *node, void *data)
{
	dbg_semcheck_verb("semcheck: do_check_in_tree: Checking node: %s\n",
	                  knot_dname_to_str(node->owner));

	arg_t *args = (arg_t *)data;

	knot_zone_contents_t *zone = (knot_zone_contents_t *)args->arg1;

	knot_node_t **last_node = (knot_node_t **)args->arg5;

	err_handler_t *handler = (err_handler_t *)args->arg6;
	
	char do_checks = *((char *)(args->arg3));

	if (do_checks) {
		sem_check_node_plain(zone, node, do_checks, handler, 0,
		                      (int *)args->arg7);
	} else {
		assert(handler);
		/* All CNAME/DNAME checks are mandatory. */
		handler->options.log_cname = 1;
		int check_level = 1 + (zone_is_secure(zone) ? 1 : 0);
		sem_check_node_plain(zone, node, check_level, handler, 1,
		                      (int *)args->arg7);
		return KNOT_EOK;
	}

	if (do_checks > 1) {
		semantic_checks_dnssec(zone, node, last_node,
				       handler, do_checks == 3);
	}

	return KNOT_EOK;
}

int zone_do_sem_checks(knot_zone_contents_t *zone, int do_checks,
                       err_handler_t *handler, knot_node_t *first_nsec3_node,
                       knot_node_t *last_nsec3_node)
{
	if (!zone || !handler) {
		return KNOT_EINVAL;
	}
	knot_node_t *last_node = NULL;
	arg_t arguments;
	arguments.arg1 = zone;
	arguments.arg3 = &do_checks;
	arguments.arg4 = NULL; // UNUSED
	arguments.arg5 = &last_node;
	arguments.arg6 = handler;
	int fatal_error = 0;
	arguments.arg7 = (void *)&fatal_error;

	int ret = knot_zone_contents_tree_apply_inorder(zone,
	                                                do_checks_in_tree,
	                                                &arguments);
	if (ret != KNOT_EOK) {
		return ret;
	}
	if (fatal_error) {
		return KNOT_ERROR;
	}
	
	log_cyclic_errors_in_zone(handler, zone, last_node, first_nsec3_node,
	                          last_nsec3_node, do_checks);
	
	return KNOT_EOK;
}

void log_cyclic_errors_in_zone(err_handler_t *handler,
                               knot_zone_contents_t *zone,
                               knot_node_t *last_node,
                               const knot_node_t *first_nsec3_node,
                               const knot_node_t *last_nsec3_node,
                               char do_checks)
{
	if (do_checks == 3) {
		/* Each NSEC3 node should only contain one RRSET. */
		if (last_nsec3_node == NULL || first_nsec3_node == NULL) {
			return;
		}
		const knot_rrset_t *nsec3_rrset =
			knot_node_rrset(last_nsec3_node,
		                              KNOT_RRTYPE_NSEC3);
		if (nsec3_rrset == NULL) {
			err_handler_handle_error(handler, last_nsec3_node,
						 ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
			return;
		}

		/* Result is a dname, it can't be larger */
		const knot_node_t *apex = knot_zone_contents_apex(zone);
		uint8_t *next_dname_str = NULL;
		uint8_t next_dname_size = 0;
		knot_rdata_nsec3_next_hashed(nsec3_rrset, 0, &next_dname_str,
		                             &next_dname_size);
		knot_dname_t *next_dname = knot_nsec3_hash_to_dname(next_dname_str,
		                                                    next_dname_size,
		                                                    apex->owner);
		if (next_dname == NULL) {
			log_zone_warning("Could not create new dname!\n");
			return;
		}

		/* Check it points somewhere first. */
		if (knot_zone_contents_find_nsec3_node(zone, next_dname) == NULL) {
			assert(knot_zone_contents_find_node(zone,
			                                    next_dname) ==
			                                    NULL);
			err_handler_handle_error(handler, last_nsec3_node,
						 ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
		} else {
			/* Compare with the actual first NSEC3 node. */
			if (!knot_dname_is_equal(first_nsec3_node->owner, next_dname)) {
				err_handler_handle_error(handler, last_nsec3_node,
							 ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
			}
		}

		/* Directly discard. */
		knot_dname_free(&next_dname);

	} else if (do_checks == 2 ) {
		if (last_node == NULL) {
			err_handler_handle_error(handler, last_node,
				ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC, NULL);
				return;
		} else {
			const knot_rrset_t *nsec_rrset =
				knot_node_rrset(last_node,
						  KNOT_RRTYPE_NSEC);

			if (nsec_rrset == NULL) {
				err_handler_handle_error(handler, last_node,
					 ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC, NULL);
				return;
			}

			const knot_dname_t *next_dname =
				knot_rdata_nsec_next(nsec_rrset, 0);
			assert(next_dname);

			const knot_dname_t *apex_dname =
				knot_node_owner(knot_zone_contents_apex(zone));
			assert(apex_dname);

			if (knot_dname_cmp(next_dname, apex_dname) !=0) {
				err_handler_handle_error(handler, last_node,
					 ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC, NULL);
			}
		}
	}
}
