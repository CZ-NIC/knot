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

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dnssec/keytag.h"
#include "knot/zone/semantic-check.h"
#include "knot/common/log.h"
#include "knot/dnssec/zone-nsec.h"
#include "libknot/libknot.h"
#include "libknot/dnssec/rrset-sign.h"
#include "contrib/base32hex.h"
#include "contrib/mempattern.h"
#include "contrib/wire.h"

static char *error_messages[(-ZC_ERR_UNKNOWN) + 1] = {
	[-ZC_ERR_MISSING_SOA] =
	"SOA record missing in zone",
	[-ZC_ERR_MISSING_NS_DEL_POINT] =
	"NS record missing in zone apex or in delegation point",
	[-ZC_ERR_TTL_MISMATCH] =
	"RRSet TTLs mismatched",

	[-ZC_ERR_RRSIG_RDATA_TYPE_COVERED] =
	"RRSIG, type covered RDATA field is wrong",
	[-ZC_ERR_RRSIG_RDATA_TTL] =
	"RRSIG, TTL RDATA field is wrong",
	[-ZC_ERR_RRSIG_RDATA_EXPIRATION] =
	"RRSIG, expired signature",
	[-ZC_ERR_RRSIG_RDATA_LABELS] =
	"RRSIG, labels RDATA field is wrong",
	[-ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER] =
	"RRSIG, signer name is different than in DNSKEY",
	[-ZC_ERR_RRSIG_NO_DNSKEY] =
	"RRSIG, missing DNSKEY for RRSIG",
	[-ZC_ERR_RRSIG_RDATA_SIGNED_WRONG] =
	"RRSIG, key error",
	[-ZC_ERR_RRSIG_NO_RRSIG] =
	"RRSIG, no RRSIG",
	[-ZC_ERR_RRSIG_SIGNED] =
	"RRSIG, signed RRSIG",
	[-ZC_ERR_RRSIG_OWNER] =
	"RRSIG, owner name RDATA field is wrong",
	[-ZC_ERR_RRSIG_CLASS] =
	"RRSIG, class is wrong",
	[-ZC_ERR_RRSIG_TTL] =
	"RRSIG, TTL is wrong",

	[-ZC_ERR_NO_NSEC] =
	"NSEC, missing record",
	[-ZC_ERR_NSEC_RDATA_BITMAP] =
	"NSEC, wrong bitmap",
	[-ZC_ERR_NSEC_RDATA_MULTIPLE] =
	"NSEC, multiple records",
	[-ZC_ERR_NSEC_RDATA_CHAIN] =
	"NSEC, chain is not coherent",
	[-ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC] =
	"NSEC, chain is not cyclic",

	[-ZC_ERR_NSEC3_UNSECURED_DELEGATION] =
	"NSEC3, zone contains unsecured delegation",
	[-ZC_ERR_NSEC3_NOT_FOUND] =
	"NSEC3, failed to find previous NSEC3 record in the zone",
	[-ZC_ERR_NSEC3_UNSECURED_DELEGATION_OPT] =
	"NSEC3, unsecured delegation is not part of the opt-out span",
	[-ZC_ERR_NSEC3_RDATA_TTL] =
	"NSEC3, original TTL RDATA field is wrong",
	[-ZC_ERR_NSEC3_RDATA_CHAIN] =
	"NSEC3, chain is not coherent",
	[-ZC_ERR_NSEC3_RDATA_BITMAP] =
	"NSEC3, wrong bitmap",
	[-ZC_ERR_NSEC3_EXTRA_RECORD] =
	"NSEC3, node contains extra record, unsupported",

	[-ZC_ERR_CNAME_EXTRA_RECORDS] =
	"CNAME, node contains other records",
	[-ZC_ERR_DNAME_CHILDREN] =
	"DNAME, node has children",
	[-ZC_ERR_CNAME_EXTRA_RECORDS_DNSSEC] =
	"CNAME, node contains other records than RRSIG and NSEC/NSEC3",
	[-ZC_ERR_CNAME_MULTIPLE] =
	"CNAME, multiple records",
	[-ZC_ERR_DNAME_MULTIPLE] =
	"DNAME, multiple records",
	[-ZC_ERR_CNAME_WILDCARD_SELF] =
	"CNAME, wildcard pointing to itself",
	[-ZC_ERR_DNAME_WILDCARD_SELF] =
	"DNAME, wildcard pointing to itself",

	/* ^
	   | Important errors (to be logged on first occurence and counted) */

	/* Below are errors of lesser importance, to be counted unless
	   specified otherwise */

	[-ZC_ERR_GLUE_NODE] =
	"GLUE, node with glue record missing",
	[-ZC_ERR_GLUE_RECORD] =
	"GLUE, record with glue address missing",
};

void err_handler_init(err_handler_t *h)
{
	memset(h, 0, sizeof(err_handler_t));
	memset(h->errors, 0, sizeof(unsigned) * (-ZC_ERR_UNKNOWN + 1));
	h->options.log_cname = 0;
	h->options.log_glue = 0;
	h->options.log_rrsigs = 0;
	h->options.log_nsec = 0;
	h->options.log_nsec3 = 0;
}

err_handler_t *err_handler_new()
{
	err_handler_t *handler= malloc(sizeof(err_handler_t));
	if (handler == NULL) {
		return NULL;
	}
	err_handler_init(handler);

	handler->options.log_cname = 1;
	handler->options.log_glue = 1;
	handler->options.log_rrsigs = 1;
	handler->options.log_nsec = 1;
	handler->options.log_nsec3 = 1;

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
				const zone_contents_t *zone,
				const zone_node_t *node,
				int error, const char *data)
{
	const knot_dname_t *zone_name = zone->apex->owner;

	if (error > (int)ZC_ERR_GLUE_RECORD) {
		log_zone_warning(zone_name, "semantic check, unknown error");
		return;
	}

	if (node == NULL) {
		log_zone_warning(zone_name, "semantic check, %d warnings, error (%s)",
		                 handler->errors[-error], error_messages[-error]);
		return;
	}

	handler->error_count++;

	char *name = knot_dname_to_str_alloc(node->owner);
	const char *errmsg = error_messages[-error];

	log_zone_warning(zone_name, "semantic check, node '%s' (%s%s%s)",
	                 name,
			 errmsg ? errmsg : "unknown error",
			 data ? " " : "",
			 data ? data : "");

	free(name);
}

int err_handler_handle_error(err_handler_t *handler, const zone_contents_t *zone,
			     const zone_node_t *node, int error, const char *data)
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

	if (error < ZC_ERR_GENERIC_GENERAL_ERROR) {
		/* The two errors before SOA were handled */
		log_error_from_node(handler, zone, node, error, data);
		return KNOT_EOK;
	} else if ((error < ZC_ERR_RRSIG_GENERAL_ERROR) &&
		   ((handler->errors[-error] == 0) ||
		   (handler->options.log_rrsigs))) {
		log_error_from_node(handler, zone, node, error, data);
	} else if ((error > ZC_ERR_RRSIG_GENERAL_ERROR) &&
		   (error < ZC_ERR_NSEC_GENERAL_ERROR) &&
		   ((handler->errors[-error] == 0) ||
		    (handler->options.log_nsec))) {
		log_error_from_node(handler, zone, node, error, data);
	} else if ((error > ZC_ERR_NSEC_GENERAL_ERROR) &&
		   (error < ZC_ERR_NSEC3_GENERAL_ERROR) &&
		   ((handler->errors[-error] == 0) ||
		    (handler->options.log_nsec3))) {
		log_error_from_node(handler, zone, node, error, data);
	} else if ((error > ZC_ERR_NSEC3_GENERAL_ERROR) &&
		   (error < ZC_ERR_CNAME_GENERAL_ERROR) &&
		   ((handler->errors[-error] == 0) ||
		    (handler->options.log_cname))) {
		log_error_from_node(handler, zone, node, error, data);
	} else if ((error > ZC_ERR_CNAME_GENERAL_ERROR) &&
		   (error < ZC_ERR_GLUE_GENERAL_ERROR) &&
		    handler->options.log_glue) {
		log_error_from_node(handler, zone, node, error, data);
	}

	handler->errors[-error]++;

	return KNOT_EOK;
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

	const knot_rdata_t *rr_data = knot_rdataset_at(&rrset->rrs, rdata_pos);
	uint16_t flags = wire_read_u16(knot_rdata_data(rr_data));
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
                             const zone_contents_t *zone,
                             const zone_node_t *node,
                             const knot_rdataset_t *rrsig,
                             size_t rr_pos,
                             const knot_rrset_t *rrset,
                             const knot_rrset_t *dnskey_rrset)
{
	/* Prepare additional info string. */
	char info_str[50] = { '\0' };
	char type_str[16] = { '\0' };
	knot_rrtype_to_string(rrset->type, type_str, sizeof(type_str));
	int ret = snprintf(info_str, sizeof(info_str), "record type '%s'", type_str);
	if (ret < 0 || ret >= sizeof(info_str)) {
		return KNOT_ENOMEM;
	}

	if (knot_rrsig_type_covered(rrsig, 0) != rrset->type) {
		err_handler_handle_error(handler, zone, node,
		                         ZC_ERR_RRSIG_RDATA_TYPE_COVERED,
		                         info_str);
	}

	/* label number at the 2nd index should be same as owner's */
	uint8_t labels_rdata = knot_rrsig_labels(rrsig, rr_pos);

	int tmp = knot_dname_labels(rrset->owner, NULL) - labels_rdata;

	if (tmp != 0) {
		/* if name has wildcard, label must not be included */
		if (!knot_dname_is_wildcard(rrset->owner)) {
			err_handler_handle_error(handler, zone, node,
			                         ZC_ERR_RRSIG_RDATA_LABELS,
			                         info_str);
		} else {
			if (abs(tmp) != 1) {
				err_handler_handle_error(handler, zone, node,
				             ZC_ERR_RRSIG_RDATA_LABELS,
				                         info_str);
			}
		}
	}

	/* check original TTL */
	uint32_t original_ttl = knot_rrsig_original_ttl(rrsig, rr_pos);

	uint16_t rr_count = rrset->rrs.rr_count;
	for (uint16_t i = 0; i < rr_count; ++i) {
		if (original_ttl != knot_rdata_ttl(knot_rdataset_at(&rrset->rrs, i))) {
			err_handler_handle_error(handler, zone, node,
			                         ZC_ERR_RRSIG_RDATA_TTL,
			                         info_str);
		}
	}

	/* Check for expired signature. */
	if (knot_rrsig_sig_expiration(rrsig, rr_pos) < time(NULL)) {
		err_handler_handle_error(handler, zone, node,
		                         ZC_ERR_RRSIG_RDATA_EXPIRATION,
		                         info_str);
	}

	/* Check if DNSKEY exists. */
	if (knot_rrset_empty(dnskey_rrset)) {
		err_handler_handle_error(handler, zone, node,
		                         ZC_ERR_RRSIG_NO_DNSKEY, info_str);
	}

	/* signer's name is same as in the zone apex */
	knot_dname_t *signer = knot_dname_copy(knot_rrsig_signer_name(rrsig, rr_pos), NULL);

	/* dnskey is in the apex node */
	if (!knot_rrset_empty(dnskey_rrset) &&
	    !knot_dname_is_equal(signer, dnskey_rrset->owner)) {
		err_handler_handle_error(handler, zone, node,
		                         ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER,
		                         info_str);
	}

	knot_dname_free(&signer, NULL);

	/* Compare algorithm, key tag and signer's name with DNSKEY rrset
	 * one of the records has to match. Signer name has been checked
	 * before */

	int match = 0;
	uint8_t rrsig_alg = knot_rrsig_algorithm(rrsig, rr_pos);
	uint16_t key_tag_rrsig = knot_rrsig_key_tag(rrsig, rr_pos);
	for (uint16_t i = 0; i < dnskey_rrset->rrs.rr_count &&
	     !match; ++i) {
		uint8_t dnskey_alg = knot_dnskey_alg(&dnskey_rrset->rrs, i);
		if (rrsig_alg != dnskey_alg) {
			continue;
		}

		/* Calculate keytag. */
		const knot_rdata_t *dnskey_rr = knot_rdataset_at(&dnskey_rrset->rrs, i);
		dnssec_binary_t rdata = {
			.size = knot_rdata_rdlen(dnskey_rr),
			.data = knot_rdata_data(dnskey_rr)
		};
		uint16_t dnskey_key_tag = 0;
		dnssec_keytag(&rdata, &dnskey_key_tag);

		if (key_tag_rrsig != dnskey_key_tag) {
			continue;
		}

		/* Final step - check DNSKEY validity. */
		if (check_dnskey_rdata(dnskey_rrset, i) == KNOT_EOK) {
			match = 1;
		} else {
			err_handler_handle_error(handler, zone, node,
			                         ZC_ERR_RRSIG_RDATA_SIGNED_WRONG,
			                         "DNSKEY RDATA not matching");
		}
	}

	if (!match) {
		err_handler_handle_error(handler, zone, node,
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
                                const zone_contents_t *zone,
                                const zone_node_t *node,
                                const knot_rrset_t *rrset,
                                const knot_rrset_t *dnskey_rrset)
{
	if (handler == NULL || node == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}
	/* Prepare additional info string. */
	char info_str[50] = { '\0' };
	char type_str[16] = { '\0' };
	knot_rrtype_to_string(rrset->type, type_str, sizeof(type_str));
	int ret = snprintf(info_str, sizeof(info_str), "record type '%s'",
	                   type_str);
	if (ret < 0 || ret >= sizeof(info_str)) {
		return KNOT_ENOMEM;
	}
	knot_rdataset_t rrsigs;
	knot_rdataset_init(&rrsigs);
	ret = knot_synth_rrsig(rrset->type,
	                           node_rdataset(node, KNOT_RRTYPE_RRSIG),
	                           &rrsigs, NULL);
	if (ret != KNOT_EOK) {
		if (ret != KNOT_ENOENT) {
			return ret;
		}
	}

	if (ret == KNOT_ENOENT) {
		err_handler_handle_error(handler, zone, node,
		                         ZC_ERR_RRSIG_NO_RRSIG,
		                         info_str);
		return KNOT_EOK;
	}

	/* signed rrsig - nonsense */
	if (node_rrtype_is_signed(node, KNOT_RRTYPE_RRSIG)) {
		err_handler_handle_error(handler, zone, node,
		                         ZC_ERR_RRSIG_SIGNED,
		                         info_str);
		/* Safe to continue, nothing is malformed. */
	}

	const knot_rdata_t *sig_rr = knot_rdataset_at(&rrsigs, 0);
	if (knot_rdata_ttl(knot_rdataset_at(&rrset->rrs, 0)) != knot_rdata_ttl(sig_rr)) {
		err_handler_handle_error(handler, zone, node,
		                         ZC_ERR_RRSIG_TTL,
		                         info_str);
	}

	for (uint16_t i = 0; i < (&rrsigs)->rr_count; ++i) {
		int ret = check_rrsig_rdata(handler, zone, node, &rrsigs, i,
		                            rrset, dnskey_rrset);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	knot_rdataset_clear(&rrsigs, NULL);
	return ret;
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
static int rdata_nsec_to_type_array(const knot_rdataset_t *rrs, uint16_t type,
                                    size_t pos, uint16_t **array, size_t *count)
{
	assert(*array == NULL);

	uint8_t *data = NULL;
	uint16_t rr_bitmap_size = 0;
	if (type == KNOT_RRTYPE_NSEC) {
		knot_nsec_bitmap(rrs, &data, &rr_bitmap_size);
	} else {
		knot_nsec3_bitmap(rrs, pos, &data, &rr_bitmap_size);
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
static int check_nsec3_node_in_zone(zone_contents_t *zone, zone_node_t *node,
                                    err_handler_t *handler)
{
	assert(handler);
	const zone_node_t *nsec3_node = node->nsec3_node;

	if (nsec3_node == NULL) {
		/* I know it's probably not what RFCs say, but it will have to
		 * do for now. */
		if (node_rrtype_exists(node, KNOT_RRTYPE_DS)) {
			err_handler_handle_error(handler, zone, node,
					ZC_ERR_NSEC3_UNSECURED_DELEGATION,
			                         NULL);
			return KNOT_EOK;
		} else {
			/* Unsecured delegation, check whether it is part of
			 * opt-out span */
			const zone_node_t *nsec3_previous;
			const zone_node_t *nsec3_node;

			if (zone_contents_find_nsec3_for_name(zone,
			                                      node->owner,
			                                      &nsec3_node,
			                                      &nsec3_previous) != 0) {
				err_handler_handle_error(handler, zone, node,
				                         ZC_ERR_NSEC3_NOT_FOUND, NULL);
				return KNOT_EOK;
			}

			if (nsec3_node == NULL) {
				/* Probably should not ever happen */
				return KNOT_ERROR;
			}

			assert(nsec3_previous);

			const knot_rdataset_t *previous_rrs =
				node_rdataset(nsec3_previous, KNOT_RRTYPE_NSEC3);

			assert(previous_rrs);

			/* check for Opt-Out flag */
			uint8_t flags =
				knot_nsec3_flags(previous_rrs, 0);
			uint8_t opt_out_mask = 1;

			if (!(flags & opt_out_mask)) {
				err_handler_handle_error(handler, zone, node,
					ZC_ERR_NSEC3_UNSECURED_DELEGATION_OPT,
				                         NULL);
				/* We cannot continue from here. */
				return KNOT_EOK;
			}
		}
	}

	const knot_rdataset_t *nsec3_rrs = node_rdataset(nsec3_node,
	                                            KNOT_RRTYPE_NSEC3);
	if (nsec3_rrs == NULL) {
		err_handler_handle_error(handler, zone, node,
		                         ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
		return KNOT_EOK;
	}

	const knot_rdata_t *nsec3_rr = knot_rdataset_at(nsec3_rrs, 0);
	const knot_rdataset_t *soa_rrs = node_rdataset(zone->apex, KNOT_RRTYPE_SOA);
	assert(soa_rrs);
	uint32_t minimum_ttl = knot_soa_minimum(soa_rrs);
	if (knot_rdata_ttl(nsec3_rr) != minimum_ttl) {
		err_handler_handle_error(handler, zone, node,
		                         ZC_ERR_NSEC3_RDATA_TTL, NULL);
	}

	/* Result is a dname, it can't be larger */
	const zone_node_t *apex = zone->apex;
	uint8_t *next_dname_str = NULL;
	uint8_t next_dname_size = 0;
	knot_nsec3_next_hashed(nsec3_rrs, 0, &next_dname_str,
	                           &next_dname_size);
	knot_dname_t *next_dname = knot_nsec3_hash_to_dname(next_dname_str,
	                                                    next_dname_size,
	                                                    apex->owner);
	if (next_dname == NULL) {
		return KNOT_ERROR;
	}

	if (zone_contents_find_nsec3_node(zone, next_dname) == NULL) {
		err_handler_handle_error(handler, zone, node,
					 ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
	}

	knot_dname_free(&next_dname, NULL);

	size_t arr_size;
	uint16_t *array = NULL;
	/* TODO only works for one NSEC3 RR. */
	int ret = rdata_nsec_to_type_array(nsec3_rrs,
	                                   KNOT_RRTYPE_NSEC3, 0,
	                                   &array, &arr_size);
	if (ret != KNOT_EOK) {
		return ret;
	}

	uint16_t type = 0;
	for (int j = 0; j < arr_size; j++) {
		/* test for each type's presence */
		type = array[j];
		if (type == KNOT_RRTYPE_RRSIG) {
			continue;
		}

		if (!node_rrtype_exists(node, type)) {
			err_handler_handle_error(handler, zone, node,
			                         ZC_ERR_NSEC3_RDATA_BITMAP,
			                         NULL);
		}
	}

	/* Check that the node only contains NSEC3 and RRSIG. */
	for (int i = 0; i < nsec3_node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(nsec3_node, i);
		uint16_t type = rrset.type;
		if (!(type == KNOT_RRTYPE_NSEC3 ||
		    type == KNOT_RRTYPE_RRSIG)) {
			err_handler_handle_error(handler, zone, nsec3_node,
			                         ZC_ERR_NSEC3_EXTRA_RECORD,
			                         NULL);
		}
	}

	free(array);

	return KNOT_EOK;
}

static int sem_check_node_mandatory(const zone_contents_t *zone,
                                    const zone_node_t *node,
                                    err_handler_t *handler, bool *fatal_error)
{
	const knot_rdataset_t *cname_rrs = node_rdataset(node, KNOT_RRTYPE_CNAME);
	if (cname_rrs) {
		if (node->rrset_count != 1) {
			/* With DNSSEC node can contain RRSIGs or NSEC */
			if (!(node_rrtype_exists(node, KNOT_RRTYPE_NSEC) ||
			      node_rrtype_exists(node, KNOT_RRTYPE_RRSIG)) ||
			    node->rrset_count > 3) {
				*fatal_error = true;
				err_handler_handle_error(handler, zone, node,
				ZC_ERR_CNAME_EXTRA_RECORDS_DNSSEC, NULL);
			}
		}

		if (cname_rrs->rr_count != 1) {
			*fatal_error = true;
			err_handler_handle_error(handler, zone, node,
			                         ZC_ERR_CNAME_MULTIPLE, NULL);
		}
	}

	const knot_rdataset_t *dname_rrs = node_rdataset(node, KNOT_RRTYPE_DNAME);
	if (dname_rrs) {
		if (cname_rrs) {
			*fatal_error = true;
			err_handler_handle_error(handler, zone, node,
			                         ZC_ERR_CNAME_EXTRA_RECORDS,
			                         NULL);
		}

		if (node->children != 0) {
			*fatal_error = true;
			err_handler_handle_error(handler, zone, node,
			                         ZC_ERR_DNAME_CHILDREN,
			                         "error triggered by parent node");
		}
	}

	if (node->parent && node_rrtype_exists(node->parent, KNOT_RRTYPE_DNAME)) {
		*fatal_error = true;
		err_handler_handle_error(handler, zone, node,
		                         ZC_ERR_DNAME_CHILDREN,
		                         "error triggered by child node");
	}

	return KNOT_EOK;
}

static int sem_check_node_optional(const zone_contents_t *zone,
                                   const zone_node_t *node,
                                   err_handler_t *handler)
{
	if (!((node->flags & NODE_FLAGS_DELEG) || zone->apex ==
	                node)) {
		return KNOT_EOK;
	}
	const knot_rdataset_t *ns_rrs = node_rdataset(node, KNOT_RRTYPE_NS);
	if (ns_rrs == NULL) {
		err_handler_handle_error(handler, zone, node,
		                         ZC_ERR_MISSING_NS_DEL_POINT,
		                         NULL);
		return KNOT_EOK;
	}

	for (int i = 0; i < ns_rrs->rr_count; ++i) {
		const knot_dname_t *ns_dname =
			knot_ns_name(ns_rrs, i);

		const zone_node_t *glue_node = zone_contents_find_node(zone, ns_dname);

		if (knot_dname_is_sub(ns_dname, zone->apex->owner)) {

			if (glue_node == NULL) {
				/* Try wildcard ([1]* + suffix). */
				knot_dname_t wildcard[KNOT_DNAME_MAXLEN];
				memcpy(wildcard, "\x1""*", 2);
				knot_dname_to_wire(wildcard + 2,
				                   knot_wire_next_label(ns_dname, NULL),
				                   sizeof(wildcard) - 2);

				const zone_node_t *wildcard_node =
				                zone_contents_find_node(zone, wildcard);
				if (wildcard_node == NULL) {
					err_handler_handle_error(handler, zone, node,
							 ZC_ERR_GLUE_NODE,
							NULL );
					// Cannot continue
					return KNOT_EOK;
				}
				glue_node = wildcard_node;
			}
			if (!node_rrtype_exists(glue_node, KNOT_RRTYPE_A) &&
			    !node_rrtype_exists(glue_node, KNOT_RRTYPE_AAAA)) {
				err_handler_handle_error(handler, zone, node,
				                         ZC_ERR_GLUE_RECORD,
				                         NULL);
			}
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Run semantic checks for node without DNSSEC-related types.
 *
 * \param zone Current zone.
 * \param node Node to be checked.
 * \param handler Error handler.
 * \param only_mandatory Mandatory/optional test switch
 * \param fatal_error Set to true if error is blocking zone from being loaded
 *
 * \retval KNOT_EOK if no error was found.
 *
 * \return Appropriate error code if error was found.
 */
int sem_check_node_plain(const zone_contents_t *zone,
                         const zone_node_t *node,
                         err_handler_t *handler,
                         bool only_mandatory,
                         bool *fatal_error)
{
	assert(handler);
	*fatal_error = false;
	if (only_mandatory) {
		/* Check CNAME and DNAME, else no-op. */
		return sem_check_node_mandatory(zone, node, handler,
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
static int semantic_checks_dnssec(zone_contents_t *zone,
                                  zone_node_t *node,
                                  zone_node_t **last_node,
                                  err_handler_t *handler,
                                  char nsec3)
{
	assert(handler);
	assert(node);
	bool auth = !(node->flags & NODE_FLAGS_NONAUTH);
	bool deleg = (node->flags & NODE_FLAGS_DELEG);
	short rrset_count = node->rrset_count;
	knot_rrset_t dnskey_rrset = node_rrset(zone->apex, KNOT_RRTYPE_DNSKEY);

	int ret = KNOT_EOK;

	for (int i = 0; i < rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		if (auth && !deleg && rrset.type != KNOT_RRTYPE_RRSIG &&
		    (ret = check_rrsig_in_rrset(handler, zone, node,
		                                &rrset, &dnskey_rrset)) != 0) {
			err_handler_handle_error(handler, zone, node, ret, NULL);
		}

		if (!nsec3 && auth) {
			/* check for NSEC record */
			const knot_rdataset_t *nsec_rrs =
				node_rdataset(node, KNOT_RRTYPE_NSEC);
			if (nsec_rrs == NULL) {
				err_handler_handle_error(handler, zone, node,
				                         ZC_ERR_NO_NSEC, NULL);
				return KNOT_EOK;
			}

			/* check NSEC/NSEC3 bitmap */
			size_t count;
			uint16_t *array = NULL;
			int ret = rdata_nsec_to_type_array(nsec_rrs,
			                                   KNOT_RRTYPE_NSEC,
			                                   0,
			                                   &array,
			                                   &count);
			if (ret != KNOT_EOK) {
				return ret;
			}

			uint16_t type = 0;
			for (int j = 0; j < count; j++) {
				/* test for each type's presence */
				type = array[j];
				if (type == KNOT_RRTYPE_RRSIG) {
					continue;
				}
				if (!node_rrtype_exists(node, type)) {
					err_handler_handle_error(handler,
					                         zone, node,
					                         ZC_ERR_NSEC_RDATA_BITMAP,
					                         NULL);
				}
			}
			free(array);
			/* Test that only one record is in the NSEC RRSet */
			if (nsec_rrs->rr_count != 1) {
				err_handler_handle_error(handler,
				                         zone, node,
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
			const knot_dname_t *next_domain =
				knot_nsec_next(nsec_rrs);

			if (zone_contents_find_node(zone, next_domain) == NULL) {
				err_handler_handle_error(handler, zone, node,
				                         ZC_ERR_NSEC_RDATA_CHAIN,
				                         NULL);
			}

			if (knot_dname_is_equal(next_domain, zone->apex->owner)) {
				/* saving the last node */
				*last_node = node;

			}
		} else if (nsec3 && (auth || deleg)) { /* nsec3 */
			int ret = check_nsec3_node_in_zone(zone, node,
			                                   handler);
			if (ret != KNOT_EOK) {
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
static int do_checks_in_tree(zone_node_t *node, void *data)
{
	arg_t *args = (arg_t *)data;

	zone_contents_t *zone = (zone_contents_t *)args->arg1;

	zone_node_t **last_node = (zone_node_t **)args->arg5;

	err_handler_t *handler = (err_handler_t *)args->arg6;

	char do_checks = *((char *)(args->arg3));

	if (do_checks) {
		sem_check_node_plain(zone, node, handler, false,
		                      (bool *)args->arg7);
	} else {
		assert(handler);
		/* All CNAME/DNAME checks are mandatory. */
		handler->options.log_cname = 1;
		sem_check_node_plain(zone, node, handler, true,
		                      (bool *)args->arg7);
		return KNOT_EOK;
	}

	if (do_checks == SEM_CHECK_NSEC || do_checks == SEM_CHECK_NSEC3) {
		semantic_checks_dnssec(zone, node, last_node,
				       handler, do_checks == SEM_CHECK_NSEC3);
	}

	return KNOT_EOK;
}

int zone_do_sem_checks(zone_contents_t *zone, int do_checks,
                       err_handler_t *handler, zone_node_t *first_nsec3_node,
                       zone_node_t *last_nsec3_node)
{
	if (!zone || !handler) {
		return KNOT_EINVAL;
	}
	zone_node_t *last_node = NULL;
	arg_t arguments;
	arguments.arg1 = zone;
	arguments.arg3 = &do_checks;
	arguments.arg4 = NULL; // UNUSED
	arguments.arg5 = &last_node;
	arguments.arg6 = handler;
	int fatal_error = 0;
	arguments.arg7 = (void *)&fatal_error;

	int ret = zone_contents_tree_apply_inorder(zone,
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
                               zone_contents_t *zone,
                               zone_node_t *last_node,
                               const zone_node_t *first_nsec3_node,
                               const zone_node_t *last_nsec3_node,
                               char do_checks)
{
	if (do_checks == SEM_CHECK_NSEC3) {
		/* Each NSEC3 node should only contain one RRSET. */
		if (last_nsec3_node == NULL || first_nsec3_node == NULL) {
			return;
		}
		const knot_rdataset_t *nsec3_rrs =
			node_rdataset(last_nsec3_node, KNOT_RRTYPE_NSEC3);
		if (nsec3_rrs == NULL) {
			err_handler_handle_error(handler, zone, last_nsec3_node,
						 ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
			return;
		}

		/* Result is a dname, it can't be larger */
		const zone_node_t *apex = zone->apex;

		uint8_t *next_dname_str = NULL;
		uint8_t next_dname_size = 0;
		knot_nsec3_next_hashed(nsec3_rrs, 0, &next_dname_str,
		                           &next_dname_size);
		knot_dname_t *next_dname = knot_nsec3_hash_to_dname(next_dname_str,
		                                                    next_dname_size,
		                                                    apex->owner);
		if (next_dname == NULL) {
			log_zone_warning(zone->apex->owner, "semantic check, "
			                 "failed to create new dname");
			return;
		}

		/* Check it points somewhere first. */
		if (zone_contents_find_nsec3_node(zone, next_dname) == NULL) {
			err_handler_handle_error(handler, zone, last_nsec3_node,
						 ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
		} else {
			/* Compare with the actual first NSEC3 node. */
			if (!knot_dname_is_equal(first_nsec3_node->owner, next_dname)) {
				err_handler_handle_error(handler, zone, last_nsec3_node,
							 ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
			}
		}

		/* Directly discard. */
		knot_dname_free(&next_dname, NULL);

	} else if (do_checks == SEM_CHECK_NSEC) {
		if (last_node == NULL) {
			err_handler_handle_error(handler, zone, zone->apex,
				ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC, NULL);
				return;
		} else {
			const knot_rdataset_t *nsec_rrs =
				node_rdataset(last_node, KNOT_RRTYPE_NSEC);

			if (nsec_rrs == NULL) {
				err_handler_handle_error(handler, zone, last_node,
					 ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC, NULL);
				return;
			}

			const knot_dname_t *next_dname = knot_nsec_next(nsec_rrs);
			assert(next_dname);
			knot_dname_t *lowercase = knot_dname_copy(next_dname, NULL);
			if (lowercase == NULL) {
				return;
			}
			knot_dname_to_lower(lowercase);

			if (knot_dname_cmp(lowercase, zone->apex->owner) != 0) {
				err_handler_handle_error(handler, zone, last_node,
					 ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC, NULL);
			}

			knot_dname_free(&lowercase, NULL);
		}
	}
}
