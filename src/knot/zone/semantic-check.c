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
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-nsec.h"
#include "libknot/libknot.h"
#include "contrib/base32hex.h"
#include "contrib/mempattern.h"
#include "contrib/wire.h"
#include "knot/dnssec/nsec-chain.h"

static const char *zonechecks_error_messages[(-ZC_ERR_UNKNOWN) + 1] = {
	[-ZC_ERR_UNKNOWN] =
	"unknown error",

	[-ZC_ERR_MISSING_SOA] =
	"SOA record missing in zone",
	[-ZC_ERR_MISSING_NS_DEL_POINT] =
	"NS record missing in zone apex",

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
	"NSEC(3), wrong bitmap",
	[-ZC_ERR_NSEC_RDATA_MULTIPLE] =
	"NSEC, multiple records",
	[-ZC_ERR_NSEC_RDATA_CHAIN] =
	"NSEC, chain is not coherent",
	[-ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC] =
	"NSEC, chain is not cyclic",

	[-ZC_ERR_NSEC3_NOT_FOUND] =
	"NSEC3, failed to find NSEC3 record in the zone",
	[-ZC_ERR_NSEC3_INSECURE_DELEGATION_OPT] =
	"NSEC3, insecure delegation is not part of the opt-out span",
	[-ZC_ERR_NSEC3_RDATA_TTL] =
	"NSEC3, original TTL RDATA field is wrong",
	[-ZC_ERR_NSEC3_RDATA_CHAIN] =
	"NSEC3, chain is not coherent",
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

	[-ZC_ERR_GLUE_RECORD] =
	"GLUE, record with glue address missing",
};


const char* semantic_check_error_msg(int ecode)
{
	if (ecode < ZC_ERR_UNKNOWN || ecode > ZC_ERR_LAST) {
		ecode = ZC_ERR_UNKNOWN;
	}
	if (zonechecks_error_messages[-ecode] == NULL) {
		ecode = ZC_ERR_UNKNOWN;
	}
	return zonechecks_error_messages[-ecode];
}

enum check_levels {
	MANDATORY = 1 << 0,
	OPTIONAL =  1 << 1,
	NSEC =      1 << 2,
	NSEC3 =     1 << 3,
};

typedef struct semchecks_data {
	zone_contents_t *zone;
	err_handler_t *handler;
	bool fatal_error;
	const zone_node_t *next_nsec;
	enum check_levels level;
} semchecks_data_t;

static int check_cname_multiple(const zone_node_t *node, semchecks_data_t *data);
static int check_dname(const zone_node_t *node, semchecks_data_t *data);
static int check_delegation(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec3(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec3_opt_out(const zone_node_t *node, semchecks_data_t *data);
static int check_rrsig(const zone_node_t *node, semchecks_data_t *data);
static int check_signed_rrsig(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec_bitmap(const zone_node_t *node, semchecks_data_t *data);
static int check_nsec3_presence(const zone_node_t *node, semchecks_data_t *data);

struct check_function {
	int (*function)(const zone_node_t *, semchecks_data_t *);
	enum check_levels level;
};

/* List of function callbacks for defined check_level */
static const struct check_function CHECK_FUNCTIONS[] = {
	{check_cname_multiple, MANDATORY},
	{check_dname,          MANDATORY},
	{check_delegation,     OPTIONAL},
	{check_rrsig,          NSEC | NSEC3},
	{check_signed_rrsig,   NSEC | NSEC3},
	{check_nsec,           NSEC},
	{check_nsec3,          NSEC3},
	{check_nsec3_presence, NSEC3},
	{check_nsec3_opt_out,  NSEC3},
	{check_nsec_bitmap,    NSEC | NSEC3},
};

static const int CHECK_FUNCTIONS_LEN = sizeof(CHECK_FUNCTIONS)
                                     / sizeof(struct check_function);

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

	ret = KNOT_EOK;

	if (knot_rrsig_type_covered(rrsig, 0) != rrset->type) {
		ret = handler->cb(handler, zone, node,
		                  ZC_ERR_RRSIG_RDATA_TYPE_COVERED,
		                  info_str);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* label number at the 2nd index should be same as owner's */
	uint8_t labels_rdata = knot_rrsig_labels(rrsig, rr_pos);

	int tmp = knot_dname_labels(rrset->owner, NULL) - labels_rdata;

	if (tmp != 0) {
		/* if name has wildcard, label must not be included */
		if (!knot_dname_is_wildcard(rrset->owner)) {
			ret = handler->cb(handler, zone, node,
			                  ZC_ERR_RRSIG_RDATA_LABELS,
			                  info_str);
		} else {
			if (abs(tmp) != 1) {
				ret = handler->cb(handler, zone, node,
				                  ZC_ERR_RRSIG_RDATA_LABELS,
				                  info_str);
			}
		}

		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* check original TTL */
	uint32_t original_ttl = knot_rrsig_original_ttl(rrsig, rr_pos);

	uint16_t rr_count = rrset->rrs.rr_count;
	for (uint16_t i = 0; i < rr_count; ++i) {
		if (original_ttl != knot_rdata_ttl(knot_rdataset_at(&rrset->rrs, i))) {
			ret = handler->cb(handler, zone, node,
			                  ZC_ERR_RRSIG_RDATA_TTL,
			                  info_str);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}



	/* Check for expired signature. */
	if (knot_rrsig_sig_expiration(rrsig, rr_pos) < time(NULL)) {
		ret = handler->cb(handler, zone, node,
		                  ZC_ERR_RRSIG_RDATA_EXPIRATION,
		                  info_str);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* Check if DNSKEY exists. */
	if (knot_rrset_empty(dnskey_rrset)) {
		ret = handler->cb(handler, zone, node,
		                  ZC_ERR_RRSIG_NO_DNSKEY, info_str);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* signer's name is same as in the zone apex */
	knot_dname_t *signer = knot_dname_copy(knot_rrsig_signer_name(rrsig, rr_pos), NULL);

	/* dnskey is in the apex node */
	if (!knot_rrset_empty(dnskey_rrset) &&
	    !knot_dname_is_equal(signer, dnskey_rrset->owner)) {
		ret = handler->cb(handler, zone, node,
		                  ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER,
		                  info_str);

	}

	knot_dname_free(&signer, NULL);

	if (ret != KNOT_EOK) {
		return ret;
	}

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
			ret = handler->cb(handler, zone, node,
			                  ZC_ERR_RRSIG_RDATA_SIGNED_WRONG,
			                  "DNSKEY RDATA not matching");
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	if (!match) {
		ret = handler->cb(handler, zone, node, ZC_ERR_RRSIG_NO_DNSKEY, info_str);
	}

	return ret;
}

static int check_signed_rrsig(const zone_node_t *node, semchecks_data_t *data)
{
	/* signed rrsig - nonsense */
	if (node_rrtype_is_signed(node, KNOT_RRTYPE_RRSIG)) {
		return data->handler->cb(data->handler, data->zone, node,
		                         ZC_ERR_RRSIG_SIGNED, NULL);
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
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		return ret;
	}

	if (ret == KNOT_ENOENT) {
		return handler->cb(handler, zone, node,
		                   ZC_ERR_RRSIG_NO_RRSIG,
		                   info_str);
	}

	const knot_rdata_t *sig_rr = knot_rdataset_at(&rrsigs, 0);
	if (knot_rdata_ttl(knot_rdataset_at(&rrset->rrs, 0)) != knot_rdata_ttl(sig_rr)) {
		ret = handler->cb(handler, zone, node, ZC_ERR_RRSIG_TTL, info_str);
	}

	for (uint16_t i = 0; ret == KNOT_EOK && i < (&rrsigs)->rr_count; ++i) {
		ret = check_rrsig_rdata(handler, zone, node, &rrsigs, i,
		                        rrset, dnskey_rrset);
	}

	knot_rdataset_clear(&rrsigs, NULL);
	return ret;
}

/*!
 * \brief Check if glue record for delegation is present.
 *
 * Also check if there is NS record in the zone.
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_delegation(const zone_node_t *node, semchecks_data_t *data)
{
	if (!((node->flags & NODE_FLAGS_DELEG) || data->zone->apex == node)) {
		return KNOT_EOK;
	}
	const knot_rdataset_t *ns_rrs = node_rdataset(node, KNOT_RRTYPE_NS);
	if (ns_rrs == NULL) {
		return data->handler->cb(data->handler, data->zone, node,
		                         ZC_ERR_MISSING_NS_DEL_POINT, NULL);
	}

	int ret = KNOT_EOK;

	// check glue record for delegation
	for (int i = 0; ret == KNOT_EOK && i < ns_rrs->rr_count; ++i) {
		const knot_dname_t *ns_dname = knot_ns_name(ns_rrs, i);
		if (!knot_dname_is_sub(ns_dname, data->zone->apex->owner)) {
			continue;
		}

		const zone_node_t *glue_node =
			zone_contents_find_node(data->zone, ns_dname);

		if (glue_node == NULL) {
			/* Try wildcard ([1]* + suffix). */
			knot_dname_t wildcard[KNOT_DNAME_MAXLEN];
			memcpy(wildcard, "\x1""*", 2);
			knot_dname_to_wire(wildcard + 2,
			                   knot_wire_next_label(ns_dname, NULL),
			                   sizeof(wildcard) - 2);
			glue_node = zone_contents_find_node(data->zone, wildcard);
		}
		if (!node_rrtype_exists(glue_node, KNOT_RRTYPE_A) &&
		    !node_rrtype_exists(glue_node, KNOT_RRTYPE_AAAA)) {
			ret = data->handler->cb(data->handler, data->zone,
			                        node, ZC_ERR_GLUE_RECORD, NULL /* for node 'ns.example.com' */);
		}
	}
	return ret;
}

/*!
 * \brief Run all semantic check related to RRSIG record
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_rrsig(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	if (node->flags & NODE_FLAGS_NONAUTH) {
		return KNOT_EOK;
	}

	bool deleg = node->flags & NODE_FLAGS_DELEG;

	int ret = KNOT_EOK;

	knot_rrset_t dnskey_rrset = node_rrset(data->zone->apex, KNOT_RRTYPE_DNSKEY);
	int rrset_count = node->rrset_count;
	for (int i = 0; ret == KNOT_EOK && i < rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		if (rrset.type == KNOT_RRTYPE_RRSIG) {
			continue;
		}
		if (deleg && rrset.type != KNOT_RRTYPE_NSEC &&
		    rrset.type != KNOT_RRTYPE_DS ) {
			continue;
		}

		ret = check_rrsig_in_rrset(data->handler, data->zone, node,
		                           &rrset, &dnskey_rrset);
	}
	return ret;
}

/*!
 * \brief Add all RR types from a node into the bitmap.
 */
inline static void bitmap_add_all_node_rrsets(dnssec_nsec_bitmap_t *bitmap,
                                              const zone_node_t *node)
{
	bool deleg = node->flags && NODE_FLAGS_DELEG;
	for (int i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rr = node_rrset_at(node, i);
		if (deleg && (rr.type != KNOT_RRTYPE_NS &&
		              rr.type != KNOT_RRTYPE_DS &&
			      rr.type != KNOT_RRTYPE_NSEC &&
			      rr.type != KNOT_RRTYPE_RRSIG)) {
			continue;
		}
		dnssec_nsec_bitmap_add(bitmap, rr.type);
	}
}

/*!
 * \brief Check NSEC and NSEC3 type bitmap
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec_bitmap(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	if (node->flags & NODE_FLAGS_NONAUTH) {
		return KNOT_EOK;
	}

	knot_rdataset_t *nsec_rrs;

	if (data->level & NSEC) {
		nsec_rrs = node_rdataset(node, KNOT_RRTYPE_NSEC);
	} else {
		if ( node->nsec3_node == NULL ) {
			return KNOT_EOK;
		}
		nsec_rrs = node_rdataset(node->nsec3_node, KNOT_RRTYPE_NSEC3);
	}
	if (nsec_rrs == NULL) {
		return KNOT_EOK;
	}

	// create NSEC bitmap from node
	dnssec_nsec_bitmap_t *node_bitmap = dnssec_nsec_bitmap_new();
	if (node_bitmap == NULL) {
		return KNOT_ENOMEM;
	}
	bitmap_add_all_node_rrsets(node_bitmap, node);

	uint16_t node_wire_size = dnssec_nsec_bitmap_size(node_bitmap);
	uint8_t *node_wire = malloc(node_wire_size);
	if (node_wire == NULL) {
		dnssec_nsec_bitmap_free(node_bitmap);
		return KNOT_ENOMEM;
	}
	dnssec_nsec_bitmap_write(node_bitmap, node_wire);

	// get NSEC bitmap from NSEC node
	uint8_t *nsec_wire = NULL;
	uint16_t nsec_wire_size = 0;
	if (data->level & NSEC) {
		knot_nsec_bitmap(nsec_rrs, &nsec_wire, &nsec_wire_size);
	} else {
		knot_nsec3_bitmap(nsec_rrs, 0, &nsec_wire, &nsec_wire_size);
	}

	int ret = KNOT_EOK;

	if (node_wire_size != nsec_wire_size ||
	    memcmp(node_wire, nsec_wire, node_wire_size) != 0) {
		ret = data->handler->cb(data->handler,
		                        data->zone, node,
		                        ZC_ERR_NSEC_RDATA_BITMAP,
		                        NULL);
	}

	free(node_wire);
	dnssec_nsec_bitmap_free(node_bitmap);
	return ret;
}

/*!
 * \brief Run NSEC related semantic checks
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	if (node->flags & NODE_FLAGS_NONAUTH) {
		return KNOT_EOK;
	}

	/* check for NSEC record */
	const knot_rdataset_t *nsec_rrs = node_rdataset(node, KNOT_RRTYPE_NSEC);
	if (nsec_rrs == NULL) {
		return data->handler->cb(data->handler, data->zone, node,
		                         ZC_ERR_NO_NSEC, NULL);
	}

	int ret = KNOT_EOK;

	/* Test that only one record is in the NSEC RRSet */
	if (nsec_rrs->rr_count != 1) {
		ret = data->handler->cb(data->handler,
		                        data->zone, node,
		                        ZC_ERR_NSEC_RDATA_MULTIPLE,
		                        NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (data->next_nsec != node) {
		ret = data->handler->cb(data->handler, data->zone, node,
		                        ZC_ERR_NSEC_RDATA_CHAIN,
		                        NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/*
	 * Test that NSEC chain is coherent.
	 * We have already checked that every
	 * authoritative node contains NSEC record
	 * so checking should only be matter of testing
	 * the next link in each node.
	 */
	const knot_dname_t *next_domain = knot_nsec_next(nsec_rrs);

	data->next_nsec = zone_contents_find_node(data->zone, next_domain);

	if (data->next_nsec == NULL) {
		ret = data->handler->cb(data->handler, data->zone, node,
		                        ZC_ERR_NSEC_RDATA_CHAIN,
		                        NULL);
	}

	return ret;
}

/*!
 * \brief Check if node has NSEC3 node.
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec3_presence(const zone_node_t *node, semchecks_data_t *data)
{
	bool auth = (node->flags & NODE_FLAGS_NONAUTH) == 0;
	bool deleg = (node->flags & NODE_FLAGS_DELEG) != 0;

	if ((deleg && node_rrtype_exists(node, KNOT_RRTYPE_DS)) || (auth && !deleg)) {
		if(node->nsec3_node == NULL) {
			return data->handler->cb(data->handler, data->zone, node,
		                                 ZC_ERR_NSEC3_NOT_FOUND, NULL);
		}
	}
	return KNOT_EOK;
}

/*!
 * \brief Check NSEC3 opt out.
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec3_opt_out(const zone_node_t *node, semchecks_data_t *data)
{
	if (!(node->nsec3_node == NULL && node->flags & NODE_FLAGS_DELEG)) {
		return KNOT_EOK;
	}
	/* Insecure delegation, check whether it is part of opt-out span */

	const zone_node_t *nsec3_previous = NULL;
	const zone_node_t *nsec3_node;
	zone_contents_find_nsec3_for_name(data->zone, node->owner, &nsec3_node,
	                                  &nsec3_previous);

	if (nsec3_previous == NULL) {
		return data->handler->cb(data->handler, data->zone, node,
		                         ZC_ERR_NSEC3_NOT_FOUND, NULL);
	}

	const knot_rdataset_t *previous_rrs;
	previous_rrs = node_rdataset(nsec3_previous, KNOT_RRTYPE_NSEC3);

	assert(previous_rrs);

	/* check for Opt-Out flag */
	uint8_t flags = knot_nsec3_flags(previous_rrs, 0);
	uint8_t opt_out_mask = 1;

	if (!(flags & opt_out_mask)) {
		return data->handler->cb(data->handler, data->zone, node,
		                         ZC_ERR_NSEC3_INSECURE_DELEGATION_OPT,
		                         NULL);
	}
	return KNOT_EOK;
}

/*!
 * \brief Run checks related to NSEC3.
 *
 * Check NSEC3 node for given node.
 * Check if NSEC3 chain is coherent and cyclic.
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_nsec3(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	bool auth = (node->flags & NODE_FLAGS_NONAUTH) == 0;
	bool deleg = (node->flags & NODE_FLAGS_DELEG) != 0;
	int ret = KNOT_EOK;

	if (!auth && !deleg) {
		return KNOT_EOK;
	}

	if (node->nsec3_node == NULL) {
		return KNOT_EOK;
	}

	const zone_node_t *nsec3_node = node->nsec3_node;
	const knot_rdataset_t *nsec3_rrs = node_rdataset(nsec3_node,
	                                            KNOT_RRTYPE_NSEC3);
	if (nsec3_rrs == NULL) {
		return data->handler->cb(data->handler, data->zone, node,
		                         ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
	}

	const knot_rdata_t *nsec3_rr = knot_rdataset_at(nsec3_rrs, 0);
	const knot_rdataset_t *soa_rrs = node_rdataset(data->zone->apex, KNOT_RRTYPE_SOA);
	assert(soa_rrs);
	uint32_t minimum_ttl = knot_soa_minimum(soa_rrs);
	if (knot_rdata_ttl(nsec3_rr) != minimum_ttl) {
		ret = data->handler->cb(data->handler, data->zone, node,
		                        ZC_ERR_NSEC3_RDATA_TTL, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* Get next nsec3 node */
	/* Result is a dname, it can't be larger */
	const zone_node_t *apex = data->zone->apex;
	uint8_t *next_dname_str = NULL;
	uint8_t next_dname_size = 0;
	knot_nsec3_next_hashed(nsec3_rrs, 0, &next_dname_str,
	                           &next_dname_size);
	knot_dname_t *next_dname = knot_nsec3_hash_to_dname(next_dname_str,
	                                                    next_dname_size,
	                                                    apex->owner);
	if (next_dname == NULL) {
		return KNOT_ENOMEM;
	}

	const zone_node_t *next_nsec3 =
		zone_contents_find_nsec3_node(data->zone, next_dname);
	knot_dname_free(&next_dname, NULL);

	if (next_nsec3 == NULL) {
		ret = data->handler->cb(data->handler, data->zone, node,
		                        ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
	} else if (next_nsec3->prev != nsec3_node) {
		ret = data->handler->cb(data->handler, data->zone, node,
		                        ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
	}

	/* Check that the node only contains NSEC3 and RRSIG. */
	for (int i = 0; ret == KNOT_EOK && i < nsec3_node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(nsec3_node, i);
		uint16_t type = rrset.type;
		if (!(type == KNOT_RRTYPE_NSEC3 ||
		    type == KNOT_RRTYPE_RRSIG)) {
			ret = data->handler->cb(data->handler, data->zone, nsec3_node,
			                        ZC_ERR_NSEC3_EXTRA_RECORD, NULL);
		}
	}
	return ret;
}
/*!
 * \brief Check if CNAME record contains other records
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_cname_multiple(const zone_node_t *node, semchecks_data_t *data)
{
	const  knot_rdataset_t *cname_rrs = node_rdataset(node, KNOT_RRTYPE_CNAME);
	int ret = KNOT_EOK;
	if (cname_rrs == NULL) {
		return KNOT_EOK;
	}

	unsigned rrset_limit = 1;
	/* With DNSSEC node can contain RRSIGs or NSEC */
	if (node_rrtype_exists(node, KNOT_RRTYPE_NSEC)) {
		rrset_limit += 1;
	}
	if (node_rrtype_exists(node, KNOT_RRTYPE_RRSIG)) {
		rrset_limit += 1;
	}

	if (node->rrset_count > rrset_limit) {
		data->fatal_error = true;
		ret = data->handler->cb(data->handler, data->zone, node,
		                        rrset_limit > 1 ?
		                        ZC_ERR_CNAME_EXTRA_RECORDS_DNSSEC :
		                        ZC_ERR_CNAME_EXTRA_RECORDS, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}
	if (cname_rrs->rr_count != 1) {
		data->fatal_error = true;
		ret = data->handler->cb(data->handler, data->zone, node,
		                        ZC_ERR_CNAME_MULTIPLE, NULL);
	}
	return ret;
}

/*!
 * \brief Check if DNAME record has children.
 *
 * \param node Node to check
 * \param data Semantic checks context data
 */
static int check_dname(const zone_node_t *node, semchecks_data_t *data)
{
	const knot_rdataset_t *dname_rrs = node_rdataset(node, KNOT_RRTYPE_DNAME);
	int ret = KNOT_EOK;

	if (dname_rrs != NULL && node->children != 0) {
		data->fatal_error = true;
		ret = data->handler->cb(data->handler, data->zone, node,
		                        ZC_ERR_DNAME_CHILDREN,
		                        "error triggered by parent node");
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (node->parent != NULL && node_rrtype_exists(node->parent, KNOT_RRTYPE_DNAME)) {
		data->fatal_error = true;
		ret = data->handler->cb(data->handler, data->zone, node,
		                        ZC_ERR_DNAME_CHILDREN,
		                        "error triggered by child node");
	}
	return ret;
}

/*!
 * \brief Check that NSEC chain is cyclic.
 *
 * Run only once per zone. Check that last NSEC node points to first one.
 * \param data Semantic checks context data
 */
static int check_nsec_cyclic(semchecks_data_t *data)
{
	if (data->next_nsec == NULL) {
		return data->handler->cb(data->handler, data->zone,
		                         data->zone->apex,
		                         ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC, NULL);
	}
	if (!knot_dname_is_equal(data->next_nsec->owner, data->zone->apex->owner)) {
		return data->handler->cb(data->handler, data->zone, data->next_nsec,
		                       ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC, NULL);
	}
	return KNOT_EOK;
}

/*!
 * \brief Call all semantic checks for each node.
 *
 * This function is called as callback from zone_contents_tree_apply_inorder.
 * Checks are functions from global const array check_functions.
 *
 * \param node Node to be checked
 * \param data Semantic checks context data
 */
static int do_checks_in_tree(zone_node_t *node, void *data)
{
	struct semchecks_data *s_data = (semchecks_data_t *)data;

	int ret = KNOT_EOK;

	for (int i = 0; ret == KNOT_EOK && i < CHECK_FUNCTIONS_LEN; ++i) {
		if (CHECK_FUNCTIONS[i].level & s_data->level) {
			ret = CHECK_FUNCTIONS[i].function(node, s_data);
		}
		if (ret != KNOT_EOK) {
		printf("**************** - %d\n", i);
		}

	}


	return ret;
}

int zone_do_sem_checks(zone_contents_t *zone, bool optional,
                       err_handler_t *handler)
{
	if (!zone || !handler) {
		return KNOT_EINVAL;
	}

	semchecks_data_t data = {
		.handler = handler,
		.zone = zone,
		.next_nsec = zone->apex,
		.fatal_error = false,
		.level = MANDATORY,
		};
	if (optional) {
		data.level |= OPTIONAL;
		if (zone_contents_is_signed(zone)) {
			if (node_rrtype_exists(zone->apex, KNOT_RRTYPE_NSEC3PARAM)) {
				data.level |= NSEC3;
			} else {
				data.level |= NSEC;
			}
		}
	}

	int ret = zone_contents_tree_apply_inorder(zone, do_checks_in_tree,
	                                           &data);

	if (ret != KNOT_EOK) {
		return ret;
	}
	if (data.fatal_error) {
		return KNOT_ESEMCHECK;
	}
	// check cyclic chain after every node was checked
	if (data.level & NSEC) {
		check_nsec_cyclic(&data);
	}

	if (data.fatal_error) {
		return KNOT_ESEMCHECK;
	}

	return KNOT_EOK;
}
