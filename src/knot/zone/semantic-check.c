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

const char *zonechecks_error_messages[(-ZC_ERR_UNKNOWN) + 1] = {
	[-ZC_ERR_MISSING_SOA] =
	"SOA record missing in zone",
	[-ZC_ERR_MISSING_NS_DEL_POINT] =
	"NS record missing in zone apex",
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
	"NSEC(3), wrong bitmap",
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

	[-ZC_ERR_GLUE_NODE] =
	"GLUE, node with glue record missing",
	[-ZC_ERR_GLUE_RECORD] =
	"GLUE, record with glue address missing",
};

typedef struct semchecks_data {
	zone_contents_t *zone;
	err_handler_t *handler;
	bool fatal_error;
	const zone_node_t *next_nsec;
	enum check_levels level;
} semchecks_data_t;

static void check_cname_multiple(const zone_node_t *node, semchecks_data_t *data);
static void check_dname(const zone_node_t *node, semchecks_data_t *data);
static void check_delegation(const zone_node_t *node, semchecks_data_t *data);
static void check_nsec(const zone_node_t *node, semchecks_data_t *data);
static void check_nsec3(const zone_node_t *node, semchecks_data_t *data);
static void check_nsec3_opt_out(const zone_node_t *node, semchecks_data_t *data);
static void check_rrsig(const zone_node_t *node, semchecks_data_t *data);
static void check_signed_rrsig(const zone_node_t *node, semchecks_data_t *data);
static void check_nsec_bitmap(const zone_node_t *node, semchecks_data_t *data);

struct check_function {
	void (*function)(const zone_node_t *, semchecks_data_t *);
	enum check_levels level;
};

const struct check_function check_functions[] = {
	{check_cname_multiple, SEM_CHECK_MANDATORY},
	{check_dname, SEM_CHECK_MANDATORY},
	{check_delegation, SEM_CHECK_OPTIONAL},
	{check_rrsig, SEM_CHECK_NSEC | SEM_CHECK_NSEC3},
	{check_signed_rrsig, SEM_CHECK_NSEC | SEM_CHECK_NSEC3},
	{check_nsec, SEM_CHECK_NSEC},
	{check_nsec3, SEM_CHECK_NSEC3},
	{check_nsec3_opt_out, SEM_CHECK_NSEC3},
	{check_nsec_bitmap, SEM_CHECK_NSEC | SEM_CHECK_NSEC3},
};

const int check_functions_len = sizeof(check_functions)/sizeof(struct check_function);

void err_handler_init(err_handler_t *h)
{
	memset(h, 0, sizeof(err_handler_t));
	init_list(&h->error_list);
}

void err_handler_deinit(err_handler_t *h)
{
	err_node_t *node, *next;
	WALK_LIST_DELSAFE(node, next, h->error_list) {
		free(node->data);
		free(node->name);
		free(node->zone_name);
		free(node);
	}
}

int err_handler_handle_error(err_handler_t *handler, const zone_contents_t *zone,
			     const zone_node_t *node, int error, const char *data)
{
	err_node_t * log = malloc(sizeof(err_node_t));
	if (log == NULL) {
		return KNOT_ENOMEM;
	}
	log->error = error;
	if (data != NULL) {
		log->data = strdup(data);
	} else {
		log->data = NULL;
	}

	log->name = knot_dname_to_str_alloc(node->owner);
	log->zone_name = knot_dname_to_str_alloc(zone->apex->owner);
	add_tail(&handler->error_list, (node_t*)log);
	handler->errors[-error]++;
	handler->error_count++;

	return KNOT_EOK;
}

void err_handler_log_errors(err_handler_t *handler)
{
	err_node_t *n;
	WALK_LIST(n, handler->error_list) {
		if (n->error > (int)ZC_ERR_GLUE_RECORD) {
			log_zone_str_warning(n->zone_name,
			                     "semantic check, unknown error");
			return;
		}

		const char *errmsg = zonechecks_error_messages[-n->error];
		log_zone_str_warning(n->zone_name,
		                     "semantic check, node '%s' (%s%s%s)",
		                     n->name ? n->name : "",
		                     errmsg ? errmsg : "unknown error",
		                     n->data ? " " : "",
		                     n->data ? n->data : "");
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

static void check_signed_rrsig(const zone_node_t *node, semchecks_data_t *data)
{
	/* signed rrsig - nonsense */
	if (node_rrtype_is_signed(node, KNOT_RRTYPE_RRSIG)) {
		err_handler_handle_error(data->handler, data->zone, node,
		                         ZC_ERR_RRSIG_SIGNED, NULL);
	}
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
		err_handler_handle_error(handler, zone, node,
		                         ZC_ERR_RRSIG_NO_RRSIG,
		                         info_str);
		return KNOT_EOK;
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

static void check_delegation(const zone_node_t *node, semchecks_data_t *data)
{
	if (!((node->flags & NODE_FLAGS_DELEG) || data->zone->apex == node)) {
		return;
	}
	const knot_rdataset_t *ns_rrs = node_rdataset(node, KNOT_RRTYPE_NS);
	if (ns_rrs == NULL) {
		err_handler_handle_error(data->handler, data->zone, node,
		                         ZC_ERR_MISSING_NS_DEL_POINT,
		                         NULL);
		return;
	}

	// check glue record for delegation
	for (int i = 0; i < ns_rrs->rr_count; ++i) {
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

			const zone_node_t *wildcard_node =
				zone_contents_find_node(data->zone, wildcard);
			if (wildcard_node == NULL) {
				err_handler_handle_error(
					data->handler, data->zone, node,
					ZC_ERR_GLUE_NODE, NULL);
				// Cannot continue
				return;
			}
			glue_node = wildcard_node;
		}
		if (!node_rrtype_exists(glue_node, KNOT_RRTYPE_A) &&
		    !node_rrtype_exists(glue_node, KNOT_RRTYPE_AAAA)) {
			err_handler_handle_error(data->handler, data->zone,
			                         node, ZC_ERR_GLUE_RECORD, NULL);
		}
	}
}

static void check_rrsig(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	if (node->flags & NODE_FLAGS_NONAUTH) {
		return;
	}

	bool deleg = node->flags & NODE_FLAGS_DELEG;

	knot_rrset_t dnskey_rrset = node_rrset(data->zone->apex, KNOT_RRTYPE_DNSKEY);
	int rrset_count = node->rrset_count;
	for (int i = 0; i < rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		if (rrset.type == KNOT_RRTYPE_RRSIG) {
			continue;
		}
		if (deleg && rrset.type != KNOT_RRTYPE_NSEC) {
			continue;
		}

		check_rrsig_in_rrset(data->handler, data->zone, node,
		                     &rrset, &dnskey_rrset);
	}
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

static void check_nsec_bitmap(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	if (node->flags & NODE_FLAGS_NONAUTH) {
		return;
	}

	knot_rdataset_t *nsec_rrs;

	if (data->level & SEM_CHECK_NSEC) {
		nsec_rrs = node_rdataset(node, KNOT_RRTYPE_NSEC);
	} else {
		if ( node->nsec3_node == NULL ) {
			return;
		}
		nsec_rrs = node_rdataset(node->nsec3_node, KNOT_RRTYPE_NSEC3);
	}
	if (nsec_rrs == NULL) {
		return;
	}

	// create NSEC bitmap from node
	dnssec_nsec_bitmap_t *node_bitmap = dnssec_nsec_bitmap_new();
	if (node_bitmap == NULL) {
		return ;
	}
	bitmap_add_all_node_rrsets(node_bitmap, node);

	uint16_t node_wire_size = dnssec_nsec_bitmap_size(node_bitmap);
	uint8_t *node_wire = malloc(node_wire_size);
	if (node_wire == NULL) {
		dnssec_nsec_bitmap_free(node_bitmap);
		return;
	}
	dnssec_nsec_bitmap_write(node_bitmap, node_wire);

	// get NSEC bitmap from NSEC node
	uint8_t *nsec_wire = NULL;
	uint16_t nsec_wire_size = 0;
	if (data->level & SEM_CHECK_NSEC) {
		knot_nsec_bitmap(nsec_rrs, &nsec_wire, &nsec_wire_size);
	} else {
		knot_nsec3_bitmap(nsec_rrs, 0, &nsec_wire, &nsec_wire_size);
	}

	if (node_wire_size != nsec_wire_size ||
	    memcmp(node_wire, nsec_wire, node_wire_size) != 0) {
		err_handler_handle_error(data->handler,
		                         data->zone, node,
		                         ZC_ERR_NSEC_RDATA_BITMAP,
		                         NULL);
	}
}

static void check_nsec(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	if (node->flags & NODE_FLAGS_NONAUTH) {
		return;
	}

	/* check for NSEC record */
	const knot_rdataset_t *nsec_rrs =
		node_rdataset(node, KNOT_RRTYPE_NSEC);
	if (nsec_rrs == NULL) {
		err_handler_handle_error(data->handler, data->zone, node,
		                         ZC_ERR_NO_NSEC, NULL);
		return;
	}



	/* Test that only one record is in the NSEC RRSet */
	if (nsec_rrs->rr_count != 1) {
		err_handler_handle_error(data->handler,
		                         data->zone, node,
		                         ZC_ERR_NSEC_RDATA_MULTIPLE,
		                         NULL);
	}

	if (data->next_nsec != node ) {
		err_handler_handle_error(data->handler, data->zone, node,
		                         ZC_ERR_NSEC_RDATA_CHAIN,
		                         NULL);
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
		err_handler_handle_error(data->handler, data->zone, node,
		                         ZC_ERR_NSEC_RDATA_CHAIN,
		                         NULL);
	}
}


static void check_nsec3_opt_out(const zone_node_t *node, semchecks_data_t *data)
{
	if (node->nsec3_node != NULL) {
		return;
	}
	// check for nodes without NSEC3

	/* I know it's probably not what RFCs say, but it will have to
	 * do for now. */
	if (node_rrtype_exists(node, KNOT_RRTYPE_DS)) {
		err_handler_handle_error(
				data->handler, data->zone, node,
				ZC_ERR_NSEC3_UNSECURED_DELEGATION, NULL);
		return;
	} else {
		/* Unsecured delegation, check whether it is part of
		 * opt-out span */
		const zone_node_t *nsec3_previous;
		const zone_node_t *nsec3_node;
		if (zone_contents_find_nsec3_for_name(data->zone,
		                                      node->owner,
		                                      &nsec3_node,
		                                      &nsec3_previous) != ZONE_NAME_NOT_FOUND) {
			err_handler_handle_error(data->handler,
			                         data->zone, node,
			                         ZC_ERR_NSEC3_NOT_FOUND,
			                         NULL);
			return;
		}
		assert(nsec3_previous);

		const knot_rdataset_t *previous_rrs =
			node_rdataset(nsec3_previous, KNOT_RRTYPE_NSEC3);

		assert(previous_rrs);

		/* check for Opt-Out flag */
		uint8_t flags = knot_nsec3_flags(previous_rrs, 0);
		uint8_t opt_out_mask = 1;

		if (flags & opt_out_mask) {
			// opt-out no need to check more
			return;
		} else {
			err_handler_handle_error(data->handler,
				data->zone, node,
				ZC_ERR_NSEC3_UNSECURED_DELEGATION_OPT,
				NULL);
			/* We cannot continue from here. */
			return;
		}
	}
}

/*!
 * \brief Run semantic checks for node with DNSSEC-related types.
 */
static void check_nsec3(const zone_node_t *node, semchecks_data_t *data)
{
	assert(node);
	bool auth = !(node->flags & NODE_FLAGS_NONAUTH);
	bool deleg = (node->flags & NODE_FLAGS_DELEG);

	if (!(auth || deleg)) {
		return;
	}

	if (node->nsec3_node == NULL) {
		return;
	}

	const zone_node_t *nsec3_node = node->nsec3_node;
	const knot_rdataset_t *nsec3_rrs = node_rdataset(nsec3_node,
	                                            KNOT_RRTYPE_NSEC3);
	if (nsec3_rrs == NULL) {
		err_handler_handle_error(data->handler, data->zone, node,
		                         ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
		return;
	}

	const knot_rdata_t *nsec3_rr = knot_rdataset_at(nsec3_rrs, 0);
	const knot_rdataset_t *soa_rrs = node_rdataset(data->zone->apex, KNOT_RRTYPE_SOA);
	assert(soa_rrs);
	uint32_t minimum_ttl = knot_soa_minimum(soa_rrs);
	if (knot_rdata_ttl(nsec3_rr) != minimum_ttl) {
		err_handler_handle_error(data->handler, data->zone, node,
		                         ZC_ERR_NSEC3_RDATA_TTL, NULL);
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
		return;
	}

	const zone_node_t *next_nsec3 =
		zone_contents_find_nsec3_node(data->zone, next_dname);
	knot_dname_free(&next_dname, NULL);

	if (next_nsec3 == NULL) {
		printf("XXX");
		err_handler_handle_error(data->handler, data->zone, node,
		                         ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
	} else if (next_nsec3->prev != nsec3_node) {
		printf("BBB");
		err_handler_handle_error(data->handler, data->zone, node,
		                         ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
	}

	/* Check that the node only contains NSEC3 and RRSIG. */
	for (int i = 0; i < nsec3_node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(nsec3_node, i);
		uint16_t type = rrset.type;
		if (!(type == KNOT_RRTYPE_NSEC3 ||
		    type == KNOT_RRTYPE_RRSIG)) {
			err_handler_handle_error(data->handler, data->zone, nsec3_node,
			                         ZC_ERR_NSEC3_EXTRA_RECORD,
			                         NULL);
		}
	}
}

static void check_cname_multiple(const zone_node_t *node, semchecks_data_t *data)
{
	const  knot_rdataset_t *cname_rrs = node_rdataset(node, KNOT_RRTYPE_CNAME);
	if (cname_rrs == NULL) {
		return;
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
		err_handler_handle_error(data->handler,
		data->zone, node,
		rrset_limit > 1 ?
		ZC_ERR_CNAME_EXTRA_RECORDS_DNSSEC :
		ZC_ERR_CNAME_EXTRA_RECORDS, NULL);
	}
	if (cname_rrs->rr_count != 1) {
		data->fatal_error = true;
		err_handler_handle_error(data->handler, data->zone, node,
		                         ZC_ERR_CNAME_MULTIPLE, NULL);
	}
}

static void check_dname(const zone_node_t *node, semchecks_data_t *data)
{
	const knot_rdataset_t *dname_rrs = node_rdataset(node, KNOT_RRTYPE_DNAME);

	if (dname_rrs != NULL && node->children != 0) {
		data->fatal_error = true;
		err_handler_handle_error(data->handler, data->zone, node,
		                         ZC_ERR_DNAME_CHILDREN,
		                         "error triggered by parent node");
	}


	if (node->parent != NULL && node_rrtype_exists(node->parent, KNOT_RRTYPE_DNAME)) {
		data->fatal_error = true;
		err_handler_handle_error(data->handler, data->zone, node,
		                         ZC_ERR_DNAME_CHILDREN,
		                         "error triggered by child node");
	}
}

static void check_nsec3_cyclic(semchecks_data_t *data,
                       const zone_node_t *first_nsec3_node,
                       const zone_node_t *last_nsec3_node)
{
	/* Each NSEC3 node should only contain one RRSET. */
	if (last_nsec3_node == NULL || first_nsec3_node == NULL) {
		return;
	}
	const knot_rdataset_t *nsec3_rrs =
		node_rdataset(last_nsec3_node, KNOT_RRTYPE_NSEC3);
	if (nsec3_rrs == NULL) {
		err_handler_handle_error(data->handler, data->zone,
		                         last_nsec3_node,
		                         ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
		return;
	}

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
		log_zone_warning(data->zone->apex->owner, "semantic check, "
		                 "failed to create new dname");
		return;
	}

	/* Check it points somewhere first. */
	if (zone_contents_find_nsec3_node(data->zone, next_dname) == NULL) {
		err_handler_handle_error(data->handler, data->zone,
		                         last_nsec3_node,
		                         ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
	} else {
		/* Compare with the actual first NSEC3 node. */
		if (!knot_dname_is_equal(first_nsec3_node->owner, next_dname)) {
			err_handler_handle_error(data->handler, data->zone,
			                         last_nsec3_node,
			                         ZC_ERR_NSEC3_RDATA_CHAIN, NULL);
		}
	}

	/* Directly discard. */
	knot_dname_free(&next_dname, NULL);
}

static void check_nsec_cyclic(semchecks_data_t *data)
{
	if (data->next_nsec == NULL) {
		err_handler_handle_error(data->handler, data->zone,
		                         data->zone->apex,
		                         ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC, NULL);
		return;
	}

	if (!knot_dname_is_equal(data->next_nsec->owner, data->zone->apex->owner)) {
		err_handler_handle_error(data->handler, data->zone, data->next_nsec,
		                         ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC, NULL);
		return;
	}
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
	struct semchecks_data *s_data = (semchecks_data_t *)data;

	for (int i=0; i < check_functions_len; ++i) {
		if (check_functions[i].level & s_data->level) {
			check_functions[i].function(node, s_data);
		}
	}

	return KNOT_EOK;
}

int zone_do_sem_checks(zone_contents_t *zone, bool optional,
                       err_handler_t *handler)
{
	if (!zone || !handler) {
		return KNOT_EINVAL;
	}

	semchecks_data_t data;
	data.handler = handler;
	data.zone = zone;
	data.next_nsec = zone->apex;
	data.fatal_error = false;
	data.level = SEM_CHECK_MANDATORY;
	if (optional) {
		data.level |= SEM_CHECK_OPTIONAL;
		if (zone_contents_is_signed(zone)) {
			if (node_rrtype_exists(zone->apex, KNOT_RRTYPE_NSEC3PARAM)) {
				data.level |= SEM_CHECK_NSEC3;
			} else {
				data.level |= SEM_CHECK_NSEC;
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
	if (data.level & SEM_CHECK_NSEC) {
		check_nsec_cyclic(&data);
	}

	if (data.fatal_error) {
		return KNOT_ESEMCHECK;
	}

	return KNOT_EOK;
}
