#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "knot/common.h"
#include "knot/zone/zone-dump.h"
#include "knot/other/error.h"
#include "libknot/libknot.h"
#include "common/base32hex.h"
#include "common/crc.h"

#include "semantic-check.h"

static char *error_messages[(-ZC_ERR_ALLOC) + 1] = {
	[-ZC_ERR_ALLOC] = "Memory allocation error!\n",

	[-ZC_ERR_MISSING_SOA] = "SOA record missing in zone!\n",

	[-ZC_ERR_RRSIG_RDATA_TYPE_COVERED] =
	"RRSIG: Type covered rdata field is wrong!\n",
	[-ZC_ERR_RRSIG_RDATA_TTL] =
	"RRSIG: TTL rdata field is wrong!\n",
	[-ZC_ERR_RRSIG_RDATA_LABELS] =
	"RRSIG: Labels rdata field is wrong!\n",
	[-ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER] =
	"RRSIG: Signer name is different than in DNSKEY!\n",
	[-ZC_ERR_RRSIG_RDATA_SIGNED_WRONG] =
	"RRSIG: Key error!\n",
	[-ZC_ERR_RRSIG_NO_RRSIG] =
	"RRSIG: No RRSIG!\n",
	[-ZC_ERR_RRSIG_SIGNED] =
	"RRSIG: Signed RRSIG!\n",
	[-ZC_ERR_RRSIG_OWNER] =
	"RRSIG: Owner name rdata field is wrong!\n",
	[-ZC_ERR_RRSIG_CLASS] =
	"RRSIG: Class is wrong!\n",
	[-ZC_ERR_RRSIG_TTL] =
	"RRSIG: TTL is wrong!\n",
	[-ZC_ERR_RRSIG_NOT_ALL] =
	"RRSIG: Not all RRs are signed!\n",

	[-ZC_ERR_NO_NSEC] =
	"NSEC: Missing NSEC record\n",
	[-ZC_ERR_NSEC_RDATA_BITMAP] =
	"NSEC: Wrong NSEC bitmap!\n",
	[-ZC_ERR_NSEC_RDATA_MULTIPLE] =
	"NSEC: Multiple NSEC records!\n",
	[-ZC_ERR_NSEC_RDATA_CHAIN] =
	"NSEC: NSEC chain is not coherent!\n",
	[-ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC] =
	"NSEC: NSEC chain is not cyclic!\n",

	[-ZC_ERR_NSEC3_UNSECURED_DELEGATION] =
	"NSEC3: Zone contains unsecured delegation!\n",
	[-ZC_ERR_NSEC3_NOT_FOUND] =
	"NSEC3: Could not find previous NSEC3 record in the zone!\n",
	[-ZC_ERR_NSEC3_UNSECURED_DELEGATION_OPT] =
	"NSEC3: Unsecured delegation is not part "
	"of the Opt-Out span!\n",
	[-ZC_ERR_NSEC3_RDATA_TTL] =
	"NSEC3: Original TTL rdata field is wrong!\n",
	[-ZC_ERR_NSEC3_RDATA_CHAIN] =
	"NSEC3: NSEC3 chain is not coherent!\n",
	[-ZC_ERR_NSEC3_RDATA_BITMAP] =
	"NSEC3: NSEC3 bitmap error!\n",

	[-ZC_ERR_CNAME_CYCLE] =
	"CNAME: CNAME cycle!\n",
	[-ZC_ERR_DNAME_CYCLE] =
	"CNAME: DNAME cycle!\n",
	[-ZC_ERR_CNAME_EXTRA_RECORDS] =
	"CNAME: Node with CNAME record has other records!\n",
	[-ZC_ERR_DNAME_CHILDREN] =
	"DNAME: Node with DNAME record has children!\n",
	[-ZC_ERR_CNAME_EXTRA_RECORDS_DNSSEC] =
	"CNAME: Node with CNAME record has other "
	"records than RRSIG and NSEC/NSEC3!\n",
	[-ZC_ERR_CNAME_MULTIPLE] = "CNAME: Multiple CNAME records!\n",
	[-ZC_ERR_DNAME_MULTIPLE] = "DNAME: Multiple DNAME records!\n",
	[-ZC_ERR_CNAME_WILDCARD_SELF] = "CNAME wildcard "
				  "pointing to itself!\n",
	[-ZC_ERR_DNAME_WILDCARD_SELF] = "DNAME wildcard "
				  "pointing to itself!\n",

	/* ^
	   | Important errors (to be logged on first occurence and counted) */


	/* Below are errors of lesser importance, to be counted unless
	   specified otherwise */

	[-ZC_ERR_GLUE_NODE] =
	"GLUE: Node with Glue record missing!\n",
	[-ZC_ERR_GLUE_RECORD] =
	"GLUE: Record with Glue address missing\n",
};

static const uint MAX_CNAME_CYCLE_DEPTH = 15;

err_handler_t *handler_new(char log_cname, char log_glue,
				  char log_rrsigs, char log_nsec,
				  char log_nsec3)
{
	err_handler_t *handler = malloc(sizeof(err_handler_t));
	CHECK_ALLOC_LOG(handler, NULL);

	/* It should be initialized, but to be safe */
	memset(handler->errors, 0, sizeof(uint) * (-ZC_ERR_ALLOC + 1));
	
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
				int error)
{
	if (error > (int)ZC_ERR_GLUE_RECORD) {
		fprintf(stderr, "Unknown error.\n");
		return;
	}
	
	if (node != NULL) {
		handler->error_count++;
		char *name =
			knot_dname_to_str(knot_node_owner(node));
		fprintf(stderr, "Semantic warning in node: %s: ", name);
		fprintf(stderr, "%s", error_messages[-error]);
		free(name);
	} else {
		fprintf(stderr, "Total number of warnings is: %d for error: %s",
			handler->errors[-error],
			error_messages[-error]);
	}
}

int err_handler_handle_error(err_handler_t *handler,
				    const knot_node_t *node,
				    int error)
{
	assert(handler && node);
	if ((error != 0) &&
	    (error > ZC_ERR_GLUE_GENERAL_ERROR)) {
		return KNOT_EBADARG;
	}

	/*!< \todo this is so wrong! This should not even return anything. */
	if (error == ZC_ERR_ALLOC || error == 0) {
		return KNOT_EBADARG;
	}

	/* missing SOA can only occur once, so there
	 * needn't to be an option for it */

	if ((error != 0) &&
	    (error < ZC_ERR_GENERIC_GENERAL_ERROR)) {
		/* The two errors before SOA were handled */
		log_error_from_node(handler, node, error);

	} else if ((error < ZC_ERR_RRSIG_GENERAL_ERROR) &&
		   ((handler->errors[-error] == 0) ||
		   (handler->options.log_rrsigs))) {

		log_error_from_node(handler, node, error);

	} else if ((error > ZC_ERR_RRSIG_GENERAL_ERROR) &&
		   (error < ZC_ERR_NSEC_GENERAL_ERROR) &&
		   ((handler->errors[-error] == 0) ||
		    (handler->options.log_nsec))) {

		log_error_from_node(handler, node, error);

	} else if ((error > ZC_ERR_NSEC_GENERAL_ERROR) &&
		   (error < ZC_ERR_NSEC3_GENERAL_ERROR) &&
		   ((handler->errors[-error] == 0) ||
		    (handler->options.log_nsec3))) {

		log_error_from_node(handler, node, error);

	} else if ((error > ZC_ERR_NSEC3_GENERAL_ERROR) &&
		   (error < ZC_ERR_CNAME_GENERAL_ERROR) &&
		   ((handler->errors[-error] == 0) ||
		    (handler->options.log_cname))) {

		log_error_from_node(handler, node, error);

	} else if ((error > ZC_ERR_CNAME_GENERAL_ERROR) &&
		   (error < ZC_ERR_GLUE_GENERAL_ERROR) &&
		    handler->options.log_glue) {

		log_error_from_node(handler, node, error);

	}

	handler->errors[-error]++;

	return KNOT_EOK;
}

void err_handler_log_all(err_handler_t *handler)
{
	if (handler == NULL) {
		return;
	}

	for (int i = ZC_ERR_ALLOC; i < ZC_ERR_GLUE_GENERAL_ERROR; i++) {
		if (handler->errors[-i] > 0) {
			log_error_from_node(handler, NULL, i);
		}
	}
}


/*!
 * \brief Semantic check - CNAME cycles. Uses constant value with maximum
 *        allowed CNAME chain depth.
 *
 * \param zone Zone containing the RRSet.
 * \param rrset RRSet to be tested.
 *
 * \retval KNOT_EOK when there is no cycle.
 * \retval ZC_ERR_CNAME_CYCLE when cycle is present.
 */
static int check_cname_cycles_in_zone(knot_zone_contents_t *zone,
				      const knot_rrset_t *rrset,
                                      char *fatal_error)
{
	if (rrset->type != KNOT_RRTYPE_CNAME &&
	    rrset->type != KNOT_RRTYPE_DNAME) {
		return KNOT_EBADARG;
	}
	
	const knot_rrset_t *next_rrset = rrset;
	assert(rrset);
	const knot_rdata_t *tmp_rdata = knot_rrset_rdata(next_rrset);
	const knot_node_t *next_node = NULL;

	uint i = 0;

	assert(tmp_rdata);

	const knot_dname_t *next_dname =
		knot_rdata_cname_name(tmp_rdata);
	/* (cname_name == dname_target) */

	assert(next_dname);
	
	/* Check wildcard pointing to itself. */
	if (knot_dname_is_wildcard(knot_rrset_owner(rrset))) {
		/* We need to chop the wildcard. */
		
		knot_dname_t *chopped_wc =
			knot_dname_left_chop(knot_rrset_owner(rrset));
		if (!chopped_wc) {
			/* Definitely not a cycle. */
			return KNOT_EOK;
		}
		
		/*
		 * And check that no sub-dname up to zone apex is present
		 * in its rdata.
		 */
		
		knot_dname_t *next_dname_copy =
			knot_dname_deep_copy(next_dname);
		if (!next_dname_copy) {
			knot_dname_free(&chopped_wc);
			return KNOT_ERROR;
		}
		
		const knot_dname_t *zone_origin =
			knot_node_owner(knot_zone_contents_apex(zone));
		if (!zone_origin) {
			knot_dname_free(&chopped_wc);
			knot_dname_free(&next_dname_copy);
			return KNOT_ERROR;
		}
		
		char error_found = 0;
		char cut_offs = 1;
		
		while (knot_dname_compare(next_dname_copy,
		                          zone_origin) != 0 &&
		       !error_found) {
			/* Compare chopped owner with current next dname. */
			error_found =
				knot_dname_compare(next_dname_copy,
				                   chopped_wc) == 0;
			if (error_found && cut_offs == 1) {
				/* WC without * == link. */
				knot_dname_free(&next_dname_copy);
				knot_dname_free(&chopped_wc);
				return KNOT_EOK;
			}
			
			knot_dname_t *tmp_chopped =
				knot_dname_left_chop(next_dname_copy);
			knot_dname_free(&next_dname_copy);
			if (!tmp_chopped) {
				knot_dname_free(&chopped_wc);
				knot_dname_free(&next_dname_copy);
				return KNOT_ERROR;
			}
			
			cut_offs++;
			
			next_dname_copy = tmp_chopped;
		}
		
		if (error_found) {
			knot_dname_free(&next_dname_copy);
			knot_dname_free(&chopped_wc);
			assert(cut_offs > 1);
			*fatal_error = 1;
			return ZC_ERR_CNAME_WILDCARD_SELF;
		}
		
		knot_dname_free(&next_dname_copy);
		knot_dname_free(&chopped_wc);
		
		/*
		 * Test for transitive wildcard loops.
		 * Basically the same as below, only we look for wildcards and
		 * strip them in the same fashion as above.
		 */
		
	}
	
	while (i < MAX_CNAME_CYCLE_DEPTH && next_dname != NULL) {
		next_node = knot_zone_contents_get_node(zone, next_dname);
		if (next_node == NULL) {
			next_node =
				knot_zone_contents_get_nsec3_node(zone,
			                                          next_dname);
		}
		
/*!< \todo this might replace some of the code above. */
//		/* Still NULL, try wildcards. */
//		if (next_node == NULL && knot_dname_is_wildcard(next_dname)) {
//			/* We can only use the wildcard so many times. */
			
//			/* Create chopped copy of wc. */
//			knot_dname_t *chopped_wc =
//				knot_dname_left_chop(next_dname);
//			if (chopped_wc == NULL) {
//				/* If name with this wc is in the zone,
//				   we have a problem (eg. cycle continues). */
//				next_node =
//					knot_zone_contents_get_node(zone,
//				                                    chopped_wc);
//				/* (No need to consider NSEC3 nodes.) */
//				knot_dname_free(&chopped_wc);
//			}
//		}
		
		/* Just a guess. */
		knot_dname_t *chopped_next =
			knot_dname_left_chop(next_dname);
		if (chopped_next == NULL) {
			/*!< \todo check. */
			return KNOT_ERROR;
		}
		while (next_node == NULL && chopped_next != NULL) {
			/* Cat '*' .*/
			knot_dname_t *wc =
				knot_dname_new_from_str("*", strlen("*"),
			                                NULL);
			if (wc == NULL) {
				knot_dname_free(&chopped_next);
				return KNOT_ENOMEM;
			}
			
			if (knot_dname_cat(wc, chopped_next) == NULL) {
				knot_dname_free(&chopped_next);
				knot_dname_free(&wc);
				return KNOT_ERROR;
			}
			
			next_node =
				knot_zone_contents_get_node(zone, wc);
			knot_dname_free(&wc);
			knot_dname_t *tmp = chopped_next;
			chopped_next = knot_dname_left_chop(chopped_next);
			knot_dname_free(&tmp);
		}
		
		knot_dname_free(&chopped_next);

		if (next_node != NULL) {
			next_rrset = knot_node_rrset(next_node,
						     rrset->type);
			if (next_rrset != NULL) {
				next_dname =
				knot_rdata_cname_name(next_rrset->rdata);
			} else {
				next_node = NULL;
				next_dname = NULL;
			}
		} else {
			next_dname = NULL;
		}
		i++;
	}

	/* even if the length is 0, i will be 1 */
	if (i >= MAX_CNAME_CYCLE_DEPTH) {
		*fatal_error = 1;
		return ZC_ERR_CNAME_CYCLE;
	}

	return KNOT_EOK;
}

/*!
 * \brief Return raw data from rdata item structure (without length).
 *
 * \param item Item to get rdata from.
 * \return uint16_t * raw data without length.
 */
static inline uint16_t *rdata_item_data(const knot_rdata_item_t *item)
{
	return (uint16_t *)(item->raw_data + 1);
}

/*!
 * \brief Returns type covered field from RRSIG RRSet's rdata.
 *
 * \param rdata RRSIG rdata.
 * \return uint16_t Type covered.
 */
uint16_t type_covered_from_rdata(const knot_rdata_t *rdata)
{
	return ntohs(*(uint16_t *) rdata_item_data(&(rdata->items[0])));
}

/*!
 * \brief Check whether DNSKEY rdata are valid.
 *
 * \param rdata DNSKEY rdata to be checked.
 *
 * \retval KNOT_EOK when rdata are OK.
 * \retval ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER when rdata are not OK.
 */
static int check_dnskey_rdata(const knot_rdata_t *rdata)
{
	/* check that Zone key bit it set - position 7 in net order */
	/*! \todo FIXME: endian? I swear I've fixed this already, it was 7 i guesss*/
	uint16_t mask = 1 << 8; //0b0000000100000000;

	uint16_t flags =
		knot_wire_read_u16((uint8_t *)rdata_item_data
				     (knot_rdata_item(rdata, 0)));

	if (flags & mask) {
		return KNOT_EOK;
	} else {
		/* This error does not exactly fit, but it's better
		 * than a new one */
		return ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER;
	}
}

/*!
 * \brief Calculates keytag for RSA/SHA algorithm.
 *
 * \param key Key wireformat.
 * \param keysize Wireformat size.
 *
 * \return uint16_t Calculated keytag.
 */
static uint16_t keytag_1(uint8_t *key, uint16_t keysize)
{
	uint16_t ac = 0;
	if (keysize > 4) {
		memmove(&ac, key + keysize - 3, 2);
	}

	ac = ntohs(ac);
	return ac;
}

/*!
 * \brief Calculates keytag from key wire.
 *
 * \param key Key wireformat.
 * \param keysize Wireformat size.
 *
 * \return uint16_t Calculated keytag.
 */
static uint16_t keytag(uint8_t *key, uint16_t keysize )
{
	uint32_t ac = 0; /* assumed to be 32 bits or larger */

	/* algorithm RSA/SHA */
	if (key[3] == 1) {
		return keytag_1(key, keysize);
	} else {
		for(int i = 0; i < keysize; i++) {
			ac += (i & 1) ? key[i] : key[i] << 8;
		}

		ac += (ac >> 16) & 0xFFFF;
		return (uint16_t)ac & 0xFFFF;
	}
}

/*!
 * \brief Returns size of raw data item.
 *
 * \param item Raw data item.
 *
 * \return uint16_t Size of raw data item.
 */
static inline uint16_t rdata_item_size(const knot_rdata_item_t *item)
{
	return item->raw_data[0];
}

/*!
 * \brief Converts DNSKEY rdata to wireformat.
 *
 * \param rdata DNSKEY rdata to be converted.
 * \param wire Created wire.
 * \param size Size of created wire.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ENOMEM on memory error.
 */
static int dnskey_to_wire(const knot_rdata_t *rdata, uint8_t **wire,
			  uint *size)
{
	assert(*wire == NULL);
	/* flags + algorithm + protocol + keysize */
	*size = 2 + 1 + 1 + knot_rdata_item(rdata, 3)->raw_data[0];
	*wire = malloc(sizeof(uint8_t) * *size);
	CHECK_ALLOC_LOG(*wire, KNOT_ENOMEM);

	/* copy the wire octet by octet */

	/* TODO check if we really have that many items */
	if (rdata->count < 4) {
		free(*wire);
		*wire = NULL;
		*size = 0;
		return KNOT_ERROR;
	}

	(*wire)[0] = ((uint8_t *)(knot_rdata_item(rdata, 0)->raw_data))[2];
	(*wire)[1] = ((uint8_t *)(knot_rdata_item(rdata, 0)->raw_data))[3];

	(*wire)[2] = ((uint8_t *)(knot_rdata_item(rdata, 1)->raw_data))[2];
	(*wire)[3] = ((uint8_t *)(knot_rdata_item(rdata, 2)->raw_data))[2];

	memcpy(*wire + 4, knot_rdata_item(rdata, 3)->raw_data + 1,
	       knot_rdata_item(rdata, 3)->raw_data[0]);

	return KNOT_EOK;
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
static int check_rrsig_rdata(const knot_rdata_t *rdata_rrsig,
			     const knot_rrset_t *rrset,
			     const knot_rrset_t *dnskey_rrset)
{
	if (rdata_rrsig == NULL) {
		return ZC_ERR_RRSIG_NO_RRSIG;
	}

	if (type_covered_from_rdata(rdata_rrsig) !=
	    knot_rrset_type(rrset)) {
		/* zoneparser would not let this happen
		 * but to be on the safe side
		 */
		return ZC_ERR_RRSIG_RDATA_TYPE_COVERED;
	}

	/* label number at the 2nd index should be same as owner's */
	uint16_t *raw_data =
		rdata_item_data(knot_rdata_item(rdata_rrsig, 2));

	uint8_t labels_rdata = ((uint8_t *)raw_data)[0];

	int tmp = knot_dname_label_count(knot_rrset_owner(rrset)) -
		  labels_rdata;

	if (tmp != 0) {
		/* if name has wildcard, label must not be included */
		if (!knot_dname_is_wildcard(knot_rrset_owner(rrset))) {
			return ZC_ERR_RRSIG_RDATA_LABELS;
		} else {
			if (abs(tmp) != 1) {
				return ZC_ERR_RRSIG_RDATA_LABELS;
			}
		}
	}

	/* check original TTL */
	uint32_t original_ttl =
		knot_wire_read_u32((uint8_t *)rdata_item_data(
				     knot_rdata_item(rdata_rrsig, 3)));

	if (original_ttl != knot_rrset_ttl(rrset)) {
		return ZC_ERR_RRSIG_RDATA_TTL;
	}

	/* signer's name is same as in the zone apex */
	knot_dname_t *signer_name =
		knot_rdata_item(rdata_rrsig, 7)->dname;

	/* dnskey is in the apex node */
	if (knot_dname_compare(signer_name,
				 knot_rrset_owner(dnskey_rrset)) != 0) {
		return ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER;
	}

	/* Compare algorithm, key tag and signer's name with DNSKEY rrset
	 * one of the records has to match. Signer name has been checked
	 * before */
	char match = 0;
	const knot_rdata_t *tmp_dnskey_rdata =
		knot_rrset_rdata(dnskey_rrset);
	do {
		uint8_t alg =
		((uint8_t *)(knot_rdata_item(rdata_rrsig, 1)->raw_data))[2];
		uint8_t alg_dnskey =
		((uint8_t *)(knot_rdata_item(tmp_dnskey_rdata,
					       2)->raw_data))[2];

		raw_data = rdata_item_data(knot_rdata_item(rdata_rrsig, 6));
		uint16_t key_tag_rrsig =
			knot_wire_read_u16((uint8_t *)raw_data);

/*		raw_data =
			rdata_item_data(knot_rdata_item(
					tmp_dnskey_rdata, 3));

		uint16_t raw_length = rdata_item_size(knot_rdata_item(
						     tmp_dnskey_rdata, 3)); */

		uint8_t *dnskey_wire = NULL;
		uint dnskey_wire_size = 0;

		int ret = 0;
		if ((ret = dnskey_to_wire(tmp_dnskey_rdata, &dnskey_wire,
				   &dnskey_wire_size)) != KNOT_EOK) {
			return ret;
		}

		uint16_t key_tag_dnskey =
			keytag(dnskey_wire, dnskey_wire_size);

		free(dnskey_wire);

		match = (alg == alg_dnskey) &&
			(key_tag_rrsig == key_tag_dnskey) &&
			!check_dnskey_rdata(tmp_dnskey_rdata);

	} while (!match &&
		 ((tmp_dnskey_rdata =
			knot_rrset_rdata_next(dnskey_rrset,
						tmp_dnskey_rdata))
		!= NULL));

	if (!match) {
		return ZC_ERR_RRSIG_RDATA_SIGNED_WRONG;
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
static int check_rrsig_in_rrset(const knot_rrset_t *rrset,
				const knot_rrset_t *dnskey_rrset,
				char nsec3)
{
	assert(dnskey_rrset && rrset);

	const knot_rrset_t *rrsigs = knot_rrset_rrsigs(rrset);

	if (rrsigs == NULL) {
		return ZC_ERR_RRSIG_NO_RRSIG;
	}

	/* signed rrsig - nonsense */
	if (knot_rrset_rrsigs(rrsigs) != NULL) {
		return ZC_ERR_RRSIG_SIGNED;
	}

	/* Different owner, class, ttl */

	if (knot_dname_compare(knot_rrset_owner(rrset),
				 knot_rrset_owner(rrsigs)) != 0) {
		return ZC_ERR_RRSIG_OWNER;
	}

	if (knot_rrset_class(rrset) != knot_rrset_class(rrsigs)) {
		return ZC_ERR_RRSIG_CLASS;
	}

	if (knot_rrset_ttl(rrset) != knot_rrset_ttl(rrset)) {
		return ZC_ERR_RRSIG_TTL;
	}

	/* Check whether all rrsets have their rrsigs */
	const knot_rdata_t *tmp_rdata = knot_rrset_rdata(rrset);
	const knot_rdata_t *tmp_rrsig_rdata = knot_rrset_rdata(rrsigs);

	assert(tmp_rdata);
	assert(tmp_rrsig_rdata);
	int ret = 0;
	char all_signed = tmp_rdata && tmp_rrsig_rdata;
	do {
		if ((ret = check_rrsig_rdata(tmp_rrsig_rdata,
					     rrset,
					     dnskey_rrset)) != 0) {
			return ret;
		}

		all_signed = tmp_rdata && tmp_rrsig_rdata;
	} while (((tmp_rdata = knot_rrset_rdata_next(rrset, tmp_rdata))
		!= NULL) &&
		((tmp_rrsig_rdata =
			knot_rrset_rdata_next(rrsigs, tmp_rrsig_rdata))
		!= NULL));

	if (!all_signed) {
		return ZC_ERR_RRSIG_NOT_ALL;
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
static int rdata_nsec_to_type_array(const knot_rdata_item_t *item,
			      uint16_t **array,
			      uint *count)
{
	assert(*array == NULL);

	uint8_t *data = (uint8_t *)rdata_item_data(item);

	int increment = 0;
	*count = 0;

	for (int i = 0; i < rdata_item_size(item); i += increment) {
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
static int check_nsec3_node_in_zone(knot_zone_contents_t *zone, knot_node_t *node,
                                    err_handler_t *handler)
{
	assert(handler);
	const knot_node_t *nsec3_node = knot_node_nsec3_node(node);

	if (nsec3_node == NULL) {
		/* I know it's probably not what RFCs say, but it will have to
		 * do for now. */
		if (knot_node_rrset(node, KNOT_RRTYPE_DS) != NULL) {
			err_handler_handle_error(handler, node,
					ZC_ERR_NSEC3_UNSECURED_DELEGATION);
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
						 ZC_ERR_NSEC3_NOT_FOUND);
			}

			if (nsec3_node == NULL) {
				/* Probably should not ever happen */
				return ZC_ERR_NSEC3_NOT_FOUND;
			}

			assert(nsec3_previous);

			const knot_rrset_t *previous_rrset =
				knot_node_rrset(nsec3_previous,
						  KNOT_RRTYPE_NSEC3);

			assert(previous_rrset);

			/* check for Opt-Out flag */
			uint8_t flags =
		((uint8_t *)(previous_rrset->rdata->items[1].raw_data))[2];

			uint8_t opt_out_mask = 1;

			if (!(flags & opt_out_mask)) {
				err_handler_handle_error(handler, node,
					ZC_ERR_NSEC3_UNSECURED_DELEGATION_OPT);
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
	
	const knot_rdata_t *soa_rdata = knot_rrset_rdata(soa_rrset);
	if (soa_rdata == NULL) {
		err_handler_handle_error(handler, node, ZC_ERR_UNKNOWN);
		return KNOT_EOK;
	}
	
	uint32_t minimum_ttl = knot_rdata_soa_minimum(soa_rdata);

	if (knot_rrset_ttl(nsec3_rrset) != minimum_ttl) {
			err_handler_handle_error(handler, node,
						 ZC_ERR_NSEC3_RDATA_TTL);
	}

	/* check that next dname is in the zone */
	uint8_t *next_dname_decoded = NULL;
	size_t real_size = 0;

	if (((real_size = base32hex_encode_alloc(((char *)
		rdata_item_data(&(nsec3_rrset->rdata->items[4]))) + 1,
		rdata_item_size(&nsec3_rrset->rdata->items[4]) - 1,
		(char **)&next_dname_decoded)) <= 0) ||
		(next_dname_decoded == NULL)) {
		fprintf(stderr, "Could not encode base32 string!\n");
		return KNOT_ERROR;
	}

	/* This is why we allocate maximum length of decoded string + 1 */
//	memmove(next_dname_decoded + 1, next_dname_decoded, real_size);
//	next_dname_decoded[0] = real_size;
	
	/* Local allocation, will be discarded. */
	knot_dname_t *next_dname =
		knot_dname_new_from_str((char *)next_dname_decoded,
					   real_size, NULL);
	CHECK_ALLOC_LOG(next_dname, KNOT_ENOMEM);

	free(next_dname_decoded);
	
	if (knot_dname_cat(next_dname,
		     knot_node_owner(knot_zone_contents_apex(zone))) == NULL) {
		fprintf(stderr, "Could not concatenate dnames!\n");
		return KNOT_ERROR;

	}

	if (knot_zone_contents_find_nsec3_node(zone, next_dname) == NULL) {
		err_handler_handle_error(handler, node,
					 ZC_ERR_NSEC3_RDATA_CHAIN);
	}

	/* Directly discard. */
	knot_dname_free(&next_dname);

	/* This is probably not sufficient, but again, it is covered in
	 * zone load time */

	uint count;
	uint16_t *array = NULL;
	if (rdata_nsec_to_type_array(
	    knot_rdata_item(
	    knot_rrset_rdata(nsec3_rrset), 5),
	    &array, &count) != 0) {
			err_handler_handle_error(handler, node,
						 ZC_ERR_ALLOC);
			return KNOT_ERROR;
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
			err_handler_handle_error(handler, node,
						 ZC_ERR_NSEC3_RDATA_BITMAP);
/*			char *name =
				knot_dname_to_str(
			log_zone_error("Node %s does "
					"not contain RRSet of type %s "
					"but NSEC bitmap says "
					"it does!\n", name,
					knot_rrtype_to_string(type));
			free(name); */
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
static void count_nodes_in_tree(knot_node_t *node, void *data)
{
	struct sem_check_param *param = (struct sem_check_param *)data;
	param->node_count++;
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
static int semantic_checks_plain(knot_zone_contents_t *zone,
				 knot_node_t *node,
				 char do_checks,
				 err_handler_t *handler,
				 int only_mandatory,
				 char *fatal_error)
{
	assert(handler);
	const knot_rrset_t *cname_rrset =
			knot_node_rrset(node, KNOT_RRTYPE_CNAME);
	if (cname_rrset != NULL) {
		int ret = check_cname_cycles_in_zone(zone, cname_rrset,
		                                     fatal_error);
		if (ret != KNOT_EOK) {
			err_handler_handle_error(handler, node,
						 ret);
		}

		/* No DNSSEC and yet there is more than one rrset in node */
		if (do_checks == 1 &&
		                knot_node_rrset_count(node) != 1) {
			*fatal_error = 1;
			err_handler_handle_error(handler, node,
			                         ZC_ERR_CNAME_EXTRA_RECORDS);
		} else if (knot_node_rrset_count(node) != 1) {
			/* With DNSSEC node can contain RRSIG or NSEC */
			if (!(knot_node_rrset(node, KNOT_RRTYPE_RRSIG) ||
			      knot_node_rrset(node, KNOT_RRTYPE_NSEC)) ||
			    knot_node_rrset_count(node) > 3) {
				*fatal_error = 1;
				err_handler_handle_error(handler, node,
				ZC_ERR_CNAME_EXTRA_RECORDS_DNSSEC);
			}
		}

		if (knot_rrset_rdata(cname_rrset)->next !=
		                knot_rrset_rdata(cname_rrset)) {
			*fatal_error = 1;
			err_handler_handle_error(handler, node,
			                         ZC_ERR_CNAME_MULTIPLE);
		}
	}

	const knot_rrset_t *dname_rrset =
		knot_node_rrset(node, KNOT_RRTYPE_DNAME);
	if (dname_rrset != NULL) {
		int ret = check_cname_cycles_in_zone(zone, dname_rrset,
		                                     fatal_error);
		if (ret == ZC_ERR_CNAME_CYCLE) {
			*fatal_error = 1;
			err_handler_handle_error(handler, node,
						 ZC_ERR_DNAME_CYCLE);
		} else if (ret == ZC_ERR_CNAME_WILDCARD_SELF) {
			*fatal_error = 1;
			err_handler_handle_error(handler, node,
						 ZC_ERR_DNAME_WILDCARD_SELF);
		}

		if (knot_node_rrset(node, KNOT_RRTYPE_CNAME)) {
			*fatal_error = 1;
			err_handler_handle_error(handler, node,
			                         ZC_ERR_CNAME_EXTRA_RECORDS);
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
				                         ZC_ERR_DNAME_CHILDREN);
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
				                         ZC_ERR_DNAME_CHILDREN);
			}
		}
	}
	
	if (only_mandatory) {
		return KNOT_EOK;
	}
	

	/* check for glue records at zone cuts */
	if (knot_node_is_deleg_point(node)) {
		const knot_rrset_t *ns_rrset =
				knot_node_rrset(node, KNOT_RRTYPE_NS);
		assert(ns_rrset);
		//FIXME this should be an error as well ! (i guess)

		const knot_dname_t *ns_dname =
				knot_rdata_get_item(knot_rrset_rdata
						      (ns_rrset), 0)->dname;

		assert(ns_dname);

		const knot_node_t *glue_node =
				knot_zone_contents_find_node(zone, ns_dname);

		if (knot_dname_is_subdomain(ns_dname,
			      knot_node_owner(knot_zone_contents_apex(zone)))) {
			if (glue_node == NULL) {
				err_handler_handle_error(handler, node,
							 ZC_ERR_GLUE_NODE);
			} else {
				if ((knot_node_rrset(glue_node,
					       KNOT_RRTYPE_A) == NULL) &&
				    (knot_node_rrset(glue_node,
					       KNOT_RRTYPE_AAAA) == NULL)) {
					err_handler_handle_error(handler, node,
							 ZC_ERR_GLUE_RECORD);
				}
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
 * \param first_node First node in canonical order.
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
				  knot_node_t *first_node,
				  knot_node_t **last_node,
				  err_handler_t *handler,
				  char nsec3)
{
	assert(handler);
	assert(node);
	char auth = !knot_node_is_non_auth(node);
	char deleg = knot_node_is_deleg_point(node);
	uint rrset_count = knot_node_rrset_count(node);
	const knot_rrset_t **rrsets = knot_node_rrsets(node);
	const knot_rrset_t *dnskey_rrset =
		knot_node_rrset(knot_zone_contents_apex(zone),
				  KNOT_RRTYPE_DNSKEY);

	int ret = 0;

	for (int i = 0; i < rrset_count; i++) {
		const knot_rrset_t *rrset = rrsets[i];
		if (auth && !deleg &&
		    (ret = check_rrsig_in_rrset(rrset, dnskey_rrset,
						nsec3)) != 0) {
			err_handler_handle_error(handler, node, ret);
		}

		if (!nsec3 && auth) {
			/* check for NSEC record */
			const knot_rrset_t *nsec_rrset =
					knot_node_rrset(node,
							  KNOT_RRTYPE_NSEC);

			if (nsec_rrset == NULL) {
				err_handler_handle_error(handler, node,
							 ZC_ERR_NO_NSEC);
			} else {

				/* check NSEC/NSEC3 bitmap */

				uint count;

				uint16_t *array = NULL;

				if (rdata_nsec_to_type_array(
						knot_rdata_item(
						knot_rrset_rdata(nsec_rrset),
						1),
						&array, &count) != 0) {
					err_handler_handle_error(handler,
								 NULL,
								 ZC_ERR_ALLOC);
					return ZC_ERR_ALLOC; /* ... */
					/*return; */
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
						ZC_ERR_NSEC_RDATA_BITMAP);
					}
				}
				free(array);
			}

			/* Test that only one record is in the
				 * NSEC RRSet */

			if ((nsec_rrset != NULL) &&
			    knot_rrset_rdata(nsec_rrset)->next !=
			    knot_rrset_rdata(nsec_rrset)) {
				err_handler_handle_error(handler,
						 node,
						 ZC_ERR_NSEC_RDATA_MULTIPLE);
				/* CLEANUP */
/*				char *name =
					knot_dname_to_str(
					knot_node_owner(node));
				log_zone_error("Node %s contains more "
					       "than one NSEC "
					       "record!\n", name);
				knot_rrset_dump(nsec_rrset, 0);
				free(name); */
			}

			/*
			 * Test that NSEC chain is coherent.
			 * We have already checked that every
			 * authoritative node contains NSEC record
			 * so checking should only be matter of testing
			 * the next link in each node.
			 */

			if (nsec_rrset != NULL) {
				knot_dname_t *next_domain =
					knot_rdata_item(
					knot_rrset_rdata(nsec_rrset),
					0)->dname;

				assert(next_domain);

				if (knot_zone_contents_find_node(zone, next_domain) ==
				    NULL) {
					err_handler_handle_error(handler,
						node,
						ZC_ERR_NSEC_RDATA_CHAIN);
					/* CLEANUP */
/*					log_zone_error("NSEC chain is not "
						       "coherent!\n"); */
				}

				if (knot_dname_compare(next_domain,
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
				free(rrsets);
				return ret;
			}
		}
	}
	free(rrsets);

	return KNOT_EOK;
}

/*!
 * \brief Function called by zone traversal function. Used to call
 *        knot_zone_save_enclosers.
 *
 * \param node Node to be searched.
 * \param data Arguments.
 */
static void do_checks_in_tree(knot_node_t *node, void *data)
{
	assert(data != NULL);
	arg_t *args = (arg_t *)data;

	knot_rrset_t **rrsets = knot_node_get_rrsets(node);
	short count = knot_node_rrset_count(node);

	assert(count == 0 || rrsets != NULL);

	knot_zone_contents_t *zone = (knot_zone_contents_t *)args->arg1;

	assert(zone);

	knot_node_t *first_node = (knot_node_t *)args->arg4;
	knot_node_t **last_node = (knot_node_t **)args->arg5;

	err_handler_t *handler = (err_handler_t *)args->arg6;
	
	char do_checks = *((char *)(args->arg3));

	if (do_checks) {
		semantic_checks_plain(zone, node, do_checks, handler, 0,
		                      (char *)args->arg7);
	} else {
		assert(handler);
		/* All CNAME/DNAME checks are mandatory. */
		handler->options.log_cname = 1;
		int check_level = 1 + (zone_is_secure(zone) ? 1 : 0);
		semantic_checks_plain(zone, node, check_level, handler, 1,
		                      (char *)args->arg7);
		
		free(rrsets);
		assert(do_checks == 0);
		return;
	}

	if (do_checks > 1) {
		semantic_checks_dnssec(zone, node, first_node, last_node,
				       handler, do_checks == 3);
	}

	free(rrsets);
}

int zone_do_sem_checks(knot_zone_contents_t *zone, char do_checks,
                        err_handler_t *handler,
                        knot_node_t **last_node)
{
	if (!handler) {
		return KNOT_EBADARG;
	}
	arg_t arguments;
	arguments.arg1 = zone;
	arguments.arg3 = &do_checks;
	arguments.arg4 = NULL;
	arguments.arg5 = last_node;
	arguments.arg6 = handler;
	char fatal_error = 0;
	arguments.arg7 = (void *)&fatal_error;

	knot_zone_contents_tree_apply_inorder(zone,
			   do_checks_in_tree,
			   (void *)&arguments);
	
	if (fatal_error) {
		return KNOT_ERROR;
	}
	
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
		assert(last_nsec3_node && first_nsec3_node);
		const knot_rrset_t *nsec3_rrset =
			knot_node_rrset(last_nsec3_node,
		                              KNOT_RRTYPE_NSEC3);
		if (nsec3_rrset == NULL) {
			err_handler_handle_error(handler, last_nsec3_node,
						 ZC_ERR_NSEC3_RDATA_CHAIN);
			return;
		}

		/* check that next dname is in the zone */
		uint8_t *next_dname_decoded = NULL;
		size_t real_size = 0;

		if (((real_size = base32hex_encode_alloc(((char *)
			rdata_item_data(&(nsec3_rrset->rdata->items[4]))) + 1,
			rdata_item_size(&nsec3_rrset->rdata->items[4]) - 1,
			(char **)&next_dname_decoded)) <= 0) ||
			(next_dname_decoded == NULL)) {
			fprintf(stderr, "Could not encode base32 string!\n");
			err_handler_handle_error(handler, last_nsec3_node,
						 ZC_ERR_NSEC3_RDATA_CHAIN);
			return;
		}

		/* Local allocation, will be discarded. */
		knot_dname_t *next_dname =
			knot_dname_new_from_str((char *)next_dname_decoded,
						real_size, NULL);
		if (next_dname == NULL) {
			fprintf(stderr, "Could not allocate dname!\n");
			err_handler_handle_error(handler, last_nsec3_node,
						 ZC_ERR_ALLOC);
			return;
		}

		free(next_dname_decoded);

		/*! \todo Free result and dname! */
		if (knot_dname_cat(next_dname,
			     knot_node_owner(knot_zone_contents_apex(zone))) ==
		                NULL) {
			fprintf(stderr, "Could not concatenate dnames!\n");
			err_handler_handle_error(handler, last_nsec3_node,
						 ZC_ERR_NSEC3_RDATA_CHAIN);
			return;
		}

		/* Check it points somewhere first. */
		if (knot_zone_contents_find_nsec3_node(zone, next_dname) == NULL) {
			assert(knot_zone_contents_find_node(zone,
			                                    next_dname) ==
			                                    NULL);
			err_handler_handle_error(handler, last_nsec3_node,
						 ZC_ERR_NSEC3_RDATA_CHAIN);
		} else {
			/* Compare with the actual first NSEC3 node. */
			if (knot_dname_compare(first_nsec3_node->owner,
			                         next_dname) != 0) {
				err_handler_handle_error(handler, last_nsec3_node,
							 ZC_ERR_NSEC3_RDATA_CHAIN);
			}
		}

		/* Directly discard. */
		knot_dname_free(&next_dname);

	} else if (do_checks == 2 ) {
		if (last_node == NULL) {
			err_handler_handle_error(handler, last_node,
				ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC);
				return;
		} else {
			const knot_rrset_t *nsec_rrset =
				knot_node_rrset(last_node,
						  KNOT_RRTYPE_NSEC);

			if (nsec_rrset == NULL) {
				err_handler_handle_error(handler, last_node,
					 ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC);
				return;
			}

			const knot_dname_t *next_dname =
				knot_rdata_item(
				knot_rrset_rdata(nsec_rrset), 0)->dname;
			assert(next_dname);

			const knot_dname_t *apex_dname =
				knot_node_owner(knot_zone_contents_apex(zone));
			assert(apex_dname);

			if (knot_dname_compare(next_dname, apex_dname) !=0) {
				err_handler_handle_error(handler, last_node,
					 ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC);
			}
		}
	}
}
