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
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "libknot/common.h"
#include "knot/zone/zone-dump.h"
#include "libknot/libknot.h"
#include "knot/other/debug.h"
#include "common/skip-list.h"
#include "common/base32hex.h"
#include "common/crc.h"
#include "libknot/util/error.h"

#define ZONECHECKS_VERBOSE

/*! \note Contents of a dump file:
 * MAGIC(knotxx) db_filename dname_table
 * NUMBER_OF_NORMAL_NODES NUMBER_OF_NSEC3_NODES
 * [normal_nodes] [nsec3_nodes]
 * --------------------------------------------
 * dname_table is dumped as follows:
 * NUMBER_OF_DNAMES [dname_wire_length dname_wire label_count dname_labels ID]
 * node has following format:
 * owner_id
 * node_flags node_rrset_count [node_rrsets]
 * rrset has following format:
 * rrset_type rrset_class rrset_ttl rrset_rdata_count rrset_rrsig_count
 * [rrset_rdata] [rrset_rrsigs]
 * rdata can contain either dname ID,
 * or raw data stored like this: data_len [data]
 */

static const uint MAX_CNAME_CYCLE_DEPTH = 15;

/*!
 *\brief Internal error constants. General errors are added for convenience,
 *       so that code does not have to change if new errors are added.
 */
enum zonechecks_errors {
	ZC_ERR_ALLOC = -40,
	ZC_ERR_UNKNOWN,

	ZC_ERR_MISSING_SOA,

	ZC_ERR_GENERIC_GENERAL_ERROR, /* isn't there a better name? */

	ZC_ERR_RRSIG_RDATA_TYPE_COVERED,
	ZC_ERR_RRSIG_RDATA_TTL,
	ZC_ERR_RRSIG_RDATA_LABELS,
	ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER,
	ZC_ERR_RRSIG_RDATA_SIGNED_WRONG,
	ZC_ERR_RRSIG_NO_RRSIG,
	ZC_ERR_RRSIG_SIGNED,
	ZC_ERR_RRSIG_OWNER,
	ZC_ERR_RRSIG_CLASS,
	ZC_ERR_RRSIG_TTL,
	ZC_ERR_RRSIG_NOT_ALL,

	ZC_ERR_RRSIG_GENERAL_ERROR,

	ZC_ERR_NO_NSEC,
	ZC_ERR_NSEC_RDATA_BITMAP,
	ZC_ERR_NSEC_RDATA_MULTIPLE,
	ZC_ERR_NSEC_RDATA_CHAIN,
	ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC,

	ZC_ERR_NSEC_GENERAL_ERROR,

	ZC_ERR_NSEC3_UNSECURED_DELEGATION,
	ZC_ERR_NSEC3_NOT_FOUND,
	ZC_ERR_NSEC3_UNSECURED_DELEGATION_OPT,
	ZC_ERR_NSEC3_RDATA_TTL,
	ZC_ERR_NSEC3_RDATA_CHAIN,
	ZC_ERR_NSEC3_RDATA_BITMAP,

	ZC_ERR_NSEC3_GENERAL_ERROR,

	ZC_ERR_CNAME_CYCLE,
	ZC_ERR_DNAME_CYCLE,
	ZC_ERR_CNAME_EXTRA_RECORDS,
	ZC_ERR_DNAME_EXTRA_RECORDS,
	ZC_ERR_CNAME_EXTRA_RECORDS_DNSSEC,
	ZC_ERR_CNAME_MULTIPLE,
	ZC_ERR_DNAME_MULTIPLE,

	ZC_ERR_CNAME_GENERAL_ERROR,

	ZC_ERR_GLUE_NODE,
	ZC_ERR_GLUE_RECORD,

	ZC_ERR_GLUE_GENERAL_ERROR,
};

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
	[-ZC_ERR_DNAME_EXTRA_RECORDS] =
	"DNAME: Node with DNAME record has other records!\n",
	[-ZC_ERR_CNAME_EXTRA_RECORDS_DNSSEC] =
	"CNAME: Node with CNAME record has other "
	"records than RRSIG and NSEC/NSEC3!\n",
	[-ZC_ERR_CNAME_MULTIPLE] = "CNAME: Multiple CNAME records!\n",
	[-ZC_ERR_DNAME_MULTIPLE] = "DNAME: Multiple DNAME records!\n",

	/* ^
	   | Important errors (to be logged on first occurence and counted) */


	/* Below are errors of lesser importance, to be counted unless
	   specified otherwise */

	[-ZC_ERR_GLUE_NODE] =
	"GLUE: Node with Glue record missing!\n",
	[-ZC_ERR_GLUE_RECORD] =
	"GLUE: Record with Glue address missing\n",
};

/*!
 * \brief Structure representing handle options.
 */
struct handler_options {
	char log_cname; /*!< Log all CNAME related semantic errors. */
	char log_glue; /*!< Log all glue related semantic errors. */
	char log_rrsigs; /*!< Log all RRSIG related semantic errors. */
	char log_nsec; /*!< Log all NSEC related semantic errors. */
	char log_nsec3; /*!< Log all NSEC3 related semantic errors. */
};

/*!
 * \brief Structure for handling semantic errors.
 */
struct err_handler {
	/* Consider moving error messages here */
	struct handler_options options; /*!< Handler options. */
	uint errors[(-ZC_ERR_ALLOC) + 1]; /*!< Array with error messages */
};

typedef struct err_handler err_handler_t;

/*!
 * \brief Creates new semantic error handler.
 *
 * \param log_cname If true, log all CNAME related events.
 * \param log_glue If true, log all Glue related events.
 * \param log_rrsigs If true, log all RRSIGs related events.
 * \param log_nsec If true, log all NSEC related events.
 * \param log_nsec3 If true, log all NSEC3 related events.
 *
 * \return err_handler_t * Created error handler.
 */
static err_handler_t *handler_new(char log_cname, char log_glue,
				  char log_rrsigs, char log_nsec,
				  char log_nsec3)
{
	err_handler_t *handler = malloc(sizeof(err_handler_t));
	CHECK_ALLOC_LOG(handler, NULL);

	/* It should be initialized, but to be safe */
	memset(handler->errors, 0, sizeof(uint) * (-ZC_ERR_ALLOC + 1));

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
				uint error)
{
	if (node != NULL) {
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

/*!
 * \brief Called when error has been encountered in node. Will either log error
 *        or print it, depending on handler's options.
 *
 * \param handler Error handler.
 * \param node Node with semantic error in it.
 * \param error Type of error.
 *
 * \retval KNOT_EOK on success.
 * \retval ZC_ERR_UNKNOWN if unknown error.
 * \retval ZC_ERR_ALLOC if memory error.
 */
static int err_handler_handle_error(err_handler_t *handler,
				    const knot_node_t *node,
				    uint error)
{
	assert(handler && node);
	if ((error != 0) &&
	    (error > ZC_ERR_GLUE_GENERAL_ERROR)) {
		return ZC_ERR_UNKNOWN;
	}

	if (error == ZC_ERR_ALLOC) {
		ERR_ALLOC_FAILED;
		return ZC_ERR_ALLOC;
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

/*!
 * \brief This function prints all errors that occured in zone.
 *
 * \param handler Error handler containing found errors.
 */
static void err_handler_log_all(err_handler_t *handler)
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
 * \brief Arguments to be used with tree traversal functions. Uses void pointers
 *        to be more versatile.
 *
 */
struct arg {
	void *arg1; /* FILE *f / zone */
	void *arg2; /* skip_list_t */
	void *arg3; /* zone */
	void *arg4; /* first node */
	void *arg5; /* last node */
	void *arg6; /* error handler */
	void *arg7; /* CRC */
};

typedef struct arg arg_t;

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
				      const knot_rrset_t *rrset)
{
	const knot_rrset_t *next_rrset = rrset;
	assert(rrset);
	const knot_rdata_t *tmp_rdata = knot_rrset_rdata(next_rrset);
	const knot_node_t *next_node = NULL;

	uint i = 0;

	assert(tmp_rdata);

	const knot_dname_t *next_dname =
		knot_rdata_cname_name(tmp_rdata);

	assert(next_dname);

	while (i < MAX_CNAME_CYCLE_DEPTH && next_dname != NULL) {
		next_node = knot_zone_contents_get_node(zone, next_dname);
		if (next_node == NULL) {
			next_node =
				knot_zone_contents_get_nsec3_node(zone, next_dname);
		}

		if (next_node != NULL) {
			next_rrset = knot_node_rrset(next_node,
						       KNOT_RRTYPE_CNAME);
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
	const knot_node_t *nsec3_node = knot_node_nsec3_node(node, 0);

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
						&nsec3_previous, 0) != 0) {
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

	uint32_t minimum_ttl =
		knot_wire_read_u32((uint8_t *)
		rdata_item_data(
		knot_rdata_item(
		knot_rrset_rdata(
		knot_node_rrset(
		knot_zone_contents_apex(zone), KNOT_RRTYPE_SOA)), 6)));
	/* Are those getters even worth this?
	 * Now I have no idea what this code does. */

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
	memmove(next_dname_decoded + 1, next_dname_decoded, real_size);
	next_dname_decoded[0] = real_size;

	/* Local allocation, will be discarded. */
	knot_dname_t *next_dname =
		knot_dname_new_from_wire(next_dname_decoded,
					   real_size + 1, NULL);
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
			break;
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
				 err_handler_t *handler)
{
	assert(handler);
	const knot_rrset_t *cname_rrset =
			knot_node_rrset(node, KNOT_RRTYPE_CNAME);
	if (cname_rrset != NULL) {
		if (check_cname_cycles_in_zone(zone, cname_rrset) !=
				KNOT_EOK) {
			err_handler_handle_error(handler, node,
						 ZC_ERR_CNAME_CYCLE);
		}

		/* No DNSSEC and yet there is more than one rrset in node */
		if (do_checks == 1 &&
		                knot_node_rrset_count(node) != 1) {
			err_handler_handle_error(handler, node,
			                         ZC_ERR_CNAME_EXTRA_RECORDS);
		} else if (knot_node_rrset_count(node) != 1) {
			/* With DNSSEC node can contain RRSIG or NSEC */
			if (!(knot_node_rrset(node, KNOT_RRTYPE_RRSIG) ||
			      knot_node_rrset(node, KNOT_RRTYPE_NSEC)) ||
			    knot_node_rrset_count(node) > 3) {
				err_handler_handle_error(handler, node,
				ZC_ERR_CNAME_EXTRA_RECORDS_DNSSEC);
			}
		}

		if (knot_rrset_rdata(cname_rrset)->next !=
		                knot_rrset_rdata(cname_rrset)) {
			err_handler_handle_error(handler, node,
			                         ZC_ERR_CNAME_MULTIPLE);
		}
	}

	const knot_rrset_t *dname_rrset =
		knot_node_rrset(node, KNOT_RRTYPE_DNAME);
	if (dname_rrset != NULL) {
		if (check_cname_cycles_in_zone(zone, dname_rrset) !=
				KNOT_EOK) {
			err_handler_handle_error(handler, node,
						 ZC_ERR_DNAME_CYCLE);
		}

		if (knot_node_rrset(node, KNOT_RRTYPE_CNAME)) {
			err_handler_handle_error(handler, node,
			                         ZC_ERR_DNAME_EXTRA_RECORDS);
		}

		if (knot_rrset_rdata(dname_rrset)->next !=
		    knot_rrset_rdata(dname_rrset)) {
			err_handler_handle_error(handler, node,
			                         ZC_ERR_DNAME_MULTIPLE);
		}
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
		  /* CLEANUP */
/*			log_zone_error("RRSIG %d node %s\n", ret,
				       knot_dname_to_str(node->owner));*/

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
				/* CLEANUP */
/*				char *name =
					knot_dname_to_str(node->owner);
				log_zone_error("Missing NSEC in node: "
					       "%s\n", name);
				free(name);
				return; */
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
					/* CLEANUP */
	/*					char *name =
						knot_dname_to_str(
						knot_node_owner(node));

						log_zone_error("Node %s does "
						"not contain RRSet of type %s "
						"but NSEC bitmap says "
					       "it does!\n", name,
					       knot_rrtype_to_string(type));

					free(name); */
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


/*	for (int i = 0; i < count; ++i) {
		assert(rrsets[i] != NULL);
		knot_zone_save_enclosers_rrset(rrsets[i],
						 zone,
						 (skip_list_t *)args->arg2);
	} */

	knot_node_t *first_node = (knot_node_t *)args->arg4;
	knot_node_t **last_node = (knot_node_t **)args->arg5;

	err_handler_t *handler = (err_handler_t *)args->arg6;

	char do_checks = *((char *)(args->arg3));

	if (do_checks) {
		semantic_checks_plain(zone, node, do_checks, handler);
	}

	if (do_checks > 1) {
		semantic_checks_dnssec(zone, node, first_node, last_node,
				       handler, do_checks == 3);
	}

	free(rrsets);
}

/*!
 * \brief Helper function - wraps its arguments into arg_t structure and
 *        calls function that does the actual work.
 *
 * \param zone Zone to be searched / checked
 * \param list Skip list of closests enclosers.
 * \param do_checks Level of semantic checks.
 * \param handler Semantic error handler.
 * \param last_node Last checked node, which is part of NSEC(3) chain.
 */
void zone_do_sem_checks(knot_zone_contents_t *zone, char do_checks,
                        err_handler_t *handler,
                        knot_node_t **last_node)
{
	if (!do_checks) {
		return;
	}

	arg_t arguments;
	arguments.arg1 = zone;
	arguments.arg3 = &do_checks;
	arguments.arg4 = NULL;
	arguments.arg5 = last_node;
	arguments.arg6 = handler;

	knot_zone_contents_tree_apply_inorder(zone,
			   do_checks_in_tree,
			   (void *)&arguments);
}

static inline int fwrite_to_file_crc(const void *src,
                                     size_t size, size_t n, FILE *f,
                                     crc_t *crc)
{
	size_t rc = fwrite(src, size, n, f);
	if (rc != n) {
		fprintf(stderr, "fwrite: invalid write %zu (expected %zu)\n", rc,
			n);
	}
	/* \todo this seems to be wrong, if you fwrite less than n items, you probably should not continue */

	if (size * n > 0) {
		*crc =
			crc_update(*crc, (unsigned char *)src,
		                   size * n);
	}

	/* \todo the rc return is certainly wrong as it is used in the caller function */
//	return rc == n;
	return (int)rc;

}

static inline int fwrite_to_stream(const void *src,
                                   size_t size, size_t n,
                                   uint8_t **stream,
                                   size_t *stream_size)
{
	/* Resize the stream */
	void *tmp = realloc(*stream,
			    (*stream_size + (size * n)) * sizeof(uint8_t));
	if (tmp != NULL) {
		*stream = tmp;
		memcpy(*stream + *stream_size, src,
		       size * n);
		*stream_size += (size * n) * sizeof(uint8_t);
		return KNOT_EOK;
	} else {
		free(*stream);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

static int fwrite_wrapper(const void *src,
                          size_t size, size_t n, FILE *fp,
                          uint8_t **stream, size_t *stream_size, crc_t *crc)
{
	if (fp == NULL) {
		assert(stream && stream_size);
		assert(crc == NULL);
		return fwrite_to_stream(src, size, n, stream, stream_size);
	} else {
		assert(stream == NULL && stream_size == NULL);
		return fwrite_to_file_crc(src, size, n, fp, crc);
	}
}

/*!
 * \brief Dumps dname labels in binary format to given file.
 *
 * \param dname Dname whose labels are to be dumped.
 * \param f Output file.
 */
static void knot_labels_dump_binary(const knot_dname_t *dname, FILE *f,
                                    uint8_t **stream, size_t *stream_size,
                                    crc_t *crc)
{
	dbg_zdump("label count: %d\n", dname->label_count);
	uint16_t label_count = dname->label_count;
	/* \todo check the return value */
	fwrite_wrapper(&label_count, sizeof(label_count), 1, f, stream,
	               stream_size, crc);
	/* \todo check the return value */
	fwrite_wrapper(dname->labels, sizeof(uint8_t), dname->label_count, f,
	               stream, stream_size, crc);
}

/*!
 * \brief Dumps dname in binary format to given file.
 *
 * \param dname Dname to be dumped.
 * \param f Output file.
 */
static void knot_dname_dump_binary(const knot_dname_t *dname, FILE *f,
                                   uint8_t **stream, size_t *stream_size,
                                   crc_t *crc)
{
	uint32_t dname_size = dname->size;
	/* \todo check the return value */
	fwrite_wrapper(&dname_size, sizeof(dname_size), 1, f, stream,
	               stream_size, crc);
	/* \todo check the return value */
	fwrite_wrapper(dname->name, sizeof(uint8_t), dname->size, f,
	               stream, stream_size, crc);
	dbg_zdump("dname size: %d\n", dname->size);
	knot_labels_dump_binary(dname, f, stream, stream_size, crc);
}

/*!< \todo some global variable indicating error! */
static void dump_dname_with_id(const knot_dname_t *dname, FILE *f,
                               uint8_t **stream, size_t *stream_size,
                               crc_t *crc)
{
	uint32_t id = dname->id;
	/* \todo check the return value */
	fwrite_wrapper(&id, sizeof(id), 1, f, stream, stream_size, crc);
	knot_dname_dump_binary(dname, f, stream, stream_size, crc);
/*	if (!fwrite_wrapper_safe(&dname->id, sizeof(dname->id), 1, f)) {
		return KNOT_ERROR;
	} */
}

/*!
 * \brief Dumps given rdata in binary format to given file.
 *
 * \param rdata Rdata to be dumped.
 * \param type Type of rdata.
 * \param data Arguments to be propagated.
 */
static void knot_rdata_dump_binary(knot_rdata_t *rdata,
				   uint32_t type, void *data, int use_ids,
                                   uint8_t **stream, size_t *stream_size,
                                   crc_t *crc)
{
	FILE *f = (FILE *)((arg_t *)data)->arg1;
	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(type);
	assert(desc != NULL);

	dbg_zdump("Dumping type: %d\n", type);

	if (desc->fixed_items) {
		assert(desc->length == rdata->count);
	}

	/* Write rdata count. */
	/* \todo check the return value */
	fwrite_wrapper(&(rdata->count),
	               sizeof(rdata->count), 1, f, stream, stream_size, crc);

	for (int i = 0; i < rdata->count; i++) {
		if (&(rdata->items[i]) == NULL) {
			dbg_zdump("Item n. %d is not set!\n", i);
			continue;
		}
		dbg_zdump("Item n: %d\n", i);
		if (desc->wireformat[i] == KNOT_RDATA_WF_COMPRESSED_DNAME ||
		desc->wireformat[i] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
		desc->wireformat[i] == KNOT_RDATA_WF_LITERAL_DNAME )	{
			/*  some temp variables - this is way too long */
			assert(rdata->items[i].dname != NULL);
			knot_dname_t *wildcard = NULL;

			if (rdata->items[i].dname->node != NULL &&
				rdata->items[i].dname->node->owner !=
				rdata->items[i].dname) {
				wildcard = rdata->items[i].dname->node->owner;
			}

			if (use_ids) {
				/* Write ID. */
				dbg_zload("%s \n",
				    knot_dname_to_str(rdata->items[i].dname));
				assert(rdata->items[i].dname->id != 0);

				uint32_t id = rdata->items[i].dname->id;
				/* \todo check the return value */
				fwrite_wrapper(&id,
				       sizeof(id), 1, f, stream, stream_size,
				               crc);
			} else {
//				assert(rdata->items[i].dname->id != 0);
				dump_dname_with_id(rdata->items[i].dname,
				                   f, stream,
				                   stream_size, crc);
			}

			/* Write in the zone bit */
			if (rdata->items[i].dname->node != NULL && !wildcard) {
				/* \todo check the return value */
				fwrite_wrapper((uint8_t *)"\1",
				       sizeof(uint8_t), 1, f, stream,
				               stream_size, crc);
			} else {
				/* \todo check the return value */
				fwrite_wrapper((uint8_t *)"\0", sizeof(uint8_t),
				       1, f, stream, stream_size, crc);
			}

			if (use_ids && wildcard) {
				/* \todo check the return value */
				fwrite_wrapper((uint8_t *)"\1",
				       sizeof(uint8_t), 1, f, stream,
				       stream_size, crc);
				uint32_t wildcard_id = wildcard->id;
				/* \todo check the return value */
				fwrite_wrapper(&wildcard_id,
				       sizeof(wildcard_id), 1, f, stream,
				               stream_size, crc);
			} else {
				/* \todo check the return value */
				fwrite_wrapper((uint8_t *)"\0", sizeof(uint8_t),
				       1, f, stream,
				       stream_size, crc);
			}

		} else {
			dbg_zdump("Writing raw data. Item nr.: %d\n",
			                 i);
			assert(rdata->items[i].raw_data != NULL);
			/* \todo check the return value */
			fwrite_wrapper(rdata->items[i].raw_data,
			               sizeof(uint8_t),
			       rdata->items[i].raw_data[0] + 2, f,
			               stream, stream_size, crc);

			dbg_zdump("Written %d long raw data\n",
					   rdata->items[i].raw_data[0]);
		}
	}
}

/*!
 * \brief Dumps RRSIG in binary format to given file.
 *
 * \param rrsig RRSIG to be dumped.
 * \param data Arguments to be propagated.
 */
static void knot_rrsig_set_dump_binary(knot_rrset_t *rrsig, arg_t *data,
                                       int use_ids,
                                       uint8_t **stream, size_t *stream_size,
                                       crc_t *crc)
{
	dbg_zdump("Dumping rrset \\w owner: %s\n",
	                   knot_dname_to_str(rrsig->owner));
	assert(rrsig->type == KNOT_RRTYPE_RRSIG);
	assert(rrsig->rdata);
	FILE *f = (FILE *)((arg_t *)data)->arg1;
	/* \todo check the return value */
	fwrite_wrapper(&rrsig->type, sizeof(rrsig->type), 1, f,
	               stream, stream_size, crc);
	fwrite_wrapper(&rrsig->rclass, sizeof(rrsig->rclass), 1, f,
	               stream, stream_size, crc);
	fwrite_wrapper(&rrsig->ttl, sizeof(rrsig->ttl), 1, f,
	               stream, stream_size, crc);

	uint32_t rdata_count = 1;
	/* Calculate rrset rdata count. */
	knot_rdata_t *tmp_rdata = rrsig->rdata;
	while(tmp_rdata->next != rrsig->rdata) {
		tmp_rdata = tmp_rdata->next;
		rdata_count++;
	}

	fwrite_wrapper(&rdata_count, sizeof(rdata_count), 1, f,
	               stream, stream_size, crc);

	tmp_rdata = rrsig->rdata;
	while (tmp_rdata->next != rrsig->rdata) {
		knot_rdata_dump_binary(tmp_rdata, KNOT_RRTYPE_RRSIG, data,
		                         use_ids, stream, stream_size, crc);
		tmp_rdata = tmp_rdata->next;
	}
	knot_rdata_dump_binary(tmp_rdata, KNOT_RRTYPE_RRSIG, data, use_ids,
	                       stream, stream_size, crc);
}

/*!
 * \brief Dumps RRSet in binary format to given file.
 *
 * \param rrset RRSSet to be dumped.
 * \param data Arguments to be propagated.
 */
static void knot_rrset_dump_binary(const knot_rrset_t *rrset, void *data,
                                   int use_ids,
                                   uint8_t **stream, size_t *stream_size,
                                   crc_t *crc)
{
	FILE *f = (FILE *)((arg_t *)data)->arg1;

	if (!use_ids) {
		dump_dname_with_id(rrset->owner, f, stream, stream_size, crc);
	}

	/* \todo check the return value */
	fwrite_wrapper(&rrset->type, sizeof(rrset->type), 1, f,
	               stream, stream_size, crc);
	fwrite_wrapper(&rrset->rclass, sizeof(rrset->rclass), 1, f,
	               stream, stream_size, crc);
	fwrite_wrapper(&rrset->ttl, sizeof(rrset->ttl), 1, f,
	               stream, stream_size, crc);

	uint32_t rdata_count = 1;
	uint8_t has_rrsig = rrset->rrsigs != NULL;

	/* Calculate rrset rdata count. */
	knot_rdata_t *tmp_rdata = rrset->rdata;
	while(tmp_rdata->next != rrset->rdata) {
		tmp_rdata = tmp_rdata->next;
		rdata_count++;
	}

	fwrite_wrapper(&rdata_count, sizeof(rdata_count), 1, f,
	               stream, stream_size, crc);
	fwrite_wrapper(&has_rrsig, sizeof(has_rrsig), 1, f,
	               stream, stream_size, crc);

	tmp_rdata = rrset->rdata;

	while (tmp_rdata->next != rrset->rdata) {
		knot_rdata_dump_binary(tmp_rdata, rrset->type, data, use_ids,
		                       stream, stream_size, crc);
		tmp_rdata = tmp_rdata->next;
	}
	knot_rdata_dump_binary(tmp_rdata, rrset->type, data, use_ids,
	                       stream, stream_size, crc);

	/* This is now obsolete, although I'd rather not use recursion - that
	 * would probably not work */

	if (rrset->rrsigs != NULL) {
		knot_rrsig_set_dump_binary(rrset->rrsigs, data, use_ids,
		                           stream, stream_size, crc);
	}
}

/*!
 * \brief Dumps all RRSets in node to file in binary format.
 *
 * \param node Node to dumped.
 * \param data Arguments to be propagated.
 */
static void knot_node_dump_binary(knot_node_t *node, void *data,
                                  uint8_t **stream, size_t *stream_size,
                                  crc_t *crc)
{
	arg_t *args = (arg_t *)data;
	FILE *f = (FILE *)args->arg1;

//	node_count++;
	/* first write dname */
	assert(node->owner != NULL);

	/* Write owner ID. */
	dbg_zdump("Dumping node owned by %s\n",
	                   knot_dname_to_str(node->owner));
	assert(node->owner->id != 0);
	uint32_t owner_id = node->owner->id;
	/* \todo check the return value */
	fwrite_wrapper(&owner_id, sizeof(owner_id), 1, f, stream, stream_size,
	               crc);

	if (knot_node_parent(node, 0) != NULL) {
		uint32_t parent_id = knot_dname_id(
				knot_node_owner(knot_node_parent(node, 0)));
		fwrite_wrapper(&parent_id, sizeof(parent_id), 1, f,
		               stream, stream_size, crc);
	} else {
		uint32_t parent_id = 0;
		fwrite_wrapper(&parent_id, sizeof(parent_id), 1, f,
		               stream, stream_size, crc);
	}

	fwrite_wrapper(&(node->flags), sizeof(node->flags), 1, f,
	               stream, stream_size, crc);

	dbg_zdump("Written flags: %u\n", node->flags);

	if (knot_node_nsec3_node(node, 0) != NULL) {
		uint32_t nsec3_id =
			knot_node_owner(knot_node_nsec3_node(node, 0))->id;
		fwrite_wrapper(&nsec3_id, sizeof(nsec3_id), 1, f,
		               stream, stream_size, crc);
		dbg_zdump("Written nsec3 node id: %u\n",
			 knot_node_owner(knot_node_nsec3_node(node, 0))->id);
	} else {
		uint32_t nsec3_id = 0;
		fwrite_wrapper(&nsec3_id, sizeof(nsec3_id), 1, f,
		               stream, stream_size, crc);
	}

	/* Now we need (or do we?) count of rrsets to be read
	 * but that number is yet unknown */

	uint16_t rrset_count = node->rrset_count;
	fwrite_wrapper(&rrset_count, sizeof(rrset_count), 1, f,
	               stream, stream_size, crc);

	/* CLEANUP */
//	const skip_node_t *skip_node = skip_first(node->rrsets);

	const knot_rrset_t **node_rrsets = knot_node_rrsets(node);
	for (int i = 0; i < rrset_count; i++)
	{
		knot_rrset_dump_binary(node_rrsets[i], data, 1,
		                       stream, stream_size, crc);
	}

	/* CLEANUP */
//	if (skip_node == NULL) {
//		/* we can return, count is set to 0 */
//		return;
//	}

//	knot_rrset_t *tmp;

//	do {
//		tmp = (knot_rrset_t *)skip_node->value;
//		knot_rrset_dump_binary(tmp, data, 1);
//	} while ((skip_node = skip_next(skip_node)) != NULL);

	free(node_rrsets);

	dbg_zdump("Position after all rrsets: %ld\n", ftell(f));
	dbg_zdump("Writing here: %ld\n", ftell(f));
	dbg_zdump("Function ends with: %ld\n\n", ftell(f));
}

/*!
 * \brief Checks if zone uses DNSSEC and/or NSEC3
 *
 * \param zone Zone to be checked.
 *
 * \retval 0 if zone is not secured.
 * \retval 2 if zone uses NSEC3
 * \retval 1 if zone uses NSEC
 */
static int zone_is_secure(knot_zone_contents_t *zone)
{
	if (knot_node_rrset(knot_zone_contents_apex(zone),
			      KNOT_RRTYPE_DNSKEY) == NULL) {
		return 0;
	} else {
		if (knot_node_rrset(knot_zone_contents_apex(zone),
				      KNOT_RRTYPE_NSEC3PARAM) != NULL) {
			return 2;
		} else {
			return 1;
		}
	}
}

/*!
 * \brief Checks if last node in NSEC/NSEC3 chain points to first node in the
 *        chain and prints possible errors.
 *
 * \param handler Semantic error handler.
 * \param zone Current zone.
 * \param last_node Last node in NSEC/NSEC3 chain.
 * \param do_checks Level of semantic checks.
 */
static void log_cyclic_errors_in_zone(err_handler_t *handler,
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

		/* This is why allocate maximum length of decoded string + 1 */
		memmove(next_dname_decoded + 1, next_dname_decoded, real_size);
		next_dname_decoded[0] = real_size;

		/* Local allocation, will be discarded. */
		knot_dname_t *next_dname =
			knot_dname_new_from_wire(next_dname_decoded,
						   real_size + 1, NULL);
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
			err_handler_handle_error(handler, last_nsec3_node,
						 ZC_ERR_NSEC3_RDATA_CHAIN);
		}

		/* Compare with the actual first NSEC3 node. */
		if (knot_dname_compare(first_nsec3_node->owner,
		                         next_dname) != 0) {
			err_handler_handle_error(handler, last_nsec3_node,
						 ZC_ERR_NSEC3_RDATA_CHAIN);
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

/*!
 * \brief Safe wrapper around fwrite.
 *
 * \param dst Destination pointer.
 * \param size Size of element to be written.
 * \param n Number of elements to be written.
 * \param fp File to write to.
 *
 * \retval > 0 if succesfull.
 * \retval 0 if failed.
 */
//static inline int fwrite_wrapper_safe(const void *src,
//                                      size_t size, size_t n, FILE *fp)
//{
//	int rc = fwrite_wrapper(src, size, n, fp);
//	if (rc != n) {
//		fprintf(stderr, "fwrite_wrapper: invalid write %d (expected %zu)\n", rc,
//			n);
//	}

//	return rc == n;
//}

static void dump_dname_from_tree(knot_dname_t *dname,
				 void *data)
{
	arg_t *arg = (arg_t *)data;
	FILE *f = (FILE *)arg->arg1;
	crc_t *crc = (crc_t*)arg->arg2;
	dump_dname_with_id(dname, f, NULL, NULL, crc);
}

static int knot_dump_dname_table(const knot_dname_table_t *dname_table,
				   FILE *f, crc_t *crc)
{
	arg_t arg;
	arg.arg1 = f;
	arg.arg2 = crc;
	/* Go through the tree and dump each dname along with its ID. */
	knot_dname_table_tree_inorder_apply(dname_table,
					    dump_dname_from_tree, &arg);
	/* CLEANUP */
//	TREE_FORWARD_APPLY(dname_table->tree, dname_table_node, avl,
//			   dump_dname_from_tree, (void *)f);

	return KNOT_EOK;
}

static void save_node_from_tree(knot_node_t *node, void *data)
{
	arg_t *arg = (arg_t *)data;
	/* Increment node count */
	(*((uint32_t *)(arg->arg1)))++;
	/* Save the first node only */
	if (arg->arg2 == NULL) {
		arg->arg2 = (void *)node;
	}
	arg->arg3 = (void *)node;
}

static void dump_node_to_file(knot_node_t *node, void *data)
{
	arg_t *arg = (arg_t *)data;
	knot_node_dump_binary(node, data, NULL, NULL, (crc_t *)arg->arg7);
}

int knot_zdump_binary(knot_zone_contents_t *zone, const char *filename,
			int do_checks, const char *sfilename)
{
	/* Open .new file. */
	char new_path[strlen(filename) + strlen(".new") + 1];
	memcpy(new_path, filename, strlen(filename) + 1);
	strcat(new_path, ".new");
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int fd = open(new_path, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (fd == -1) {
		return KNOT_EBADARG;
	}

	FILE *f = fdopen(fd, "wb");
	assert(f);

	/* CLEANUP */
//	skip_list_t *encloser_list = skip_create_list(compare_pointers);
	arg_t arguments;
	/* Memory to be derefenced in the save_node_from_tree function. */
	uint32_t node_count = 0;
	arguments.arg1 = &node_count;
	arguments.arg2 = NULL;

	/* Count number of normal nodes. */
	knot_zone_contents_tree_apply_inorder(zone, save_node_from_tree, &arguments);
	/* arg1 is now count of normal nodes */
	uint32_t normal_node_count = *((uint32_t *)arguments.arg1);

	node_count = 0;
	arguments.arg1 = &node_count;
	arguments.arg2 = NULL;

	/* Count number of NSEC3 nodes. */
	knot_zone_contents_nsec3_apply_inorder(zone, save_node_from_tree, &arguments);
	uint32_t nsec3_node_count = *((uint32_t *)arguments.arg1);
	/* arg2 is the first NSEC3 node - used in sem checks. */
	/* arg3 is the last NSEC3 node - used in sem checks. */
	const knot_node_t *first_nsec3_node = (knot_node_t *)arguments.arg2;
	const knot_node_t *last_nsec3_node = (knot_node_t *)arguments.arg3;

	if (do_checks && zone_is_secure(zone)) {
		do_checks += zone_is_secure(zone);
	}

	err_handler_t *handler = NULL;

	if (do_checks) {
		handler = handler_new(1, 0, 1, 1, 1);
		if (handler == NULL) {
			/* disable checks and we can continue */
			do_checks = 0;
		} else { /* Do check for SOA right now */
			if (knot_node_rrset(knot_zone_contents_apex(zone),
					      KNOT_RRTYPE_SOA) == NULL) {
				err_handler_handle_error(handler,
							 knot_zone_contents_apex(zone),
							 ZC_ERR_MISSING_SOA);
			}
		}

		knot_node_t *last_node = NULL;

		zone_do_sem_checks(zone, do_checks, handler, &last_node);
		log_cyclic_errors_in_zone(handler, zone, last_node,
		                          first_nsec3_node, last_nsec3_node,
		                          do_checks);
		err_handler_log_all(handler);
		free(handler);
	}

	crc_t crc = crc_init();

	/* Start writing header - magic bytes. */
	static const uint8_t MAGIC[MAGIC_LENGTH] = MAGIC_BYTES;
	fwrite_wrapper(&MAGIC, sizeof(uint8_t), MAGIC_LENGTH, f, NULL, NULL,
	               &crc);

	/* Write source file length. */
	uint32_t sflen = 0;
	if (sfilename) {
		sflen = strlen(sfilename) + 1;
	}
	fwrite_wrapper(&sflen, sizeof(uint32_t), 1, f, NULL, NULL, &crc);

	/* Write source file. */
	fwrite_wrapper(sfilename, sflen, 1, f, NULL, NULL, &crc);

	/* Notice: End of header,
	 */

	/* Start writing compiled data. */
	fwrite_wrapper(&normal_node_count, sizeof(normal_node_count), 1, f,
	               NULL, NULL, &crc);
	fwrite_wrapper(&nsec3_node_count, sizeof(nsec3_node_count), 1, f,
	               NULL, NULL, &crc);
	uint32_t auth_node_count = zone->node_count;
	fwrite_wrapper(&auth_node_count,
	       sizeof(auth_node_count), 1, f, NULL, NULL, &crc);

	/* Write total number of dnames */
	assert(zone->dname_table);
	uint32_t total_dnames = zone->dname_table->id_counter;
	fwrite_wrapper(&total_dnames,
	       sizeof(total_dnames), 1, f, NULL, NULL, &crc);

	/* Write dname table. */
	if (knot_dump_dname_table(zone->dname_table, f, &crc)
	    != KNOT_EOK) {
		return KNOT_ERROR;
	}

	arguments.arg1 = (void *)f;
	arguments.arg3 = zone;
	arguments.arg7 = &crc;

	/* TODO is there a way how to stop the traversal upon error? */
	knot_zone_contents_tree_apply_inorder(zone, dump_node_to_file,
				       (void *)&arguments);

	knot_zone_contents_nsec3_apply_inorder(zone, dump_node_to_file,
					(void *)&arguments);
	fclose(f);

	crc = crc_finalize(crc);
	/* Write CRC to separate .crc file. */
	/*!< \todo There is now function doing this. */
	char *crc_path =
		malloc(sizeof(char) * (strlen(filename) + strlen(".crc") + 1));
	if (unlikely(!crc_path)) {
		close(fd);
		return KNOT_ENOMEM;
	}
	memset(crc_path, 0,
	       sizeof(char) * (strlen(filename) + strlen(".crc") + 1));
	memcpy(crc_path, filename, sizeof(char) * strlen(filename));

	crc_path = strcat(crc_path, ".crc");
	FILE *f_crc = fopen(crc_path, "w");
	if (unlikely(!f_crc)) {
		dbg_zload("knot_zload_open: failed to open '%s'\n",
		                   crc_path);
		close(fd);
		free(crc_path);
		return ENOENT;
	}
	free(crc_path);

	fprintf(f_crc, "%lu\n", (unsigned long)crc);
	fclose(f_crc);

	close(fd);
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	fd = open(filename, O_WRONLY | O_CREAT, mode);
	if (fd == -1) {
		fprintf(stderr, "%s\n", strerror(errno));
		fprintf(stderr, "Could not open destination file! Use '%s' "
		        "file instead.\n", new_path);
		return KNOT_ERROR;
	}

	/* Try to obtain exclusive lock for originally given file. */
	if (fcntl(fd, F_SETLK, knot_file_lock(F_WRLCK, SEEK_SET)) == -1) {
		fprintf(stderr, "Could not lock destination file for write! "
		        "Use '%s' file instead.\n", new_path);
		close(fd);
		return KNOT_ERROR;
	}

	/* Move .new file to original file. */
	if (rename(new_path, filename) != 0) {
		fprintf(stderr, "Could not move to originally given file! "
		        "Use '%s' file instead.\n", new_path);
		close(fd);
		return KNOT_ERROR;
	}

	/* Release the lock. */
	if (fcntl(fd, F_SETLK, knot_file_lock(F_UNLCK, SEEK_SET)) == -1) {
		fprintf(stderr, "Could not unlock destination file!\n");
		return KNOT_ERROR;
	}

	close(fd);

	return KNOT_EOK;
}

int knot_zdump_rrset_serialize(const knot_rrset_t *rrset, uint8_t **stream,
                                 size_t *size)
{
	if (stream == NULL || *stream != NULL || rrset == NULL ||
	    size == NULL) {
		return KNOT_EBADARG;
	}

	*size = 0;
	arg_t arguments;
	memset(&arguments, 0, sizeof(arg_t));

	knot_rrset_dump_binary(rrset, &arguments, 0, stream, size, NULL);

	return KNOT_EOK;
}

static char *knot_zdump_crc_file(const char* filename)
{
	char *crc_path =
		malloc(sizeof(char) * (strlen(filename) +
		strlen(".crc") + 1));
	CHECK_ALLOC_LOG(crc_path, NULL);
	memset(crc_path, 0,
	       sizeof(char) * (strlen(filename) +
	       strlen(".crc") + 1));
	memcpy(crc_path, filename,
	       sizeof(char) * strlen(filename));
	crc_path = strcat(crc_path, ".crc");
	return crc_path;
}

int knot_zdump_dump_and_swap(knot_zone_contents_t *zone,
                             const char *temp_zonedb,
                             const char *destination_zonedb,
                             const char *sfilename)
{
	int rc = knot_zdump_binary(zone, temp_zonedb, 0, sfilename);

	if (rc != KNOT_EOK) {
		dbg_zdump("Failed to save the zone to binary zone db %s."
		                 "\n", temp_zonedb);
		return KNOT_ERROR;
	}

	/*! \todo this would also need locking as well. */
	rc = remove(destination_zonedb);
	if (rc == 0 || (rc != 0 && errno == ENOENT)) {

		/* Delete old CRC file. */
		char *destination_zonedb_crc =
			knot_zdump_crc_file(destination_zonedb);
		if (destination_zonedb_crc == NULL) {
			return KNOT_ENOMEM;
		}
		remove(destination_zonedb_crc);

		/* Move CRC file. */
		char *temp_zonedb_crc =
			knot_zdump_crc_file(temp_zonedb);
		if (temp_zonedb_crc == NULL) {
			return KNOT_ENOMEM;
		}

		if (rename(temp_zonedb_crc, destination_zonedb_crc) != 0) {
			dbg_zdump("Failed to replace old zonedb CRC %s "
					 "with new CRC zone file %s.\n",
					 destination_zonedb_crc,
					 temp_zonedb_crc);
			return KNOT_ERROR;
		}
		free(temp_zonedb_crc);
		free(destination_zonedb_crc);

		/* Rename zonedb. */
		if (rename(temp_zonedb, destination_zonedb) != 0) {
			dbg_zdump("Failed to replace old zonedb %s "
					 "with new zone file %s.\n",
					 temp_zonedb,
					 destination_zonedb);
			/*! \todo with proper locking, this shouldn't happen,
			 *        revise it later on.
			 */
			return KNOT_ERROR;
		}
	} else {
		dbg_zdump("Failed to replace old zonedb '%s'', %s.\n",
				 destination_zonedb, strerror(errno));
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}
