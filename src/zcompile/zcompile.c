/*!
 * \file zcompile.c
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>. Minor portions of code taken from
 *         NSD.
 *
 * \brief Zone compiler.
 *
 * \addtogroup zoneparser
 * @{
 */

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
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>

#include "common/base32hex.h"
#include "common/log.h"
#include "knot/other/debug.h"
#include "zcompile/zcompile.h"
#include "zcompile/parser-util.h"
#include "zcompile/zcompile-error.h"
#include "knot/zone/zone-dump.h"
#include "libknot/zone/zone-diff.h"
#include "libknot/rrset.h"
#include "libknot/util/utils.h"
#include "zscanner/file_loader.h"


struct parser {
	rrset_list_t *node_rrsigs;
	knot_zone_contents_t *current_zone;
	knot_rrset_t *current_rrset;
	knot_dname_t *origin_from_config;
	knot_node_t *last_node;
};

typedef struct parser parser_t;

/*!
 * \brief Adds RRSet to list.
 *
 * \param head Head of list.
 * \param rrsig RRSet to be added.
 */
static int rrset_list_add(rrset_list_t **head, knot_rrset_t *rrsig)
{
	if (*head == NULL) {
		*head = malloc(sizeof(rrset_list_t));
		if (*head == NULL) {
			ERR_ALLOC_FAILED;
			return KNOTDZCOMPILE_ENOMEM;
		}
		(*head)->next = NULL;
		(*head)->data = rrsig;
	} else {
		rrset_list_t *tmp = malloc(sizeof(*tmp));
		if (tmp == NULL) {
			ERR_ALLOC_FAILED;
			return KNOTDZCOMPILE_ENOMEM;
		}
		tmp->next = *head;
		tmp->data = rrsig;
		*head = tmp;
	}
	
	dbg_zp_verb("zp: rrset_add: Added RRSIG %p to list.\n", rrsig);

	return KNOTDZCOMPILE_EOK;
}

/*!
 * \brief Deletes RRSet list. Sets pointer to NULL.
 *
 * \param head Head of list to be deleted.
 */
static void rrset_list_delete(rrset_list_t **head)
{
	rrset_list_t *tmp;
	if (*head == NULL) {
		return;
	}

	while (*head != NULL) {
		tmp = *head;
		*head = (*head)->next;
		free(tmp);
	}

	*head = NULL;
	
	dbg_zp("zp: list_delete: List deleleted.\n");
}

static int find_rrset_for_rrsig_in_node(knot_zone_contents_t *zone,
                                 knot_node_t *node,
                                 knot_rrset_t *rrsig)
{
	assert(node);

	assert(knot_dname_compare(rrsig->owner, node->owner) == 0);

	knot_rrset_t *tmp_rrset =
		knot_node_get_rrset(node,
	                            knot_rrset_rdata_rrsig_type_covered(rrsig));

	int ret;

	if (tmp_rrset == NULL) {
		dbg_zp("zp: find_rr_for_sig_in_node: Node does not contain "
		       "RRSet of type %s.\n",
		       knot_rrtype_to_string(rrsig_type_covered(rrsig)));
		tmp_rrset = knot_rrset_new(rrsig->owner,
		                           knot_rrset_rdata_rrsig_type_covered(rrsig),
		                           rrsig->rclass,
		                           rrsig->ttl);
		if (tmp_rrset == NULL) {
			dbg_zp("zp: find_rr_for_sig_in_node: Cannot create "
			       "dummy RRSet.\n");
			return KNOT_ERROR;
		}

		ret = knot_zone_contents_add_rrset(zone, tmp_rrset, &node,
		                                   KNOT_RRSET_DUPL_MERGE, 1);
		assert(ret <= 0);
		if (ret < 0) {
			dbg_zp("zp: Failed to add new dummy RRSet to the zone."
			       "\n");
			return KNOT_ERROR;
		}
	}
	
	assert(tmp_rrset);
	
	if (tmp_rrset->ttl != rrsig->ttl) {
		char *name = knot_dname_to_str(tmp_rrset->owner);
		assert(name);
		log_zone_warning("RRSIG owned by: %s cannot be added to "
		                 "its RRSet, because their TTLs differ. "
		                 "Changing TTL to value=%d.\n",
		                 name, tmp_rrset->ttl);
		free(name);
	}

	ret = knot_zone_contents_add_rrsigs(zone, rrsig, &tmp_rrset, &node,
			                    KNOT_RRSET_DUPL_MERGE, 1);
	if (ret < 0) {
		dbg_zp("zp: find_rr_for_sig: Cannot add RRSIG.\n");
		return KNOTDZCOMPILE_EINVAL;
	} else if (ret > 0) {
		knot_rrset_free(&rrsig);
	}

	assert(tmp_rrset->rrsigs != NULL);

	return KNOTDZCOMPILE_EOK;
}

static knot_node_t *create_node(knot_zone_contents_t *zone,
	knot_rrset_t *current_rrset,
	int (*node_add_func)(knot_zone_contents_t *zone, knot_node_t *node,
	                     int create_parents, uint8_t, int),
	knot_node_t *(*node_get_func)(const knot_zone_contents_t *zone,
					const knot_dname_t *owner))
{
	dbg_zp_verb("zp: create_node: Creating node using RRSet: %p.\n",
	            current_rrset);
	knot_node_t *node =
		knot_node_new(current_rrset->owner, NULL, 0);
	if (node_add_func(zone, node, 1, 0, 1) != 0) {
		return NULL;
	}

	current_rrset->owner = node->owner;

	return node;
}

static void process_rrsigs_in_node(parser_t *parser,
                                   knot_zone_contents_t *zone,
                                   knot_node_t *node)
{
	dbg_zp_verb("zp: process_rrsigs: Processing RRSIGS in node: %p.\n",
	            node);
	rrset_list_t *tmp = parser->node_rrsigs;
	while (tmp != NULL) {
		if (find_rrset_for_rrsig_in_node(zone, node,
						 tmp->data) != KNOT_EOK) {
			fprintf(stderr, "Could not add RRSIG to zone!\n");
			return;
		}
		tmp = tmp->next;
	}
}

void process_error(const scanner_t *scanner)
{
	fprintf(stderr, "GODS! There's been an error!\n");
}

int add_rdata_to_rr(knot_rrset_t *rrset, const scanner_t *scanner)
{
	if (rrset == NULL) {
		dbg_zp("zp: add_rdata_to_rr: No RRSet.\n");
		return KNOT_EINVAL;
	}
	
	const rdata_descriptor_t *desc =
		get_rdata_descriptor(knot_rrset_type(rrset));
	assert(desc);
	
	/* TODO it needs to return size as well!. */
	/* A good idea might be, once we know, what the size of say, RRSIGs will be, its not gonna change, so we can store it somewhere to further speedup processing. */
	uint8_t *rdata = knot_rrset_rdata_prealloc(rrset);
	size_t offset = 0;
	
	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		int item = desc->block_types[i];
		if (descriptor_item_is_dname(item)) {
			/* TODO another function perhaps? */
			knot_dname_t *dname =
				knot_dname_new_from_wire(scanner->r_data +
			                                 scanner->r_data_blocks[i],
			                                 scanner->r_data_blocks[i + 1] - scanner->r_data_blocks[i],
			                                 NULL);
			if (dname == NULL) {
				printf("Dname failed\n.");
				//TODO handle
				return KNOT_ERROR;
			}
			
			memcpy(rdata + offset, &dname, sizeof(knot_dname_t *));
			offset += sizeof(knot_dname_t *);
			//parse dname from binary
		} else if (descriptor_item_is_fixed(item)) {
			//copy the whole thing
			// TODO check the size
			memcpy(rdata + offset,
			       scanner->r_data + scanner->r_data_blocks[i],
			       scanner->r_data_blocks[i + 1] -
			       scanner->r_data_blocks[i]);
			offset += scanner->r_data_blocks[i + 1] -
			          scanner->r_data_blocks[i];
		} else if (descriptor_item_is_remainder(item)) {
			//copy the rest
			memcpy(rdata + offset,
			       scanner->r_data + scanner->r_data_blocks[i],
			       scanner->r_data_blocks[i + 1] -
			       scanner->r_data_blocks[i]);
			offset += scanner->r_data_blocks[i + 1] -
			          scanner->r_data_blocks[i];
		} else {
			//NAPTR
			assert(knot_rrset_type(rrset) == KNOT_RRTYPE_NAPTR);
			assert(0);
		}
	}
	
	int ret = knot_rrset_add_rdata(rrset, rdata, offset);
	if (ret != KNOT_EOK) {
		dbg_zp("zp: add_rdat_to_rr: Could not add RR. Reason: %s.\n",
		       knot_strerror(ret));
		return ret;
	}
	
	printf("Data ok\n");
	
	return KNOT_EOK;
}

void process_rr(const scanner_t *scanner)
{
	
	parser_t *parser = scanner->data;
	knot_zone_contents_t *contents = parser->current_zone;
	/* Create rrset. TODO will not be always needed. */
	knot_dname_t *current_owner =
	                knot_dname_new_from_wire(scanner->r_owner,
	                                         scanner->r_owner_length,
	                                         NULL);
	assert(current_owner);
	knot_rrset_t *current_rrset = knot_rrset_new(current_owner, scanner->r_type,
	                                       scanner->r_class,
	                                       scanner->r_ttl);
	assert(current_rrset);
	parser->current_rrset = current_rrset;
	knot_rrset_t *rrset;
	
	int ret = add_rdata_to_rr(current_rrset, scanner);
	assert(ret == 0);

dbg_zp_exec_detail(
	char *name = knot_dname_to_str(parser->current_rrset->owner);
	dbg_zp_detail("zp: process_rr: Processing RR owned by: %s .\n",
	              name);
	free(name);
);
	dbg_zp_verb("zp: process_rr: Processing type: %s.\n",
	            knot_rrtype_to_string(parser->current_rrset->type));
	dbg_zp_verb("zp: process_rr: RDATA count: %d.\n",\
	            parser->current_rrset->rdata->count);

//	if (descriptor->fixed_items) {
//		assert(current_rrset->rdata->count == descriptor->length);
//	}


	assert(current_rrset->rdata_count);
	assert(knot_dname_is_fqdn(current_rrset->owner));

	int (*node_add_func)(knot_zone_contents_t *, knot_node_t *, int,
	                     uint8_t, int);
	knot_node_t *(*node_get_func)(const knot_zone_contents_t *,
	                                const knot_dname_t *);


	/* If we have RRSIG of NSEC3 type first node will have
	 * to be created in NSEC3 part of the zone */

	uint16_t type_covered = 0;
	if (current_rrset->type == KNOT_RRTYPE_RRSIG) {
		type_covered =
			knot_rrset_rdata_rrsig_type_covered(current_rrset);
	}

	if (current_rrset->type != KNOT_RRTYPE_NSEC3 &&
	    type_covered != KNOT_RRTYPE_NSEC3) {
		node_add_func = &knot_zone_contents_add_node;
		node_get_func = &knot_zone_contents_get_node;
	} else {
		node_add_func = &knot_zone_contents_add_nsec3_node;
		node_get_func = &knot_zone_contents_get_nsec3_node;
	}

	if (current_rrset->type == KNOT_RRTYPE_SOA) {
		if (knot_node_rrset(knot_zone_contents_apex(contents),
		                      KNOT_RRTYPE_SOA) != NULL) {
			/* Receiving another SOA. */
			if (!knot_rrset_compare(current_rrset,
			    knot_node_rrset(knot_zone_contents_apex(contents),
			    KNOT_RRTYPE_SOA), KNOT_RRSET_COMPARE_WHOLE)) {
				return KNOTDZCOMPILE_ESOA;
			} else {
				fprintf(stderr, "encountered identical "
				                     "extra SOA record");
				return KNOTDZCOMPILE_EOK;
			}
		}
	}

	/*!< \todo Make sure the maximum RDLENGTH does not exceed 65535 bytes.*/

	if (current_rrset->type == KNOT_RRTYPE_SOA) {
		if (knot_dname_compare(current_rrset->owner,
					parser->origin_from_config) != 0) {
			fprintf(stderr, "SOA record has a different "
				"owner than the one specified "
				"in config! \n");
			/* Such SOA cannot even be added, because
			 * it would not be in the zone apex. */
			return KNOTDZCOMPILE_EBADSOA;
		}
	}

	if (current_rrset->type == KNOT_RRTYPE_RRSIG) {
		/*!< \todo Use deep copy function here! */
		knot_rrset_t *tmp_rrsig = NULL;
		int ret = knot_rrset_deep_copy(current_rrset, &tmp_rrsig, 1);
		if (ret != KNOT_EOK) {
			dbg_zp("zp: Cannot copy RRSet.\n");
			return ret;
		}
//		knot_rrset_t *tmp_rrsig =
//			knot_rrset_new(current_rrset->owner,
//					     KNOT_RRTYPE_RRSIG,
//					     current_rrset->rclass,
//					     current_rrset->ttl);
//		if (tmp_rrsig == NULL) {
//			dbg_zp("zp: process_rr: Cannot create tmp RRSIG.\n");
//			return KNOTDZCOMPILE_ENOMEM;
//		}

//		if (knot_rrset_add_rdata(tmp_rrsig,
//		                         current_rrset->rdata,
//		                         knot_rrset_rdata_length()) != KNOT_EOK) {
//			knot_rrset_free(&tmp_rrsig);
//			dbg_zp("zp: process_rr: Cannot add data to tmp"
//			       " RRSIG.\n");
//			return KNOTDZCOMPILE_EBRDATA;
//		}

		if (parser->last_node &&
		    knot_dname_compare(parser->last_node->owner,
		                         current_rrset->owner) != 0) {
			/* RRSIG is first in the node, so we have to create it
			 * before we return
			 */
			if (parser->node_rrsigs != NULL) {
				process_rrsigs_in_node(parser,
				                       contents,
				                       parser->last_node);
				rrset_list_delete(&parser->node_rrsigs);
			}
			
			/* The node might however been created previously. */
			parser->last_node =
				knot_zone_contents_get_node(contents,
					knot_rrset_owner(current_rrset));
			
			if (parser->last_node == NULL) {
				/* Try NSEC3 tree. */
				parser->last_node =
					knot_zone_contents_get_nsec3_node(
						contents,
						knot_rrset_owner(
							current_rrset));
			}
			
			if (parser->last_node == NULL) {
				/* Still NULL, node has to be created. */
				if ((parser->last_node = create_node(contents,
				                                     current_rrset, node_add_func,
				                                     node_get_func)) == NULL) {
					knot_rrset_free(&tmp_rrsig);
					dbg_zp("zp: process_rr: Cannot "
					       "create new node.\n");
					return KNOTDZCOMPILE_EBADNODE;
				}
			}
		}

		if (rrset_list_add(&parser->node_rrsigs, tmp_rrsig) != 0) {
			dbg_zp("zp: process_rr: Cannot "
			       "create new node.\n");
			return KNOTDZCOMPILE_ENOMEM;
		}
		
		dbg_zp_verb("zp: process_rr: RRSIG proccesed successfully.\n");
		return KNOTDZCOMPILE_EOK;
	}
	
	/*! \todo Move RRSIG and RRSet handling to funtions. */
	assert(current_rrset->type != KNOT_RRTYPE_RRSIG);

	knot_node_t *node = NULL;
	/* \note this could probably be much simpler */
	if (parser->last_node && current_rrset->type != KNOT_RRTYPE_SOA &&
	    knot_dname_compare(parser->last_node->owner,
				 current_rrset->owner) ==
	    0) {
		node = parser->last_node;
	} else {
		if (parser->last_node && parser->node_rrsigs) {
			process_rrsigs_in_node(parser,
			                       contents,
			                       parser->last_node);
		}

		rrset_list_delete(&parser->node_rrsigs);

		/* new node */
		node = node_get_func(contents, current_rrset->owner);
	}

	if (node == NULL) {
		if (parser->last_node && parser->node_rrsigs) {
			process_rrsigs_in_node(parser,
			                       contents,
			                       parser->last_node);
		}

		if ((node = create_node(contents, current_rrset,
					node_add_func,
					node_get_func)) == NULL) {
			dbg_zp("zp: process_rr: Cannot "
			       "create new node.\n");
			return KNOTDZCOMPILE_EBADNODE;
		}
	}

	rrset = knot_node_get_rrset(node, current_rrset->type);
	if (!rrset) {
		int ret = knot_rrset_deep_copy(current_rrset, &rrset, 1);
		if (ret != KNOT_EOK) {
			dbg_zp("zp: Cannot copy RRSet.\n");
			return ret;
		}
//		rrset = knot_rrset_new(current_rrset->owner,
//					 current_rrset->type,
//					 current_rrset->rclass,
//					 current_rrset->ttl);
//		if (rrset == NULL) {
//			dbg_zp("zp: process_rr: Cannot "
//			       "create new RRSet.\n");
//			return KNOTDZCOMPILE_ENOMEM;
//		}

//		if (knot_rrset_add_rdata(rrset, current_rrset->rdata) != 0) {
//			knot_rrset_free(&rrset);
//			dbg_zp("zp: process_rr: Cannot "
//			       "add RDATA to RRSet.\n");
//			return KNOTDZCOMPILE_EBRDATA;
//		}
		
		/* Selected merge option does not really matter here. */
		if (knot_zone_contents_add_rrset(contents, rrset, &node,
		                   KNOT_RRSET_DUPL_MERGE, 1) < 0) {
			knot_rrset_free(&rrset);
			dbg_zp("zp: process_rr: Cannot "
			       "add RDATA to RRSet.\n");
			return KNOTDZCOMPILE_EBRDATA;
		}
	} else {
		if (current_rrset->type !=
				KNOT_RRTYPE_RRSIG && rrset->ttl !=
				current_rrset->ttl) {
			fprintf(stderr, 
				"TTL does not match the TTL of the RRSet. "
				"Changing to %d.\n", rrset->ttl);
		}

		if (knot_zone_contents_add_rrset(contents, current_rrset,
		                          &node,
		                   KNOT_RRSET_DUPL_MERGE, 1) < 0) {
			dbg_zp("zp: process_rr: Cannot "
			       "merge RRSets.\n");
			return KNOTDZCOMPILE_EBRDATA;
		}
	}

	parser->last_node = node;
	
	dbg_zp_verb("zp: process_rr: RRSet %p processed successfully.\n",
	            parser->current_rrset);
	return KNOTDZCOMPILE_EOK;
}

int zone_read(const char *name, const char *zonefile, const char *outfile,
	      int semantic_checks)
{
	knot_zone_t *zone;
	parser_t my_parser;
	my_parser.origin_from_config = knot_dname_new_from_str(name,
	                                                       strlen(name),
	                                                       NULL);
	assert(my_parser.origin_from_config);
	my_parser.last_node = knot_node_new(my_parser.origin_from_config,
	                                    NULL, 0);
	my_parser.current_zone = knot_zone_contents_new(my_parser.last_node,
	                                                0, 0, zone);
	file_loader_t* file_loader_create(const char	 *file_name,
					  const char	 *zone_origin,
					  const uint16_t default_class,
					  const uint32_t default_ttl,
					  void (*process_record)(const scanner_t *),
					  void (*process_error)(const scanner_t *),
					  void *data);
	file_loader_t *loader = file_loader_create(zonefile, name,
	                                           KNOT_CLASS_IN, 3600,
	                                           process_rr,
	                                           process_error, &my_parser);
	file_loader_process(loader);
	printf("Done?\n");
}

/*! @} */
