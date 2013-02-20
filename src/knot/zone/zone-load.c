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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#include "common/crc.h"
#include "libknot/common.h"
#include "knot/other/debug.h"
#include "knot/zone/zone-load.h"
#include "libknot/libknot.h"
#include "zscanner/file_loader.h"

/*!
 * \brief Compares two time_t values.
 *
 * \param x First time_t value to be compared.
 * \param y Second time_t value to be compared.
 *
 * \retval 0 when times are the some.
 * \retval 1 when x > y.
 * \retval -1 when x < y.
 */
/*static int timet_cmp(time_t x, time_t y)
{
	if (x > y) return 1;
	if (x < y) return -1;
	return 0;
}
*/

/* ZONE LOADING FROM FILE USING RAGEL PARSER */


// TODO remove once debugging is done
static long rr_count = 0;
static long new_rr_count = 0;
static long new_dname_count = 0;
static long err_count = 0;


/*!
 * \brief Adds RRSet to list.
 *
 * \param head Head of list.
 * \param rrsig RRSet to be added.
 */
static int rrset_list_add(rrset_list_t **head, knot_rrset_t *rrsig)
{
	if (*head == NULL) {
		*head = xmalloc(sizeof(rrset_list_t));
		(*head)->next = NULL;
		(*head)->data = rrsig;
	} else {
		rrset_list_t *tmp = xmalloc(sizeof(*tmp));
		tmp->next = *head;
		tmp->data = rrsig;
		*head = tmp;
	}
	
	dbg_zp_verb("zp: rrset_add: Added RRSIG %p to list.\n", rrsig);

	return KNOT_EOK;
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
		       "RRSet of type %d.\n",
		       knot_rrset_rdata_rrsig_type_covered(rrsig));
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
		log_zone_warning("RRSIG owned by: %s (covering type %d) cannot be added to "
		                 "its RRSet, because their TTLs differ. "
		                 "Changing TTL=%d to value=%d.\n",
		                 name, knot_rrset_rdata_rrsig_type_covered(rrsig),
		                 rrsig->ttl, tmp_rrset->ttl);
		free(name);
	}

	ret = knot_zone_contents_add_rrsigs(zone, rrsig, &tmp_rrset, &node,
			                    KNOT_RRSET_DUPL_MERGE, 1);
	if (ret < 0) {
		dbg_zp("zp: find_rr_for_sig: Cannot add RRSIG.\n");
		return KNOT_EINVAL;
	} else if (ret > 0) {
		knot_rrset_deep_free(&rrsig, 0, 0);
	}
	
	knot_dname_release(tmp_rrset->owner);

	assert(tmp_rrset->rrsigs != NULL);

	return KNOT_EOK;
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
	
	assert(current_rrset->owner == node->owner);

	return node;
}

static void process_rrsigs_in_node(parser_context_t *parser,
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

static void process_error(const scanner_t *s)
{
	err_count++;
	if (s->stop == true) {
		log_zone_error("FATAL ERROR=%s on line=%"PRIu64"\n",
		               knot_strerror(s->error_code), s->line_counter);
	} else {
		log_zone_error("ERROR=%s on line=%"PRIu64"\n",
		               knot_strerror(s->error_code), s->line_counter);
	}
	fflush(stdout);
}

// TODO this could be a part of the cycle below, but we'd need a buffer.
static size_t calculate_item_size(const knot_rrset_t *rrset,
                               const scanner_t *scanner)
{
	const rdata_descriptor_t *desc = get_rdata_descriptor(rrset->type);
	assert(desc);
	size_t size = 0;
	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		int item = desc->block_types[i];
		if (descriptor_item_is_dname(item)) {
			size += sizeof(knot_dname_t *);
		} else if (descriptor_item_is_fixed(item)) {
			assert(item == scanner->r_data_blocks[i + 1] -
			       scanner->r_data_blocks[i]);
			size += item;
		} else if (descriptor_item_is_remainder(item)) {
			size += scanner->r_data_blocks[i + 1] -
			        scanner->r_data_blocks[i];
		} else {
			//naptr
			assert(0);
		}
	}
	
	return size;
}

static int add_rdata_to_rr(knot_rrset_t *rrset, const scanner_t *scanner)
{
	if (rrset == NULL) {
		dbg_zp("zp: add_rdata_to_rr: No RRSet.\n");
		return KNOT_EINVAL;
	}
	
	const rdata_descriptor_t *desc =
		get_rdata_descriptor(knot_rrset_type(rrset));
	assert(desc);
	
	dbg_zp_detail("zp: add_rdata_to_rr: Adding type %d, RRSet has %d RRs.\n",
	              rrset->type, rrset->rdata_count);
	
	size_t rdlen = calculate_item_size(rrset, scanner);
	size_t offset = 0;
	uint8_t *rdata = knot_rrset_create_rdata(rrset, rdlen);
	if (rdata == NULL) {
		dbg_zp("zp: create_rdata: Could not create RR.\n");
		return KNOT_ENOMEM;
	}
	
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
				//TODO handle
				return KNOT_ERROR;
			}
dbg_zp_exec_detail(
			char *name = knot_dname_to_str(dname);
			dbg_zp_detail("zp: arr_rdata_to_rr: "
			              "Offset=%d:Adding dname=%s (%p)\n",
			              offset, name, dname);
			free(name);
);
			memcpy(rdata + offset, &dname, sizeof(knot_dname_t *));
			offset += sizeof(knot_dname_t *);
			//parse dname from binary
		} else if (descriptor_item_is_fixed(item)) {
			//copy the whole thing
			// TODO check the size
			assert(item == scanner->r_data_blocks[i + 1] -
			       scanner->r_data_blocks[i]);
			memcpy(rdata + offset,
			       scanner->r_data + scanner->r_data_blocks[i],
			       item);
			offset += item;
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
	
	return KNOT_EOK;
}

static void process_rr(const scanner_t *scanner)
{
	dbg_zp_detail("Owner from parser=%s\n",
	              scanner->r_owner);
	rr_count++;
	char add = 0;
	parser_context_t *parser = scanner->data;
	knot_zone_contents_t *contents = parser->current_zone;
	/* Create rrset. TODO will not be always needed. */
	knot_dname_t *current_owner = NULL;
	knot_rrset_t *current_rrset = NULL;
	if (parser->last_node &&
	    (scanner->r_owner_length == parser->last_node->owner->size) &&
	    (strncmp((char *)parser->last_node->owner->name,
	            (char *)scanner->r_owner, scanner->r_owner_length) == 0)) {
		// no need to create new dname;
		current_owner = parser->last_node->owner;
		// what about RRSet, do we need a new one?
		current_rrset = knot_node_get_rrset(parser->last_node,
		                                    scanner->r_type);
		if (current_rrset == NULL) {
			add = 1;
			new_rr_count++	;
			current_rrset =
				knot_rrset_new(current_owner,
				               scanner->r_type,
				               scanner->r_class,
				               scanner->r_ttl);
		}
	} else {
		add = 1;
//		if (strncmp((char *)parser->last_node->owner->name,
//	                (char *)scanner->r_owner, scanner->r_owner_length)) {
//			new_dname_count++;
//			current_owner = 
//		                knot_dname_new_from_wire(scanner->r_owner,
//	                                         scanner->r_owner_length,
//	                                         NULL);
//		} else {
//			current_owner = parser->last_node->owner;
//		}
		current_owner = 
			knot_dname_new_from_wire(scanner->r_owner,
			                         scanner->r_owner_length,
			                         NULL);
		new_rr_count++;
		new_dname_count++;
		current_rrset =
			knot_rrset_new(current_owner,
			               scanner->r_type,
			               scanner->r_class,
			               scanner->r_ttl);
		knot_dname_release(current_owner);
	}
	
	assert(current_owner);
	parser->current_rrset = current_rrset;
	assert(current_rrset);
	
	int ret = add_rdata_to_rr(current_rrset, scanner);
	assert(ret == 0);
	
	dbg_zp_verb("zp: process_rr: Processing type: %s.\n",
	            knot_rrtype_to_string(parser->current_rrset->type));
	dbg_zp_verb("zp: process_rr: RDATA count: %d.\n",\
	            parser->current_rrset->rdata->count);

	assert(current_rrset->rdata_count);

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
			if (!knot_rrset_equal(current_rrset,
			    knot_node_rrset(knot_zone_contents_apex(contents),
			    KNOT_RRTYPE_SOA), KNOT_RRSET_COMPARE_WHOLE)) {
				log_zone_error("Extra SOA record in the "
				               "zone.\n");
				/*!< \todo consider a new error */
				parser->ret = KNOT_EBADZONE;
				return;
			} else {
				log_zone_warning("encountered identical "
				                 "extra SOA record");
				parser->ret = KNOT_EOK;
				return;
			}
		}
	}

	/*!< \todo Make sure the maximum RDLENGTH does not exceed 65535 bytes.*/

	if (current_rrset->type == KNOT_RRTYPE_SOA) {
		if (knot_dname_compare(current_rrset->owner,
					parser->origin_from_config) != 0) {
			log_zone_error("SOA record has a different "
				"owner than the one specified "
				"in config! \n");
			/* Such SOA cannot even be added, because
			 * it would not be in the zone apex. */
			/*!< \todo consider a new error */
			parser->ret = KNOT_EBADZONE;
			return;
		}
	}

	if (current_rrset->type == KNOT_RRTYPE_RRSIG) {
		knot_rrset_t *tmp_rrsig = current_rrset;

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
				if (current_rrset->type == KNOT_RRTYPE_NSEC3 ||
				    current_rrset->type == KNOT_RRTYPE_RRSIG) {
					parser->last_node =
						knot_zone_contents_get_nsec3_node(
							contents,
							knot_rrset_owner(
								current_rrset));
				}
			}
			
			if (parser->last_node == NULL) {
				/* Still NULL, node has to be created. */
				if ((parser->last_node = create_node(contents,
				                                     current_rrset, node_add_func,
				                                     node_get_func)) == NULL) {
					knot_rrset_free(&tmp_rrsig);
					dbg_zp("zp: process_rr: Cannot "
					       "create new node.\n");
					log_zone_error("None cannot be created.\n");
					/*!< \todo consider a new error */
					parser->ret = KNOT_ERROR;
					return;
				}
			}
		}

		if (rrset_list_add(&parser->node_rrsigs, tmp_rrsig) != 0) {
			dbg_zp("zp: process_rr: Cannot "
			       "create new node.\n");
			parser->ret = KNOT_ERROR;
			return;
		}
		
		dbg_zp_verb("zp: process_rr: RRSIG proccesed successfully.\n");
		parser->ret = KNOT_EOK;
		return;
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
			/*!< \todo consider a new error */
			log_zone_error("Cannot create new node.\n");
			parser->ret = KNOT_ERROR;
			return;
		}
	}
	
//	rrset = knot_node_get_rrset(node, current_rrset->type);
//	if (!rrset) {
//		rrset = current_rrset;
//	} else {
//		merged = 1;
//	}
///	if (!rrset) {
//		int ret = knot_rrset_deep_copy(current_rrset, &rrset, 1);
//		if (ret != KNOT_EOK) {
//			dbg_zp("zp: Cannot copy RRSet.\n");
//			return ret;
//		}
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
//		if (knot_zone_contents_add_rrset(contents, current_rrset, &node,
//		                   KNOT_RRSET_DUPL_MERGE, 1) < 0) {
//			knot_rrset_free(&rrset);
//			dbg_zp("zp: process_rr: Cannot "
//			       "add RDATA to RRSet.\n");
//			return KNOTDZCOMPILE_EBRDATA;
//		}
//	} else {
//	TODO needs solving
//	if (current_rrset->type !=
//			KNOT_RRTYPE_RRSIG && rrset->ttl !=
//			current_rrset->ttl) {
//		fprintf(stderr, 
//			"TTL does not match the TTL of the RRSet. "
//			"Changing to %d.\n", rrset->ttl);
//	}

	if (add) {
		ret = knot_zone_contents_add_rrset(contents, current_rrset,
		                                   &node,
		                                   KNOT_RRSET_DUPL_MERGE, 1);
		if (ret < 0) {
			dbg_zp("zp: process_rr: Cannot "
			       "add RRSets.\n");
			/*!< \todo mixed error codes, has to be changed. */
			parser->ret = ret;
			return;
		} else if (ret > 0) {
			knot_rrset_deep_free(&current_rrset, 0, 0);
		}
	}
//	}

	parser->last_node = node;
	
	dbg_zp_verb("zp: process_rr: RRSet %p processed successfully.\n",
	            parser->current_rrset);
	parser->ret = KNOT_EOK;
}

int knot_zload_open(zloader_t **dst, const char *source, const char *origin, 
                    int semantic_checks)
{
	if (!dst || !source || !origin) {
		dbg_zload("zload: open: Bad arguments.\n");
		return KNOT_EINVAL;
	}
	
	*dst = NULL;
	
	/* Check zone file. */
	struct stat st;
	if (stat(source, &st) < 0) {
		return knot_map_errno(errno);
	}
	
	/* Create context. */
	parser_context_t *context = xmalloc(sizeof(parser_context_t));
	context->origin_from_config = knot_dname_new_from_str(origin,
	                                                       strnlen((char *)origin,
	                                                               255),
	                                                       NULL);
	assert(context->origin_from_config);
	context->last_node = knot_node_new(context->origin_from_config,
	                                    NULL, 0);
	knot_zone_t *zone = knot_zone_new(context->last_node, 0, 0);
	context->current_zone = knot_zone_get_contents(zone);
	context->node_rrsigs = NULL;
	
	/* Create file loader. */
	file_loader_t *loader = file_loader_create(source, origin,
	                                           KNOT_CLASS_IN, 3600,
	                                           process_rr,
	                                           process_error,
	                                           context);
	if (loader == NULL) {
		dbg_zload("Could not create file loader.\n");
		return KNOT_ERROR;
	}

	/* Allocate new loader. */
	zloader_t *zl = xmalloc(sizeof(zloader_t));
	
	zl->source = strdup(source);
	zl->origin = strdup(origin);
	zl->file_loader = loader;
	zl->context = context;
	*dst = zl;

	return KNOT_EOK;
}

knot_zone_t *knot_zload_load(zloader_t *loader)
{
	dbg_zload("zload: load: Loading zone, loader: %p.\n", loader);
	if (!loader) {
		dbg_zload("zload: load: NULL loader!\n");
		return NULL;
	}
	
	parser_context_t *c = loader->context;
	assert(c);
	
	file_loader_process(loader->file_loader);
	if (c->last_node && c->node_rrsigs) {
		process_rrsigs_in_node(c, c->current_zone, c->last_node);
	}
	if (c->ret != KNOT_EOK) {
		log_zone_error("Zone could not be loaded (%d).", c->ret);
		/*!< \todo Depending on the error, free stuff. */
		rrset_list_delete(&c->node_rrsigs);
		return NULL;
	}
	
	if (loader->file_loader->scanner->error_counter > 0) {
		log_zone_error("Zone could not be loaded due to %"PRIu64" errors"
		               " encountered.\n",
		               loader->file_loader->scanner->error_counter);
		rrset_list_delete(&c->node_rrsigs);
		knot_zone_t *zone_to_free = c->current_zone->zone;
		knot_zone_contents_deep_free(&c->current_zone);
		zone_to_free->contents = NULL;
		knot_zone_free(&zone_to_free);
		return NULL;
	}
	
	knot_zone_contents_adjust(c->current_zone);
	rrset_list_delete(&c->node_rrsigs);
	
	return c->current_zone->zone;
}

int knot_zload_needs_update(zloader_t *loader)
{
	assert(0);
	if (!loader) {
		return 1;
	}
	
	/* Compare the mtime of the source and file. */
	/*! \todo Inspect types on Linux. */
//	if (timet_cmp(st_bin.st_mtime, st_src.st_mtime) < 0) {
//		return 1;
//	}

	return 0;
}

void knot_zload_close(zloader_t *loader)
{
	if (!loader) {
		return;
	}
	
	file_loader_free(loader->file_loader);

	free(loader->source);
	free(loader->origin);
	free(loader);
}
