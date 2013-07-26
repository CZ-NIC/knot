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
#include "knot/zone/semantic-check.h"
#include "libknot/zone/zone-contents.h"
#include "knot/other/debug.h"
#include "knot/zone/zone-load.h"
#include "zscanner/file_loader.h"

/* ZONE LOADING FROM FILE USING RAGEL PARSER */

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
		                                   KNOT_RRSET_DUPL_MERGE);
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
			                    KNOT_RRSET_DUPL_MERGE);
	if (ret < 0) {
		dbg_zp("zp: find_rr_for_sig: Cannot add RRSIG.\n");
		return KNOT_EINVAL;
	} else if (ret > 0) {
		/* Merged, free data + owner, but not DNAMEs inside RDATA. */
		knot_rrset_deep_free(&rrsig, 1, 0);
	}
	assert(tmp_rrset->rrsigs != NULL);

	return KNOT_EOK;
}

static knot_node_t *create_node(knot_zone_contents_t *zone,
                                knot_rrset_t *current_rrset,
                                int (*node_add_func)(knot_zone_contents_t *zone,
                                                     knot_node_t *node,
                                                     int create_parents, uint8_t))
{
	dbg_zp_verb("zp: create_node: Creating node using RRSet: %p.\n",
	            current_rrset);
	knot_node_t *node =
		knot_node_new(current_rrset->owner, NULL, 0);
	int ret = node_add_func(zone, node, 1, 0);
	if (ret != KNOT_EOK) {
		log_zone_warning("Node could not be added (%s).\n",
		                 knot_strerror(ret));
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
			parser->ret = KNOT_ERROR;
			log_zone_error("Could not add RRSIG to zone!\n");
			return;
		}
		tmp = tmp->next;
	}
}

void process_error(const scanner_t *s)
{
	if (s->stop == true) {
		log_zone_error("Fatal error in zone file %s:%"PRIu64": %s "
		               "Stopping zone loading.\n",
		               s->file_name, s->line_counter,
		               knot_strerror(s->error_code));
	} else {
		log_zone_error("Error in zone file %s:%"PRIu64": %s\n",
		               s->file_name, s->line_counter,
		               knot_strerror(s->error_code));
	}
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
		} else {
			size += scanner->r_data_blocks[i + 1] -
			        scanner->r_data_blocks[i];
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

	parser_context_t *parser = scanner->data;

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
			knot_dname_t *dname =
				knot_dname_new_from_wire(scanner->r_data +
			                                 scanner->r_data_blocks[i],
			                                 scanner->r_data_blocks[i + 1] - scanner->r_data_blocks[i],
			                                 NULL);
			if (dname == NULL) {
				return KNOT_ERROR;
			}
			knot_dname_to_lower(dname);
dbg_zp_exec_detail(
			char *name = knot_dname_to_str(dname);
			dbg_zp_detail("zp: arr_rdata_to_rr: "
			              "Offset=%zu:Adding dname=%s (%p)\n",
			              offset, name, dname);
			free(name);
);
			/* Handle DNAME duplications. */
			knot_zone_contents_insert_dname_into_table(&dname,
							parser->lookup_tree);
			memcpy(rdata + offset, &dname, sizeof(knot_dname_t *));
			offset += sizeof(knot_dname_t *);
		} else if (descriptor_item_is_fixed(item)) {
			//copy the whole thing
			// TODO check the size
			assert(item == scanner->r_data_blocks[i + 1] -
			       scanner->r_data_blocks[i]);
			memcpy(rdata + offset,
			       scanner->r_data + scanner->r_data_blocks[i],
			       item);
			offset += item;
		} else {
			memcpy(rdata + offset,
			       scanner->r_data + scanner->r_data_blocks[i],
			       scanner->r_data_blocks[i + 1] -
			       scanner->r_data_blocks[i]);
			offset += scanner->r_data_blocks[i + 1] -
			          scanner->r_data_blocks[i];
		}
	}

	return KNOT_EOK;
}

static void process_rr(const scanner_t *scanner)
{
	/*!< \todo Refactor, too long. */
	dbg_zp_detail("Owner from parser=%s\n",
	              scanner->r_owner);
	parser_context_t *parser = scanner->data;
	if (parser->ret != KNOT_EOK) {
		return;
	}
	knot_zone_contents_t *contents = parser->current_zone;
	knot_dname_t *current_owner = NULL;
	knot_rrset_t *current_rrset = NULL;
	if (parser->last_node &&
	    (scanner->r_owner_length == parser->last_node->owner->size) &&
	    (strncmp((char *)parser->last_node->owner->name,
	            (char *)scanner->r_owner, scanner->r_owner_length) == 0)) {
		// no need to create new dname;
		current_owner = parser->last_node->owner;
		knot_dname_retain(current_owner);
	} else {
		current_owner =
			knot_dname_new_from_wire(scanner->r_owner,
			                         scanner->r_owner_length,
			                         NULL);
		if (current_owner == NULL) {
			parser->ret = KNOT_ERROR;
			return;
		}
		knot_dname_to_lower(current_owner);
		/*!< \todo
		 * If name is already in the table, we might not need to create
		 * dname object, just compare wires.
		 */
		knot_zone_contents_insert_dname_into_table(&current_owner,
		                                           parser->lookup_tree);
	}

	/*!< \todo Do not create RRSet each time - merging needs to be sorted though. */
	current_rrset = knot_rrset_new(current_owner,
	               scanner->r_type,
	               scanner->r_class,
	               scanner->r_ttl);
	knot_dname_release(current_owner);

	assert(current_owner);
	assert(current_rrset);
	parser->current_rrset = current_rrset;

	int ret = add_rdata_to_rr(current_rrset, scanner);
	if (ret != KNOT_EOK) {
		log_zone_error("Cannot add RDATA to zone, load failed.\n");
		parser->ret = ret;
		return;
	}

	dbg_zp_verb("zp: process_rr: Processing type: %d.\n",
	            parser->current_rrset->type);

	assert(current_rrset->rdata_count);

	/* Node add/get functions. */
	int (*node_add_func)(knot_zone_contents_t *, knot_node_t *, int,
	                     uint8_t);
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
				parser->ret = KNOT_EMALF;
				return;
			} else {
				log_zone_warning("encountered identical "
				                 "extra SOA record\n");
				knot_rrset_deep_free(&current_rrset, 1, 1);
				parser->ret = KNOT_EOK;
				return;
			}
		}
	}

	if (current_rrset->type == KNOT_RRTYPE_SOA) {
		if (knot_dname_compare(current_rrset->owner,
					parser->origin_from_config) != 0) {
			log_zone_error("SOA record has a different "
				"owner than the one specified "
				"in config! \n");
			/* Such SOA cannot even be added, because
			 * it would not be in the zone apex. */
			parser->ret = KNOT_EOUTOFZONE;
			return;
		}
	}

	if (current_rrset->type == KNOT_RRTYPE_RRSIG) {
		knot_rrset_t *tmp_rrsig = current_rrset;

		if (parser->last_node &&
		    knot_dname_compare_non_canon(parser->last_node->owner,
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
				                                     current_rrset,
				                                     node_add_func))
				    == NULL) {
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
	    knot_dname_compare_non_canon(parser->last_node->owner,
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
		                        node_add_func)) == NULL) {
			dbg_zp("zp: process_rr: Cannot "
			       "create new node.\n");
			char *zone_name = knot_dname_to_str(contents->apex->owner);
			char *name = knot_dname_to_str(current_rrset->owner);
			log_zone_warning("Zone %s: Cannot create new "
			                 "node owned by %s, skipping.\n",
			                 zone_name, name);
			free(name);
			free(zone_name);
			return;
		}
	}

	if (current_rrset->type != KNOT_RRTYPE_RRSIG) {
		/*
		 * If there's already an RRSet of this type in a node, check
		 * that TTLs are the same, if not, give warning a change TTL.
		 */
		const knot_rrset_t *rrset_in_node =
			knot_node_rrset(node, current_rrset->type);
		if (rrset_in_node &&
		    current_rrset->ttl != rrset_in_node->ttl) {
			log_zone_warning("TTL does not match TTL of its RRSet."
			                 "Changing to %"PRIu32"\n",
			                 rrset_in_node->ttl);
			/* Actual change will happen in merge. */
		}
	}

	ret = knot_zone_contents_add_rrset(contents, current_rrset,
	                                   &node,
	                                   KNOT_RRSET_DUPL_MERGE);
	if (ret < 0) {
		dbg_zp("zp: process_rr: Cannot "
		       "add RRSets.\n");
		/*!< \todo mixed error codes, has to be changed. */
		parser->ret = ret;
		return;
	} else if (ret > 0) {
		knot_rrset_deep_free(&current_rrset, 1, 0);
	}
	assert(parser->current_zone && node);
	/* Do mandatory semantic checks. */
	int sem_fatal_error = 0;
	ret = sem_check_node_plain(parser->current_zone, node, -1,
	                           parser->err_handler, 1,
	                           &sem_fatal_error);
	if (ret != KNOT_EOK) {
		log_zone_error("Semantic check failed to run (%s)\n",
		               knot_strerror(ret));
		parser->ret = ret;
		return;
	}
	if (sem_fatal_error) {
		log_zone_error("Semantic check found fatal error "
		               "on line=%"PRIu64"\n",
		               scanner->line_counter);
		parser->ret = KNOT_EMALF;
		return;
	}

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

	/* Create trie for DNAME duplicits. */
	context->lookup_tree = hattrie_create();
	if (context->lookup_tree == NULL) {
		free(context);
		return KNOT_ENOMEM;
	}

	context->origin_from_config =
		knot_dname_new_from_str(origin, strlen(origin), NULL);
	assert(context->origin_from_config);
	knot_dname_to_lower(context->origin_from_config);
	/* Add first DNAME to lookup tree. */
	knot_zone_contents_insert_dname_into_table(&context->origin_from_config,
	                                           context->lookup_tree);
	context->last_node = knot_node_new(context->origin_from_config,
	                                   NULL, 0);
	knot_dname_release(context->origin_from_config);
	knot_zone_t *zone = knot_zone_new(context->last_node);
	context->current_zone = knot_zone_get_contents(zone);
	context->node_rrsigs = NULL;
	context->ret = KNOT_EOK;

	/* Create file loader. */
	file_loader_t *loader = file_loader_create(source, origin,
	                                           KNOT_CLASS_IN, 3600,
	                                           process_rr, process_error,
	                                           context);
	if (loader == NULL) {
		dbg_zload("Could not create file loader.\n");
		hattrie_free(context->lookup_tree);
		free(context);
		return KNOT_ERROR;
	}

	/* Allocate new loader. */
	zloader_t *zl = xmalloc(sizeof(zloader_t));

	zl->source = strdup(source);
	zl->origin = strdup(origin);
	zl->file_loader = loader;
	zl->context = context;
	zl->semantic_checks = semantic_checks;
	*dst = zl;

	/* Log all information for now - possibly more config options. */
	zl->err_handler = handler_new(1, 1, 1, 1, 1);
	if (zl->err_handler == NULL) {
		/* Not a reason to stop. */
		log_zone_warning("Could not create semantic checks handler. "
		                 "Semantic check skipped for zone %s\n",
		                 origin);
	}

	context->err_handler = zl->err_handler;

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
		log_zone_error("Zone could not be loaded (%s).\n",
		               knot_strerror(c->ret));
		rrset_list_delete(&c->node_rrsigs);
		knot_zone_t *zone_to_free = c->current_zone->zone;
		knot_zone_deep_free(&zone_to_free);
		return NULL;
	}

	if (loader->file_loader->scanner->error_counter > 0) {
		log_zone_error("Zone could not be loaded due to %"PRIu64" errors"
		               " encountered.\n",
		               loader->file_loader->scanner->error_counter);
		rrset_list_delete(&c->node_rrsigs);
		knot_zone_t *zone_to_free = c->current_zone->zone;
		knot_zone_deep_free(&zone_to_free);
		return NULL;
	}

	if (knot_zone_contents_apex(c->current_zone) == NULL ||
	    knot_node_rrset(knot_zone_contents_apex(c->current_zone), KNOT_RRTYPE_SOA) == NULL) {
		log_zone_error("No SOA record in the zone file.\n");
		rrset_list_delete(&c->node_rrsigs);
		knot_zone_t *zone_to_free = c->current_zone->zone;
		knot_zone_deep_free(&zone_to_free);
		return NULL;
	}

	knot_node_t *first_nsec3_node = NULL;
	knot_node_t *last_nsec3_node = NULL;
	rrset_list_delete(&c->node_rrsigs);
	knot_zone_contents_adjust(c->current_zone, &first_nsec3_node,
	                          &last_nsec3_node, 0);

	if (loader->semantic_checks) {
		int check_level = 1;
		const knot_rrset_t *soa_rr =
			knot_node_rrset(knot_zone_contents_apex(c->current_zone),
		                        KNOT_RRTYPE_SOA);
		assert(soa_rr); // In this point, SOA has to exist
		const knot_rrset_t *nsec3param_rr =
			knot_node_rrset(knot_zone_contents_apex(c->current_zone),
		                        KNOT_RRTYPE_NSEC3PARAM);
		if (soa_rr->rrsigs && nsec3param_rr == NULL) {
			/* Set check level to DNSSEC. */
			check_level = 2;
		} else if (soa_rr->rrsigs && nsec3param_rr) {
			check_level = 3;
		}
		zone_do_sem_checks(c->current_zone, check_level,
		                   loader->err_handler, first_nsec3_node,
		                   last_nsec3_node);
		char *zname = knot_dname_to_str(knot_rrset_owner(soa_rr));
		log_zone_info("Semantic checks completed for zone=%s\n", zname);
		free(zname);
	}

	return c->current_zone->zone;
}

void knot_zload_close(zloader_t *loader)
{
	if (!loader) {
		return;
	}

	hattrie_free(loader->context->lookup_tree);

	file_loader_free(loader->file_loader);

	free(loader->source);
	free(loader->origin);
	free(loader->context);
	free(loader->err_handler);
	free(loader);
}
