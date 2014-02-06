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
#include "knot/zone/zone-contents.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/other/debug.h"
#include "knot/zone/zone-load.h"
#include "zscanner/file_loader.h"
#include "libknot/rdata.h"

/* ZONE LOADING FROM FILE USING RAGEL PARSER */

static knot_node_t *create_node(knot_zone_contents_t *zone,
                                knot_rrset_t *current_rrset,
                                int (*node_add_func)(knot_zone_contents_t *zone,
                                                     knot_node_t *node,
                                                     int create_parents, uint8_t))
{
	dbg_zload_verb("zp: create_node: Creating node using RRSet: %p.\n",
	            current_rrset);
	knot_node_t *node = knot_node_new(current_rrset->owner, NULL, 0);
	if (node == NULL) {
		return NULL;
	}

	int ret = node_add_func(zone, node, 1, 0);
	if (ret != KNOT_EOK) {
		knot_node_free(&node);
		return NULL;
	}

	return node;
}

void process_error(const scanner_t *s)
{
	if (s->stop == true) {
		log_zone_error("Fatal error in zone file %s:%"PRIu64": %s "
		               "Stopping zone loading.\n",
		               s->file_name, s->line_counter,
		               zscanner_strerror(s->error_code));
	} else {
		log_zone_error("Error in zone file %s:%"PRIu64": %s\n",
		               s->file_name, s->line_counter,
		               zscanner_strerror(s->error_code));
	}
}

static int add_rdata_to_rr(knot_rrset_t *rrset, const scanner_t *scanner)
{
	if (rrset == NULL) {
		dbg_zload("zp: add_rdata_to_rr: No RRSet.\n");
		return KNOT_EINVAL;
	}

	dbg_zload_detail("zp: add_rdata_to_rr: Adding type %d, RRSet has %d RRs.\n",
	              rrset->type, rrset->rdata_count);

	uint8_t *rdata = knot_rrset_create_rdata(rrset, scanner->r_data_length,
	                                         NULL);
	if (rdata == NULL) {
		dbg_zload("zp: create_rdata: Could not create RR.\n");
		return KNOT_ENOMEM;
	}

	memcpy(rdata, scanner->r_data, scanner->r_data_length);

	return KNOT_EOK;
}

static void process_rr(const scanner_t *scanner)
{
	/*!< \todo Refactor, too long. */
	dbg_zload_detail("Owner from parser=%s\n",
	              scanner->r_owner);
	parser_context_t *parser = scanner->data;
	if (parser->ret != KNOT_EOK) {
		return;
	}

	knot_zone_contents_t *contents = parser->current_zone;

	/*!
	 * \todo Node/RRSet compression at this level? To avoid duplicate
	 *       names.
	 */

	knot_rrset_t *current_rrset = NULL;
	knot_dname_t *current_owner = knot_dname_copy(scanner->r_owner);

	knot_dname_to_lower(current_owner);

	/*!< \todo Do not create RRSet each time - merging needs to be
	 *         sorted though.
	 */
	current_rrset = knot_rrset_new(current_owner,
	               scanner->r_type,
	               scanner->r_class,
	               scanner->r_ttl, NULL);

	assert(current_owner);
	assert(current_rrset);
	parser->current_rrset = current_rrset;

	int ret = add_rdata_to_rr(current_rrset, scanner);
	if (ret != KNOT_EOK) {
		char *rr_name = knot_dname_to_str(current_owner);
		log_zone_error("%s:%"PRIu64": Can't add RDATA for '%s'.\n",
		               scanner->file_name, scanner->line_counter, rr_name);
		free(rr_name);
		parser->ret = ret;
		return;
	}

	dbg_zload_verb("zp: process_rr: Processing type: %d.\n",
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
			knot_rdata_rrsig_type_covered(current_rrset, 0);
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
				char *rr_name = knot_dname_to_str(current_owner);
				log_zone_error("%s:%"PRIu64": Extra SOA record in the zone '%s'.\n",
				               scanner->file_name, scanner->line_counter, rr_name);
				free(rr_name);
				/*!< \todo consider a new error */
				parser->ret = KNOT_EMALF;
				return;
			} else {
				char *rr_name = knot_dname_to_str(current_owner);
				log_zone_error("%s:%"PRIu64": encountered identical extra SOA record '%s'.\n",
				               scanner->file_name, scanner->line_counter, rr_name);
				free(rr_name);
				knot_rrset_deep_free(&current_rrset, 1, NULL);
				parser->ret = KNOT_EOK;
				return;
			}
		}
	}

	if (current_rrset->type == KNOT_RRTYPE_SOA) {
		if (knot_dname_cmp(current_rrset->owner,
		                   parser->origin_from_config) != 0) {
			char *rr_name = knot_dname_to_str(current_owner);
			log_zone_error("%s:%"PRIu64": SOA record '%s' has a different "
			               "owner than the one specified in config!.\n",
			               scanner->file_name, scanner->line_counter, rr_name);
			free(rr_name);
			/* Such SOA cannot even be added, because
			 * it would not be in the zone apex. */
			parser->ret = KNOT_EOUTOFZONE;
			return;
		}
	}

	knot_node_t *node = NULL;
	/* \note this could probably be much simpler */
	if (parser->last_node && current_rrset->type != KNOT_RRTYPE_SOA &&
	    knot_dname_is_equal(parser->last_node->owner, current_rrset->owner)) {
		node = parser->last_node;
	}

	if (node == NULL) {
		if ((node = create_node(contents, current_rrset,
		                        node_add_func)) == NULL) {
			char *rr_name = knot_dname_to_str(current_owner);
			log_zone_error("%s:%"PRIu64": Can't create node for '%s'.\n",
			               scanner->file_name, scanner->line_counter, rr_name);
			free(rr_name);
			knot_rrset_deep_free(&current_rrset, 1, NULL);
			return;
		}
	}

	/*
	 * If there's already an RRSet of this type in a node, check
	 * that TTLs are the same, if not, give warning a change TTL.
	 */
	const knot_rrset_t *rrset_in_node =
		knot_node_rrset(node, current_rrset->type);
	if (rrset_in_node && current_rrset->ttl != rrset_in_node->ttl) {
		char *rr_name = knot_dname_to_str(current_owner);
		log_zone_warning("%s:%"PRIu64": TTL of '%s/TYPE%u' does not match TTL "
		                 "of its RRSet. Changing to %"PRIu32"\n",
		                 scanner->file_name, scanner->line_counter,
		                 rr_name, current_rrset->type, rrset_in_node->ttl);
		free(rr_name);
		/* Actual change will happen in merge. */
	}

	ret = knot_zone_contents_add_rrset(contents, current_rrset,
	                                   &node,
	                                   KNOT_RRSET_DUPL_MERGE);
	if (ret < 0) {
		dbg_zload("zp: process_rr: Cannot "
		       "add RRSets.\n");
		/*!< \todo mixed error codes, has to be changed. */
		parser->ret = ret;
		knot_rrset_deep_free(&current_rrset, 1, NULL);
		return;
	} else if (ret > 0) {
		knot_rrset_deep_free(&current_rrset, 1, NULL);
	}
	assert(parser->current_zone && node);
	/* Do mandatory semantic checks. */
	bool sem_fatal_error = false;
	ret = sem_check_node_plain(parser->current_zone, node,
	                           parser->err_handler, true,
	                           &sem_fatal_error);
	if (ret != KNOT_EOK) {
		log_zone_error("%s:%"PRIu64": Semantic check failed: %s\n",
		               scanner->file_name, scanner->line_counter,
		               knot_strerror(ret));
		parser->ret = ret;
		return;
	}
	if (sem_fatal_error) {
		log_zone_error("%s:%"PRIu64": Semantic check found fatal error: %s\n",
		               scanner->file_name, scanner->line_counter,
		               knot_strerror(ret));
		parser->ret = KNOT_EMALF;
		return;
	}

	parser->last_node = node;

	dbg_zload_verb("zp: process_rr: RRSet %p processed successfully.\n",
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
	if (access(source, F_OK | R_OK) != 0) {
		return KNOT_EACCES;
	}

	/* Create context. */
	parser_context_t *context = xmalloc(sizeof(parser_context_t));

	/* Create trie for DNAME duplicits. */
	context->lookup_tree = hattrie_create();
	if (context->lookup_tree == NULL) {
		free(context);
		return KNOT_ENOMEM;
	}

	/* As it's a first node, no need for compression yet. */
	context->origin_from_config = knot_dname_from_str(origin);
	assert(context->origin_from_config);
	knot_dname_to_lower(context->origin_from_config);
	context->last_node = knot_node_new(context->origin_from_config, NULL, 0);
	knot_zone_t *zone = knot_zone_new(context->last_node);
	context->current_zone = knot_zone_get_contents(zone);
	context->ret = KNOT_EOK;

	/* Create file loader. */
	file_loader_t *loader = file_loader_create(source, origin,
	                                           KNOT_CLASS_IN, 3600,
	                                           process_rr, process_error,
	                                           context);
	if (loader == NULL) {
		dbg_zload("Could not initialize zone parser.\n");
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

	zl->err_handler = err_handler_new();
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
	int ret = file_loader_process(loader->file_loader);
	if (ret != ZSCANNER_OK) {
		log_zone_error("%s: zone file could not be loaded (%s).\n",
		               loader->source, zscanner_strerror(ret));
	}

	if (c->ret != KNOT_EOK) {
		log_zone_error("%s: zone file could not be loaded (%s).\n",
		               loader->source, zscanner_strerror(c->ret));
		knot_zone_t *zone_to_free = c->current_zone->zone;
		knot_zone_deep_free(&zone_to_free);
		return NULL;
	}

	if (loader->file_loader->scanner->error_counter > 0) {
		log_zone_error("%s: zone file could not be loaded due to "
		               "%"PRIu64" errors encountered.\n",
		               loader->source,
		               loader->file_loader->scanner->error_counter);
		knot_zone_t *zone_to_free = c->current_zone->zone;
		knot_zone_deep_free(&zone_to_free);
		return NULL;
	}

	if (knot_zone_contents_apex(c->current_zone) == NULL ||
	    knot_node_rrset(knot_zone_contents_apex(c->current_zone),
	                    KNOT_RRTYPE_SOA) == NULL) {
		log_zone_error("%s: no SOA record in the zone file.\n",
		               loader->source);
		knot_zone_t *zone_to_free = c->current_zone->zone;
		knot_zone_deep_free(&zone_to_free);
		return NULL;
	}

	knot_node_t *first_nsec3_node = NULL;
	knot_node_t *last_nsec3_node = NULL;
	int kret = knot_zone_contents_adjust_full(c->current_zone, &first_nsec3_node,
	                                          &last_nsec3_node);
	if (kret != KNOT_EOK)  {
		log_zone_error("%s: Failed to finalize zone contents: %s\n",
		               loader->source, knot_strerror(kret));
		knot_zone_t *zone_to_free = c->current_zone->zone;
		knot_zone_deep_free(&zone_to_free);
		return NULL;
	}

	if (loader->semantic_checks) {
		int check_level = 1;
		const knot_rrset_t *soa_rr =
			knot_node_rrset(knot_zone_contents_apex(c->current_zone),
		                        KNOT_RRTYPE_SOA);
		assert(soa_rr); // In this point, SOA has to exist
		const knot_rrset_t *nsec3param_rr =
			knot_node_rrset(knot_zone_contents_apex(c->current_zone),
		                        KNOT_RRTYPE_NSEC3PARAM);
		if (knot_zone_contents_is_signed(loader->context->current_zone) && nsec3param_rr == NULL) {
			/* Set check level to DNSSEC. */
			check_level = 2;
		} else if (knot_zone_contents_is_signed(loader->context->current_zone) && nsec3param_rr) {
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

	knot_dname_free(&loader->context->origin_from_config);

	free(loader->source);
	free(loader->origin);
	free(loader->context);
	free(loader->err_handler);
	free(loader);
}
