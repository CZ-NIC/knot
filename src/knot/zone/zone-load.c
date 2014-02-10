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

static int zone_loader_step(zone_loader_t *zl, knot_rrset_t *rr)
{
	assert(zl && rr);

	knot_node_t *n = NULL;
	int ret = knot_zone_contents_add_rr(zl->z, rr, &n);
	if (ret < 0) {
		return ret;
	} else if (ret > 0) {
		knot_rrset_deep_free(&rr, true, NULL);
	}
	ret = KNOT_EOK;

	bool sem_fatal_error = false;
//	ret = sem_check_node_plain(zl->z, n,
//	                           zl->err_handler, true,
//	                           &sem_fatal_error);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return sem_fatal_error ? KNOT_EMALF : KNOT_EOK;
}

/*! \brief Creates RR from parser input, passes it to handling function. */
static void loader_process(const scanner_t *scanner)
{
	zone_loader_t *zl = scanner->data;
	if (zl->ret != KNOT_EOK) {
		return;
	}

	knot_dname_t *owner = knot_dname_copy(scanner->r_owner);
	if (owner == NULL) {
		zl->ret = KNOT_ENOMEM;
		return;
	}
	knot_dname_to_lower(owner);

	knot_rrset_t *rr = knot_rrset_new(owner,
	                                  scanner->r_type,
	                                  scanner->r_class,
	                                  scanner->r_ttl, NULL);
	if (rr == NULL) {
		knot_dname_free(&owner);
		zl->ret = KNOT_ENOMEM;
		return;
	}

	int ret = add_rdata_to_rr(rr, scanner);
	if (ret != KNOT_EOK) {
		char *rr_name = knot_dname_to_str(rr->owner);
		log_zone_error("%s:%"PRIu64": Can't add RDATA for '%s'.\n",
		               scanner->file_name, scanner->line_counter, rr_name);
		free(rr_name);
		zl->ret = ret;
		return;
	}

	ret = zone_loader_step(zl, rr);
	if (ret != KNOT_EOK) {
		knot_rrset_deep_free(&rr, 1, NULL);
		zl->ret = ret;
		return;
	}
}

int knot_zload_open(zloader_t **dst, const char *source, const char *origin_str,
                    int semantic_checks)
{
	if (!dst || !source || !origin_str) {
		dbg_zload("zload: open: Bad arguments.\n");
		return KNOT_EINVAL;
	}

	*dst = NULL;

	/* Check zone file. */
	if (access(source, F_OK | R_OK) != 0) {
		return KNOT_EACCES;
	}

	/* Create context. */
	zone_loader_t *zl = xmalloc(sizeof(zone_loader_t));
	memset(zl, 0, sizeof(*zl));

	/* Create trie for DNAME duplicates. */
	zl->lookup_tree = hattrie_create();
	if (zl->lookup_tree == NULL) {
		free(zl);
		return KNOT_ENOMEM;
	}

	/* As it's a first node, no need for compression yet. */
	knot_dname_t *origin = knot_dname_from_str(origin_str);
	knot_dname_to_lower(origin);
	knot_node_t *apex = knot_node_new(origin, NULL, 0);
	knot_zone_t *zone = knot_zone_new(apex);
	zl->z = zone->contents;
	zl->ret = KNOT_EOK;

	/* Create file loader. */
	file_loader_t *loader = file_loader_create(source, origin_str,
	                                           KNOT_CLASS_IN, 3600,
	                                           loader_process, process_error,
	                                           zl);
	if (loader == NULL) {
		dbg_zload("Could not initialize zone parser.\n");
		hattrie_free(zl->lookup_tree);
		free(zl);
		return KNOT_ERROR;
	}

	/* Allocate new loader. */
	zloader_t *zld = xmalloc(sizeof(zloader_t));

	zld->source = strdup(source);
	zld->origin = strdup(origin_str);
	zld->file_loader = loader;
	zld->context = zl;
	zld->semantic_checks = semantic_checks;
	*dst = zld;

	zld->err_handler = zl->err_handler;
	return KNOT_EOK;
}

knot_zone_t *knot_zload_load(zloader_t *loader)
{
	dbg_zload("zload: load: Loading zone, loader: %p.\n", loader);
	if (!loader) {
		dbg_zload("zload: load: NULL loader!\n");
		return NULL;
	}

	zone_loader_t *c = loader->context;
	assert(c);
	int ret = file_loader_process(loader->file_loader);
	if (ret != ZSCANNER_OK) {
		log_zone_error("%s: zone file could not be loaded (%s).\n",
		               loader->source, zscanner_strerror(ret));
	}

	if (c->ret != KNOT_EOK) {
		log_zone_error("%s: zone file could not be loaded (%s).\n",
		               loader->source, knot_strerror(c->ret));
		knot_zone_t *zone_to_free = c->z->zone;
		knot_zone_deep_free(&zone_to_free);
		return NULL;
	}

	if (loader->file_loader->scanner->error_counter > 0) {
		log_zone_error("%s: zone file could not be loaded due to "
		               "%"PRIu64" errors encountered.\n",
		               loader->source,
		               loader->file_loader->scanner->error_counter);
		knot_zone_t *zone_to_free = c->z->zone;
		knot_zone_deep_free(&zone_to_free);
		return NULL;
	}

	if (knot_zone_contents_apex(c->z) == NULL ||
	    knot_node_rrset(knot_zone_contents_apex(c->z),
	                    KNOT_RRTYPE_SOA) == NULL) {
		log_zone_error("%s: no SOA record in the zone file.\n",
		               loader->source);
		knot_zone_t *zone_to_free = c->z->zone;
		knot_zone_deep_free(&zone_to_free);
		return NULL;
	}

	knot_node_t *first_nsec3_node = NULL;
	knot_node_t *last_nsec3_node = NULL;
	int kret = knot_zone_contents_adjust_full(c->z, &first_nsec3_node,
	                                          &last_nsec3_node);
	if (kret != KNOT_EOK)  {
		log_zone_error("%s: Failed to finalize zone contents: %s\n",
		               loader->source, knot_strerror(kret));
		knot_zone_t *zone_to_free = c->z->zone;
		knot_zone_deep_free(&zone_to_free);
		return NULL;
	}

	if (loader->semantic_checks) {
		int check_level = 1;
		const knot_rrset_t *soa_rr =
			knot_node_rrset(knot_zone_contents_apex(c->z),
		                        KNOT_RRTYPE_SOA);
		assert(soa_rr); // In this point, SOA has to exist
		const knot_rrset_t *nsec3param_rr =
			knot_node_rrset(knot_zone_contents_apex(c->z),
		                        KNOT_RRTYPE_NSEC3PARAM);
		if (knot_zone_contents_is_signed(loader->context->z) && nsec3param_rr == NULL) {
			/* Set check level to DNSSEC. */
			check_level = 2;
		} else if (knot_zone_contents_is_signed(loader->context->z) && nsec3param_rr) {
			check_level = 3;
		}
		zone_do_sem_checks(c->z, check_level,
		                   loader->err_handler, first_nsec3_node,
		                   last_nsec3_node);
		char *zname = knot_dname_to_str(knot_rrset_owner(soa_rr));
		log_zone_info("Semantic checks completed for zone=%s\n", zname);
		free(zname);
	}

	return c->z->zone;
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
