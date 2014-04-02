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
#include "knot/zone/zone-create.h"
#include "zscanner/zscanner.h"
#include "libknot/rdata.h"

void process_error(const zs_scanner_t *s)
{
	if (s->stop == true) {
		log_zone_error("Fatal error in zone file %s:%"PRIu64": %s "
		               "Stopping zone loading.\n",
		               s->file_name, s->line_counter,
		               zs_strerror(s->error_code));
	} else {
		log_zone_error("Error in zone file %s:%"PRIu64": %s\n",
		               s->file_name, s->line_counter,
		               zs_strerror(s->error_code));
	}
}

static int add_rdata_to_rr(knot_rrset_t *rrset, const zs_scanner_t *scanner)
{
	return knot_rrset_add_rr(rrset, scanner->r_data, scanner->r_data_length,
	                         scanner->r_ttl, NULL);
}

static bool handle_err(zcreator_t *zc,
                       const knot_rrset_t *rr,
                       int ret)
{
	char *zname = zc->z ? knot_dname_to_str(zc->z->apex->owner) : NULL;
	char *rrname = rr ? knot_dname_to_str(rr->owner) : NULL;
	if (ret == KNOT_EOUTOFZONE) {
		log_zone_warning("Zone %s: Ignoring out-of-zone data for %s\n",
		                 zname ? zname : "unknown", rrname ? rrname : "unknown");
		free(zname);
		free(rrname);
		return true;
	} else {
		log_zone_error("Zone %s: Cannot process record %s, stopping.\n",
		               zname ? zname : "unknown", rrname ? rrname : "unknown");
		free(zname);
		free(rrname);
		return false;
	}
}

int zcreator_step(zcreator_t *zc, const knot_rrset_t *rr)
{
	assert(zc && rr);

	if (rr->type == KNOT_RRTYPE_SOA &&
	    knot_node_rrtype_exists(zc->z->apex, KNOT_RRTYPE_SOA)) {
		// Ignore extra SOA
		return KNOT_EOK;
	}

	knot_node_t *node = NULL;
	int ret = knot_zone_contents_add_rr(zc->z, rr, &node);
	if (ret < 0) {
		if (!handle_err(zc, rr, ret)) {
			// Fatal error
			return ret;
		}
		// Recoverable error, skip record
		return KNOT_EOK;
	}
	assert(node);

	// Do RRSet and node semantic checks
	bool sem_fatal_error = false;
	err_handler_t err_handler;
	err_handler_init(&err_handler);
	// TODO
//	ret = sem_check_rrset(node, zone_rrset, &err_handler);
//	if (ret != KNOT_EOK) {
//		return ret;
//	}
	ret = sem_check_node_plain(zc->z, node,
	                           &err_handler, true,
	                           &sem_fatal_error);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return sem_fatal_error ? KNOT_EMALF : KNOT_EOK;
}

/*! \brief Creates RR from parser input, passes it to handling function. */
static void loader_process(const zs_scanner_t *scanner)
{
	zcreator_t *zc = scanner->data;
	if (zc->ret != KNOT_EOK) {
		return;
	}

	knot_dname_t *owner = knot_dname_copy(scanner->r_owner, NULL);
	if (owner == NULL) {
		zc->ret = KNOT_ENOMEM;
		return;
	}
	knot_dname_to_lower(owner);

	knot_rrset_t rr = {.owner = owner,
	                   .type = scanner->r_type,
	                   .rclass = scanner->r_class,
	                   .additional = NULL};
	knot_rrs_init(&rr.rrs);
	int ret = add_rdata_to_rr(&rr, scanner);
	if (ret != KNOT_EOK) {
		char *rr_name = knot_dname_to_str(rr.owner);
		log_zone_error("%s:%"PRIu64": Can't add RDATA for '%s'.\n",
		               scanner->file_name, scanner->line_counter, rr_name);
		free(rr_name);
		knot_dname_free(&owner, NULL);
		zc->ret = ret;
		return;
	}

	ret = zcreator_step(zc, &rr);
	knot_dname_free(&owner, NULL);
	knot_rrs_clear(&rr.rrs, NULL);
	if (ret != KNOT_EOK) {
		zc->ret = ret;
		return;
	}
}

static knot_zone_contents_t *create_zone_from_name(const char *origin)
{
	if (origin == NULL) {
		return NULL;
	}
	knot_dname_t *owner = knot_dname_from_str(origin);
	if (owner == NULL) {
		return NULL;
	}
	knot_dname_to_lower(owner);
	knot_zone_contents_t *z = knot_zone_contents_new(owner);
	knot_dname_free(&owner, NULL);
	return z;
}

int zonefile_open(zloader_t *loader, const conf_zone_t *conf)
{
	if (!loader || !conf) {
		return KNOT_EINVAL;
	}

	/* Check zone file. */
	if (access(conf->file, F_OK | R_OK) != 0) {
		return KNOT_EACCES;
	}

	/* Create context. */
	zcreator_t *zc = malloc(sizeof(zcreator_t));
	if (zc == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}
	memset(zc, 0, sizeof(zcreator_t));

	zc->z = create_zone_from_name(conf->name);
	if (zc->z == NULL) {
		free(zc);
		return KNOT_ENOMEM;
	}

	/* Create file loader. */
	memset(loader, 0, sizeof(zloader_t));
	loader->file_loader = zs_loader_create(conf->file, conf->name,
	                                       KNOT_CLASS_IN, 3600,
	                                       loader_process, process_error,
	                                       zc);
	if (loader->file_loader == NULL) {
		free(zc);
		return KNOT_ERROR;
	}

	loader->source = strdup(conf->file);
	loader->origin = strdup(conf->name);
	loader->creator = zc;
	loader->semantic_checks = conf->enable_checks;

	return KNOT_EOK;
}

knot_zone_contents_t *zonefile_load(zloader_t *loader)
{
	dbg_zload("zload: load: Loading zone, loader: %p.\n", loader);
	if (!loader) {
		dbg_zload("zload: load: NULL loader!\n");
		return NULL;
	}

	zcreator_t *zc = loader->creator;
	assert(zc);
	int ret = zs_loader_process(loader->file_loader);
	if (ret != ZS_OK) {
		log_zone_error("%s: zone file could not be loaded (%s).\n",
		               loader->source, zs_strerror(ret));
		goto fail;
	}

	if (zc->ret != KNOT_EOK) {
		log_zone_error("%s: zone file could not be loaded (%s).\n",
		               loader->source, knot_strerror(zc->ret));
		goto fail;
	}

	if (loader->file_loader->scanner->error_counter > 0) {
		log_zone_error("%s: zone file could not be loaded due to "
		               "%"PRIu64" errors encountered.\n",
		               loader->source,
		               loader->file_loader->scanner->error_counter);
		goto fail;
	}

	if (!knot_node_rrtype_exists(loader->creator->z->apex, KNOT_RRTYPE_SOA)) {
		log_zone_error("%s: no SOA record in the zone file.\n",
		               loader->source);
		goto fail;
	}

	knot_node_t *first_nsec3_node = NULL;
	knot_node_t *last_nsec3_node = NULL;

	int kret = knot_zone_contents_adjust_full(zc->z,
	                                          &first_nsec3_node, &last_nsec3_node);
	if (kret != KNOT_EOK) {
		log_zone_error("%s: Failed to finalize zone contents: %s\n",
		               loader->source, knot_strerror(kret));
		goto fail;
	}

	if (loader->semantic_checks) {
		int check_level = SEM_CHECK_UNSIGNED;
		knot_rrset_t soa_rr = NODE_RR_INIT(zc->z->apex, KNOT_RRTYPE_SOA);
		assert(!knot_rrset_empty(&soa_rr)); // In this point, SOA has to exist
		const bool have_nsec3param =
			knot_node_rrtype_exists(zc->z->apex, KNOT_RRTYPE_NSEC3PARAM);
		if (knot_zone_contents_is_signed(zc->z) && have_nsec3param) {
			/* Set check level to DNSSEC. */
			check_level = SEM_CHECK_NSEC;
		} else if (knot_zone_contents_is_signed(zc->z) && have_nsec3param) {
			check_level = SEM_CHECK_NSEC3;
		}
		err_handler_t err_handler;
		err_handler_init(&err_handler);
		zone_do_sem_checks(zc->z, check_level,
		                   &err_handler, first_nsec3_node,
		                   last_nsec3_node);
		char *zname = knot_dname_to_str(soa_rr.owner);
		log_zone_info("Semantic checks completed for zone=%s\n", zname);
		free(zname);
	}

	return zc->z;

fail:
	knot_zone_contents_deep_free(&zc->z);
	return NULL;
}

void zonefile_close(zloader_t *loader)
{
	if (!loader) {
		return;
	}

	zs_loader_free(loader->file_loader);

	free(loader->source);
	free(loader->origin);
	free(loader->creator);
}
