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
#include "common/strlcat.h"
#include "common/strlcpy.h"
#include "libknot/common.h"
#include "knot/zone/semantic-check.h"
#include "knot/zone/contents.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/other/debug.h"
#include "knot/zone/zonefile.h"
#include "zscanner/loader.h"
#include "libknot/rdata.h"
#include "knot/zone/zone-dump.h"

void process_error(zs_scanner_t *s)
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
	return knot_rrset_add_rdata(rrset, scanner->r_data, scanner->r_data_length,
	                         scanner->r_ttl, NULL);
}

static bool handle_err(zcreator_t *zc, const zone_node_t *node,
                       const knot_rrset_t *rr, int ret, bool master)
{
	char *zname = zc->z ? knot_dname_to_str(zc->z->apex->owner) : NULL;
	char *rrname = rr ? knot_dname_to_str(rr->owner) : NULL;
	if (ret == KNOT_EOUTOFZONE) {
		log_zone_warning("Zone %s: Ignoring out-of-zone data for %s\n",
		                 zname ? zname : "unknown", rrname ? rrname : "unknown");
		free(zname);
		free(rrname);
		return true;
	} else if (ret == KNOT_ETTL) {
		free(zname);
		free(rrname);
		assert(node);
		log_ttl_error(node, rr);
		// Fail if we're the master for this zone.
		return !master;
	} else {
		log_zone_error("Zone %s: Cannot process record %s, stopping.\n",
		               zname ? zname : "unknown", rrname ? rrname : "unknown");
		free(zname);
		free(rrname);
		return false;
	}
}

void log_ttl_error(const zone_node_t *node, const knot_rrset_t *rr)
{
	err_handler_t err_handler;
	err_handler_init(&err_handler);
	// Prepare additional info string.
	char info_str[64] = { '\0' };
	char type_str[16] = { '\0' };
	knot_rrtype_to_string(rr->type, type_str, sizeof(type_str));
	int ret = snprintf(info_str, sizeof(info_str), "Record type: %s.",
	                   type_str);
	if (ret <= 0 || ret >= sizeof(info_str)) {
		*info_str = '\0';
	}

	/*!< \todo REPLACE WITH FATAL ERROR for master. */
	err_handler_handle_error(&err_handler, node,
	                         ZC_ERR_TTL_MISMATCH, info_str);
}

int zcreator_step(zcreator_t *zc, const knot_rrset_t *rr)
{
	if (zc == NULL || rr == NULL || rr->rrs.rr_count != 1) {
		return KNOT_EINVAL;
	}

	if (rr->type == KNOT_RRTYPE_SOA &&
	    node_rrtype_exists(zc->z->apex, KNOT_RRTYPE_SOA)) {
		// Ignore extra SOA
		return KNOT_EOK;
	}

	zone_node_t *node = NULL;
	int ret = zone_contents_add_rr(zc->z, rr, &node);
	if (ret != KNOT_EOK) {
		if (!handle_err(zc, node, rr, ret, zc->master)) {
			// Fatal error
			return ret;
		}
		if (ret == KNOT_EOUTOFZONE) {
			// Skip out-of-zone record
			return KNOT_EOK;
		}
	}
	assert(node);

	// Do node semantic checks
	err_handler_t err_handler;
	err_handler_init(&err_handler);
	bool sem_fatal_error = false;

	ret = sem_check_node_plain(zc->z, node,
	                           &err_handler, true,
	                           &sem_fatal_error);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return sem_fatal_error ? KNOT_EMALF : KNOT_EOK;
}

/*! \brief Creates RR from parser input, passes it to handling function. */
static void loader_process(zs_scanner_t *scanner)
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

	knot_rrset_t rr;
	knot_rrset_init(&rr, owner, scanner->r_type, scanner->r_class);
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
	knot_rdataset_clear(&rr.rrs, NULL);
	if (ret != KNOT_EOK) {
		zc->ret = ret;
		return;
	}
}

static zone_contents_t *create_zone_from_name(const char *origin)
{
	if (origin == NULL) {
		return NULL;
	}
	knot_dname_t *owner = knot_dname_from_str(origin);
	if (owner == NULL) {
		return NULL;
	}
	knot_dname_to_lower(owner);
	zone_contents_t *z = zone_contents_new(owner);
	knot_dname_free(&owner, NULL);
	return z;
}

int zonefile_open(zloader_t *loader, const char *source, const char *origin,
		  bool semantic_checks)
{
	if (!loader) {
		return KNOT_EINVAL;
	}

	/* Check zone file. */
	if (access(source, F_OK | R_OK) != 0) {
		return KNOT_EACCES;
	}

	/* Create context. */
	zcreator_t *zc = malloc(sizeof(zcreator_t));
	if (zc == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}
	memset(zc, 0, sizeof(zcreator_t));

	zc->z = create_zone_from_name(origin);
	if (zc->z == NULL) {
		free(zc);
		return KNOT_ENOMEM;
	}

	/* Create file loader. */
	memset(loader, 0, sizeof(zloader_t));
	loader->file_loader = zs_loader_create(source, origin,
	                                       KNOT_CLASS_IN, 3600,
	                                       loader_process, process_error,
	                                       zc);
	if (loader->file_loader == NULL) {
		free(zc);
		return KNOT_ERROR;
	}

	loader->source = strdup(source);
	loader->origin = strdup(origin);
	loader->creator = zc;
	loader->semantic_checks = semantic_checks;

	return KNOT_EOK;
}

zone_contents_t *zonefile_load(zloader_t *loader)
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

	if (!node_rrtype_exists(loader->creator->z->apex, KNOT_RRTYPE_SOA)) {
		log_zone_error("%s: no SOA record in the zone file.\n",
		               loader->source);
		goto fail;
	}

	zone_node_t *first_nsec3_node = NULL;
	zone_node_t *last_nsec3_node = NULL;

	int kret = zone_contents_adjust_full(zc->z,
	                                          &first_nsec3_node, &last_nsec3_node);
	if (kret != KNOT_EOK) {
		log_zone_error("%s: Failed to finalize zone contents: %s\n",
		               loader->source, knot_strerror(kret));
		goto fail;
	}

	if (loader->semantic_checks) {
		int check_level = SEM_CHECK_UNSIGNED;
		knot_rrset_t soa_rr = node_rrset(zc->z->apex, KNOT_RRTYPE_SOA);
		assert(!knot_rrset_empty(&soa_rr)); // In this point, SOA has to exist
		const bool have_nsec3param =
			node_rrtype_exists(zc->z->apex, KNOT_RRTYPE_NSEC3PARAM);
		if (zone_contents_is_signed(zc->z) && !have_nsec3param) {

			/* Set check level to DNSSEC. */
			check_level = SEM_CHECK_NSEC;
		} else if (zone_contents_is_signed(zc->z) && have_nsec3param) {
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
	zone_contents_deep_free(&zc->z);
	return NULL;
}

/*! \brief Return zone file mtime. */
time_t zonefile_mtime(const char *path)
{
	struct stat zonefile_st = { 0 };
	int result = stat(path, &zonefile_st);
	if (result < 0) {
		return result;
	}
	return zonefile_st.st_mtime;
}

/*! \brief Moved from zones.c, no doc. @mvavrusa */
static int zones_open_free_filename(const char *old_name, char **new_name)
{
	/* find zone name not present on the disk */
	char *suffix = ".XXXXXX";
	size_t name_size = strlen(old_name);
	size_t max_size = name_size + strlen(suffix) + 1;
	*new_name = malloc(max_size);
	if (*new_name == NULL) {
		return -1;
	}
	strlcpy(*new_name, old_name, max_size);
	strlcat(*new_name, suffix, max_size);
	mode_t old_mode = umask(077);
	int fd = mkstemp(*new_name);
	UNUSED(umask(old_mode));
	if (fd < 0) {
		free(*new_name);
		*new_name = NULL;
	}

	return fd;
}

int zonefile_write(const char *path, zone_contents_t *zone,
                   const struct sockaddr_storage *from)
{
	if (!zone || !path) {
		return KNOT_EINVAL;
	}

	char *new_fname = NULL;
	int fd = zones_open_free_filename(path, &new_fname);
	if (fd < 0) {
		return KNOT_EWRITABLE;
	}

	FILE *f = fdopen(fd, "w");
	if (f == NULL) {
		log_zone_warning("Failed to open file descriptor for text zone.\n");
		unlink(new_fname);
		free(new_fname);
		return KNOT_ERROR;
	}

	if (zone_dump_text(zone, from, f) != KNOT_EOK) {
		log_zone_warning("Failed to save the transferred zone to '%s'.\n",
		                 new_fname);
		fclose(f);
		unlink(new_fname);
		free(new_fname);
		return KNOT_ERROR;
	}

	/* Set zone file rights to 0640. */
	fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);

	/* Swap temporary zonefile and new zonefile. */
	fclose(f);

	int ret = rename(new_fname, path);
	if (ret < 0 && ret != EEXIST) {
		log_zone_warning("Failed to replace old zone file '%s'' with a "
		                 "new zone file '%s'.\n", path, new_fname);
		unlink(new_fname);
		free(new_fname);
		return KNOT_ERROR;
	}

	free(new_fname);
	return KNOT_EOK;
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
