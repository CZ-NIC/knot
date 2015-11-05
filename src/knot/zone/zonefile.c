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

#include "common-knot/strlcat.h"
#include "common-knot/strlcpy.h"
#include "libknot/common.h"
#include "knot/zone/semantic-check.h"
#include "knot/zone/contents.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/other/debug.h"
#include "knot/zone/zonefile.h"
#include "libknot/rdata.h"
#include "knot/zone/zone-dump.h"
#include "libknot/rrtype/naptr.h"

#define ERROR(zone, fmt...) log_zone_error(zone, "zone loader, " fmt)
#define WARNING(zone, fmt...) log_zone_warning(zone, "zone loader, " fmt)
#define INFO(zone, fmt...) log_zone_info(zone, "zone loader, " fmt)

void process_error(zs_scanner_t *s)
{
	zcreator_t *zc = s->data;
	const knot_dname_t *zname = zc->z->apex->owner;

	ERROR(zname, "%s in zone, file '%s', line %"PRIu64" (%s)",
	      s->stop ? "fatal error" : "error",
	      s->file.name, s->line_counter,
	      zs_strerror(s->error_code));
}

static int add_rdata_to_rr(knot_rrset_t *rrset, const zs_scanner_t *scanner)
{
	return knot_rrset_add_rdata(rrset, scanner->r_data, scanner->r_data_length,
	                         scanner->r_ttl, NULL);
}

static bool handle_err(zcreator_t *zc, const zone_node_t *node,
                       const knot_rrset_t *rr, int ret, bool master)
{
	const knot_dname_t *zname = zc->z->apex->owner;
	char *rrname = rr ? knot_dname_to_str_alloc(rr->owner) : NULL;
	if (ret == KNOT_EOUTOFZONE) {
		WARNING(zname, "ignoring out-of-zone data, owner '%s'",
		        rrname ? rrname : "unknown");
		free(rrname);
		return true;
	} else if (ret == KNOT_ETTL) {
		free(rrname);
		assert(node);
		log_ttl_error(zc->z, node, rr);
		// Fail if we're the master for this zone.
		return !master;
	} else {
		ERROR(zname, "failed to process record, owner '%s'",
		      rrname ? rrname : "unknown");
		free(rrname);
		return false;
	}
}

void log_ttl_error(const zone_contents_t *zone, const zone_node_t *node,
		   const knot_rrset_t *rr)
{
	err_handler_t err_handler;
	err_handler_init(&err_handler);
	// Prepare additional info string.
	char info_str[64] = { '\0' };
	char type_str[16] = { '\0' };
	knot_rrtype_to_string(rr->type, type_str, sizeof(type_str));
	int ret = snprintf(info_str, sizeof(info_str), "record type %s",
	                   type_str);
	if (ret <= 0 || ret >= sizeof(info_str)) {
		*info_str = '\0';
	}

	/*!< \todo REPLACE WITH FATAL ERROR for master. */
	err_handler_handle_error(&err_handler, zone, node,
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
    //printf("APO TO ZONEFILE KALESA GIA ADD_RR\n");
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

	return sem_fatal_error ? KNOT_ESEMCHECK : KNOT_EOK;
}

/*! \brief Creates RR from parser input, passes it to handling function. */
static void scanner_process(zs_scanner_t *scanner)
{
	zcreator_t *zc = scanner->data;
	if (zc->ret != KNOT_EOK) {
		scanner->stop = true;
		return;
	}

	knot_dname_t *owner = knot_dname_copy(scanner->r_owner, NULL);
	if (owner == NULL) {
		zc->ret = KNOT_ENOMEM;
		return;
	}

	knot_rrset_t rr;
	knot_rrset_init(&rr, owner, scanner->r_type, scanner->r_class);
	int ret = add_rdata_to_rr(&rr, scanner);
	if (ret != KNOT_EOK) {
		char *rr_name = knot_dname_to_str_alloc(rr.owner);
		const knot_dname_t *zname = zc->z->apex->owner;
		ERROR(zname, "failed to add RDATA, file '%s', line %"PRIu64", owner '%s'",
		      scanner->file.name, scanner->line_counter, rr_name);
		free(rr_name);
		knot_dname_free(&owner, NULL);
		zc->ret = ret;
		return;
	}

	/* Convert RDATA dnames to lowercase before adding to zone. */
	ret = knot_rrset_rr_to_canonical(&rr);
	if (ret != KNOT_EOK) {
		knot_dname_free(&owner, NULL);
		zc->ret = ret;
		return;
	}

	zc->ret = zcreator_step(zc, &rr);
	knot_dname_free(&owner, NULL);
	knot_rdataset_clear(&rr.rrs, NULL);
}

static zone_contents_t *create_zone_from_name(const char *origin)
{
	if (origin == NULL) {
		return NULL;
	}
	knot_dname_t *owner = knot_dname_from_str_alloc(origin);
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
	loader->scanner = zs_scanner_create(origin, KNOT_CLASS_IN, 3600,
	                                    scanner_process, process_error,
	                                    zc);
	if (loader->scanner == NULL) {
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
	const knot_dname_t *zname = zc->z->apex->owner;

	assert(zc);
    //printf ("print to parse file\n");
	int ret = zs_scanner_parse_file(loader->scanner, loader->source);
	if (ret != 0 && loader->scanner->error_counter == 0) {
        printf("first error\n");
		ERROR(zname, "failed to load zone, file '%s' (%s)",
		      loader->source, zs_strerror(loader->scanner->error_code));
		goto fail;
	}

	if (zc->ret != KNOT_EOK) {
        printf("second error\n");

		ERROR(zname, "failed to load zone, file '%s' (%s)",
		      loader->source, knot_strerror(zc->ret));
		goto fail;
	}

	if (loader->scanner->error_counter > 0) {
        printf("third error\n");

		ERROR(zname, "failed to load zone, file '%s', %"PRIu64" errors",
		      loader->source, loader->scanner->error_counter);
		goto fail;
	}

	if (!node_rrtype_exists(loader->creator->z->apex, KNOT_RRTYPE_SOA)) {
        printf("fourth error\n");

		ERROR(zname, "no SOA record, file '%s'", loader->source);
		goto fail;
	}

	zone_node_t *first_nsec3_node = NULL;
	zone_node_t *last_nsec3_node = NULL;

    dbg_zload("zload: adjusting pointers\n");
	int kret = zone_contents_adjust_full(zc->z,
	                                     &first_nsec3_node, &last_nsec3_node);
    dbg_zload("zload: pointers adjusted\n");
    
	if (kret != KNOT_EOK) {
		ERROR(zname, "failed to finalize zone contents (%s)",
		      knot_strerror(kret));
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
		INFO(zname, "semantic check, completed");
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
    //printf("old file name: %s\n", old_name);
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

int zonefile_write(const char *path, zone_contents_t *zone)
{
	if (!zone || !path) {
        printf("out in the first check\n");
		return KNOT_EINVAL;
	}
    //printf( "path: %s\n", path);
	char *new_fname = NULL;
    //printf("TRYING TO OPEN FREE FILENAME\n");
	int fd = zones_open_free_filename(path, &new_fname);
    //printf("OPENED FREE FILENAME\n");

	if (fd < 0) {
        printf("not writable\n");

		return KNOT_EWRITABLE;
	}

	const knot_dname_t *zname = zone->apex->owner;

    //printf("TRYING TO FDOPEN\n");
	FILE *f = fdopen(fd, "w");
	if (f == NULL) {
		WARNING(zname, "failed to open zone, file '%s' (%s)",
		        new_fname, knot_strerror(knot_errno_to_error(errno)));
		unlink(new_fname);
		free(new_fname);
		return KNOT_ERROR;
	}
    //printf("to zone name --> %s", knot_dname_to_str_alloc(zname));
    //printf("TWRA THA GRAPSW TI ZWNI sto file %s\n", new_fname);
	if (zone_dump_text(zone, f) != KNOT_EOK) {
		WARNING(zname, "failed to save zone, file '%s'", new_fname);
		fclose(f);
		unlink(new_fname);
		free(new_fname);
		return KNOT_ERROR;
	}
    //printf("VGIKA APO zone_dump_text..\n");

	/* Set zone file rights to 0640. */
	fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);

	/* Swap temporary zonefile and new zonefile. */
	fclose(f);

	int ret = rename(new_fname, path);
	if (ret < 0 && ret != EEXIST) {
		WARNING(zname, "failed to swap zone files, old '%s', new '%s'",
		        path, new_fname);
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

	zs_scanner_free(loader->scanner);

	free(loader->source);
	free(loader->origin);
	free(loader->creator);
}

#undef ERROR
#undef WARNING
#undef INFO
