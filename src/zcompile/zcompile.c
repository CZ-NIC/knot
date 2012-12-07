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
#include "libknot/libknot.h"
#include "libknot/util/utils.h"

/* Some global flags... */
static int vflag = 0;
/* if -v then print progress each 'progress' RRs */
static int progress = 10000;

/* Total errors counter */
static long int totalerrors = 0;
static long int totalrrs = 0;

extern FILE *zp_get_in(void *scanner);

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
	assert(rrsig != NULL);
	assert(rrsig->rdata->items[0].raw_data);
	assert(node);

	assert(knot_dname_compare(rrsig->owner, node->owner) == 0);

	knot_rrset_t *tmp_rrset =
		knot_node_get_rrset(node, rrsig_type_covered(rrsig));

	int ret;

	if (tmp_rrset == NULL) {
		dbg_zp("zp: find_rr_for_sig_in_node: Node does not contain "
		       "RRSet of type %s.\n",
		       knot_rrtype_to_string(rrsig_type_covered(rrsig)));
		tmp_rrset = knot_rrset_new(rrsig->owner,
		                           rrsig_type_covered(rrsig),
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

static void process_rrsigs_in_node(knot_zone_contents_t *zone,
                            knot_node_t *node)
{
	dbg_zp_verb("zp: process_rrsigs: Processing RRSIGS in node: %p.\n",
	            node);
	rrset_list_t *tmp = parser->node_rrsigs;
	while (tmp != NULL) {
		if (find_rrset_for_rrsig_in_node(zone, node,
						 tmp->data) != KNOT_EOK) {
			zc_error_prev_line("Could not add RRSIG to zone!\n");
			return;
		}
		tmp = tmp->next;
	}
}

int process_rr(void)
{
	knot_zone_t *zone = parser->current_zone;
	assert(zone != NULL);
	knot_zone_contents_t *contents = knot_zone_get_contents(zone);
	assert(contents != NULL);
	knot_rrset_t *current_rrset = parser->current_rrset;
	knot_rrset_t *rrset;
	knot_rrtype_descriptor_t *descriptor =
		knot_rrtype_descriptor_by_type(current_rrset->type);

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

	if (descriptor->fixed_items) {
		assert(current_rrset->rdata->count == descriptor->length);
	}


	assert(current_rrset->rdata->count > 0);
	assert(knot_dname_is_fqdn(current_rrset->owner));

	int (*node_add_func)(knot_zone_contents_t *, knot_node_t *, int,
	                     uint8_t, int);
	knot_node_t *(*node_get_func)(const knot_zone_contents_t *,
	                                const knot_dname_t *);


	/* If we have RRSIG of NSEC3 type first node will have
	 * to be created in NSEC3 part of the zone */

	uint16_t type_covered = 0;
	if (current_rrset->type == KNOT_RRTYPE_RRSIG) {
		type_covered = rrsig_type_covered(current_rrset);
	}

	if (current_rrset->type != KNOT_RRTYPE_NSEC3 &&
	    type_covered != KNOT_RRTYPE_NSEC3) {
		node_add_func = &knot_zone_contents_add_node;
		node_get_func = &knot_zone_contents_get_node;
	} else {
		node_add_func = &knot_zone_contents_add_nsec3_node;
		node_get_func = &knot_zone_contents_get_nsec3_node;
	}

	if ((current_rrset->type == KNOT_RRTYPE_SOA) && (zone != NULL)) {
		if (knot_node_rrset(knot_zone_contents_apex(contents),
		                      KNOT_RRTYPE_SOA) != NULL) {
			/* Receiving another SOA. */
			if (!knot_rrset_match(current_rrset,
			    knot_node_rrset(knot_zone_contents_apex(contents),
			    KNOT_RRTYPE_SOA), KNOT_RRSET_COMPARE_WHOLE)) {
				return KNOTDZCOMPILE_ESOA;
			} else {
				zc_warning_prev_line("encountered identical "
				                     "extra SOA record");
				return KNOTDZCOMPILE_EOK;
			}
		}
	}

	/*!< \todo Make sure the maximum RDLENGTH does not exceed 65535 bytes.*/

	if (current_rrset->type == KNOT_RRTYPE_SOA) {
		if (knot_dname_compare(current_rrset->owner,
					 parser->origin_from_config) != 0) {
			zc_error_prev_line("SOA record has a different "
				"owner than the one specified "
				"in config! \n");
			/* Such SOA cannot even be added, because
			 * it would not be in the zone apex. */
			return KNOTDZCOMPILE_EBADSOA;
		}
	}

	if (current_rrset->type == KNOT_RRTYPE_RRSIG) {
		/*!< \todo Use deep copy function here! */
		knot_rrset_t *tmp_rrsig =
			knot_rrset_new(current_rrset->owner,
					     KNOT_RRTYPE_RRSIG,
					     current_rrset->rclass,
					     current_rrset->ttl);
		if (tmp_rrsig == NULL) {
			dbg_zp("zp: process_rr: Cannot create tmp RRSIG.\n");
			return KNOTDZCOMPILE_ENOMEM;
		}

		if (knot_rrset_add_rdata(tmp_rrsig,
		                           current_rrset->rdata) != KNOT_EOK) {
			knot_rrset_free(&tmp_rrsig);
			dbg_zp("zp: process_rr: Cannot add data to tmp"
			       " RRSIG.\n");
			return KNOTDZCOMPILE_EBRDATA;
		}

		if (parser->last_node &&
		    knot_dname_compare(parser->last_node->owner,
		                         current_rrset->owner) != 0) {
			/* RRSIG is first in the node, so we have to create it
			 * before we return
			 */
			if (parser->node_rrsigs != NULL) {
				process_rrsigs_in_node(contents,
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
			process_rrsigs_in_node(contents,
			                       parser->last_node);
		}

		rrset_list_delete(&parser->node_rrsigs);

		/* new node */
		node = node_get_func(contents, current_rrset->owner);
	}

	if (node == NULL) {
		if (parser->last_node && parser->node_rrsigs) {
			process_rrsigs_in_node(contents,
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
		rrset = knot_rrset_new(current_rrset->owner,
					 current_rrset->type,
					 current_rrset->rclass,
					 current_rrset->ttl);
		if (rrset == NULL) {
			dbg_zp("zp: process_rr: Cannot "
			       "create new RRSet.\n");
			return KNOTDZCOMPILE_ENOMEM;
		}

		if (knot_rrset_add_rdata(rrset, current_rrset->rdata) != 0) {
			knot_rrset_free(&rrset);
			dbg_zp("zp: process_rr: Cannot "
			       "add RDATA to RRSet.\n");
			return KNOTDZCOMPILE_EBRDATA;
		}
		
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
			zc_warning_prev_line(
				"TTL does not match the TTL of the RRSet. "
				"Changing to %lu.\n", rrset->ttl);
		}

		if (knot_zone_contents_add_rrset(contents, current_rrset,
		                          &node,
		                   KNOT_RRSET_DUPL_MERGE, 1) < 0) {
			dbg_zp("zp: process_rr: Cannot "
			       "merge RRSets.\n");
			return KNOTDZCOMPILE_EBRDATA;
		}
	}

	if (vflag > 1 && totalrrs > 0 && (totalrrs % progress == 0)) {
		zc_error_prev_line("Total errors: %ld\n", totalrrs);
	}

	parser->last_node = node;
	++totalrrs;
	
	dbg_zp_verb("zp: process_rr: RRSet %p processed successfully.\n",
	            parser->current_rrset);
	return KNOTDZCOMPILE_EOK;
}

static int zone_open(const char *filename, uint32_t ttl, uint16_t rclass,
	  knot_node_t *origin, void *scanner, knot_dname_t *origin_from_config)
{
	/*!< \todo #1676 Implement proper locking. */
	zparser_init(filename, ttl, rclass, origin, origin_from_config);

	
	/* Open the zone file... */
	if (strcmp(filename, "-") == 0) {
		zp_set_in(stdin, scanner);
		filename = "<stdin>";
	} else {
		FILE *f = fopen(filename, "r");
		if (f == NULL) {
			return 0;
		}
		zp_set_in(f, scanner);
		if (zp_get_in(scanner) == 0) {
			return 0;
		}
	}
	
	return 1;
}

int zone_read(const char *name, const char *zonefile, const char *outfile,
	      int semantic_checks)
{
	if (!outfile) {
		zc_error_prev_line("Missing output file for '%s'\n",
			zonefile);
		return KNOTDZCOMPILE_EINVAL;
	}
	
	dbg_zp("zp: zone_read: Reading zone: %s.\n", zonefile);

	/* Check that we can write to outfile. */
	FILE *f = fopen(outfile, "wb");
	if (f == NULL) {
		log_zone_error("Cannot write zone db to file '%s' (%s).\n",
		        outfile, strerror(errno));
		return KNOTDZCOMPILE_EINVAL;
	}
	fclose(f);

	knot_dname_t *dname =
		knot_dname_new_from_str(name, strlen(name), NULL);
	if (dname == NULL) {
		return KNOTDZCOMPILE_ENOMEM;
	}

	if (!knot_dname_is_fqdn(dname)) {
		log_zone_error("Error: given zone origin is not FQDN.\n");
		knot_dname_release(dname);
		return KNOTDZCOMPILE_EINVAL;
	}

	knot_node_t *origin_node = knot_node_new(dname, NULL, 0);
	knot_dname_release(dname); /* Stored in node or should be freed. */
	if (origin_node == NULL) {
		return KNOTDZCOMPILE_ENOMEM;
	}
	
	assert(knot_node_parent(origin_node) == NULL);

	/*!< \todo Another copy is probably not needed. */
	knot_dname_t *origin_from_config =
		knot_dname_new_from_str(name, strlen(name), NULL);
	if (origin_from_config == NULL) {
		knot_node_free(&origin_node);
		return KNOTDZCOMPILE_ENOMEM;
	}

	void *scanner = NULL;
	zp_lex_init(&scanner);
	if (scanner == NULL) {
		knot_dname_release(origin_from_config);
		knot_node_free(&origin_node);
		return KNOTDZCOMPILE_ENOMEM;
	}

	if (!zone_open(zonefile, 3600, KNOT_CLASS_IN, origin_node, scanner,
	               origin_from_config)) {
		zc_error_prev_line("Cannot open '%s' (%s).",
		                   zonefile, strerror(errno));
		zp_lex_destroy(scanner);
		knot_dname_release(origin_from_config);
//		knot_node_free(&origin_node, 0);
		return KNOTDZCOMPILE_EZONEINVAL;
	}
	
	/* Lock zone file. There should not be any modifications. */
	struct flock lock;
	lock.l_type = F_RDLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;
	lock.l_pid = getpid();
	if (fcntl(fileno(zp_get_in(scanner)), F_SETLK, &lock) == -1) {
		log_zone_error("Cannot obtain zone source file lock (%d).\n",
		        errno);
		FILE *in_file = (FILE *)zp_get_in(scanner);
		fclose(in_file);
		zp_lex_destroy(scanner);
		knot_dname_release(origin_from_config);
		return KNOTDZCOMPILE_EINVAL;
	}
	
	/* Change lock type to unlock rigth away. */
	lock.l_type = F_UNLCK;

	if (zp_parse(scanner) != 0) {
		log_zone_error("Parse failed.\n");
		FILE *in_file = (FILE *)zp_get_in(scanner);
		fclose(in_file);
		knot_dname_release(origin_from_config);
//		knot_node_free(&origin_node, 0);
		/* Release file lock. */
		if (fcntl(fileno(zp_get_in(scanner)), F_SETLK, &lock) == -1) {
			log_zone_error("Cannot release zone source file "
			        "lock (%d).\n",
			        errno);
		}
		zp_lex_destroy(scanner);
		return KNOTDZCOMPILE_ESYNT;
	}

	knot_zone_contents_t *contents =
			knot_zone_get_contents(parser->current_zone);
	
	/* Release file lock. */
	if (fcntl(fileno(zp_get_in(scanner)), F_SETLK, &lock) == -1) {
		log_zone_error("Cannot release zone source file lock (%d).\n",
		        errno);
	}

	FILE *in_file = (FILE *)zp_get_in(scanner);
	fclose(in_file);
	zp_lex_destroy(scanner);

	dbg_zp("zp: zone_read: Parse complete for %s.\n",
	       zonefile);

	if (parser->last_node && parser->node_rrsigs != NULL) {
		/* assign rrsigs to last node in the zone*/
		process_rrsigs_in_node(contents,
		                       parser->last_node);
		rrset_list_delete(&parser->node_rrsigs);
	}

	dbg_zp("zp: zone_read: RRSIGs processed.\n");

	if (!(parser->current_zone &&
	      knot_node_rrset(parser->current_zone->contents->apex,
	                        KNOT_RRTYPE_SOA))) {
		zc_error_prev_line("Zone file does not contain SOA record!\n");
//		knot_zone_deep_free(&parser->current_zone, 1);
		knot_dname_release(origin_from_config);
//		knot_node_free(&origin_node, 0);
		return KNOTDZCOMPILE_EZONEINVAL;
	}

	int ret = knot_zone_contents_adjust(contents);
	if (ret != KNOT_EOK) {
		fprintf(stderr, "Zone could not be adjusted, error: %s.\n",
		        knot_strerror(ret));
		parser->errors++;
	}
	
	dbg_zp("zp: zone_read: Zone adjusted.\n");

	if (parser->errors != 0) {
		log_zone_error("Parser finished with %d error(s), "
		               "not dumping the zone!\n",
		               parser->errors);
	} else {
		int fd = open(outfile, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG);
		if (fd < 0) {
			log_zone_error("Could not open destination file for db: %s.\n",
			               outfile);
			totalerrors++;
		} else {
			crc_t crc;
			int ret = knot_zdump_binary(contents, fd,
			                            semantic_checks,
			                            zonefile, &crc);
			if (ret != KNOT_EOK) {
				log_zone_error("Could not dump zone, reason: "
				               "%s.\n", knot_strerror(ret));
				if (remove(outfile) != 0) {
					log_zone_error("Could not remove "
					               "db file!\n");
				}
				totalerrors++;
			} else {
				/* Write CRC file. */
				char *crc_path = knot_zdump_crc_file(outfile);
				if (crc_path == NULL) {
					log_zone_error(
					"Could not get crc file path.\n");
					remove(outfile);
					totalerrors++;
				} else {
					FILE *f_crc = fopen(crc_path, "w");
					if (f_crc == NULL) {
						log_zone_error(
						"Could not open crc file \n");
						remove(outfile);
						totalerrors++;
					} else {
						fprintf(f_crc,
						        "%lu",
						        (unsigned long)crc);
						fclose(f_crc);
					}
				}
				free(crc_path);
			}
		}


		dbg_zp("zp: zone_read: Zone %s dumped successfully.\n",
		       zonefile);
	}

	fflush(stdout);
	totalerrors += parser->errors;
	knot_dname_release(origin_from_config);

	return totalerrors;
}

/*! @} */
