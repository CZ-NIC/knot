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
#include "zcompile/zcompile.h"
#include "zcompile/parser-util.h"
#include "zcompile/zcompile-error.h"
#include "knot/zone/zone-dump.h"
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

#ifdef KNOT_COMPILER_DEBUG
#define dbg_zp(msg...) fprintf(stderr, msg)
#else
#define dbg_zp(msg...)
#endif

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
}

static int find_rrset_for_rrsig_in_zone(knot_zone_contents_t *zone,
                                        knot_rrset_t *rrsig)
{
	assert(rrsig != NULL);
	assert(rrsig->rdata->items[0].raw_data);

	knot_node_t *tmp_node = NULL;

	if (knot_rdata_rrsig_type_covered(knot_rrset_rdata(rrsig))
		!= KNOT_RRTYPE_NSEC3) {
		tmp_node = knot_zone_contents_get_node(zone, rrsig->owner);
	} else {
		tmp_node = knot_zone_contents_get_nsec3_node(zone,
						      rrsig->owner);
	}
	
	dbg_zp("Found this node for RRSIG: %p\n",
	       tmp_node);

	if (tmp_node == NULL) {
		return KNOTDZCOMPILE_EINVAL;
	}

	knot_rrset_t *tmp_rrset =
		knot_node_get_rrset(tmp_node,
	                            knot_rdata_rrsig_type_covered(
	                                    rrsig->rdata));
	
	dbg_zp("Found this rrset for RRSIG: %p\n",
	       tmp_rrset);

	if (tmp_rrset == NULL) {
		return KNOTDZCOMPILE_EINVAL;
	}
	

	if (tmp_rrset->rrsigs != NULL) {
		knot_zone_contents_add_rrsigs(zone, rrsig, &tmp_rrset, &tmp_node,
		                       KNOT_RRSET_DUPL_MERGE, 1);
		knot_rrset_free(&rrsig);
	} else {
		knot_zone_contents_add_rrsigs(zone, rrsig, &tmp_rrset, &tmp_node,
		                       KNOT_RRSET_DUPL_SKIP, 1);
	}

	return KNOTDZCOMPILE_EOK;
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

	if (tmp_rrset == NULL) {
		return KNOTDZCOMPILE_EINVAL;
	}

	if (tmp_rrset->rrsigs != NULL) {
		if (knot_zone_contents_add_rrsigs(zone, rrsig, &tmp_rrset, &node,
		                           KNOT_RRSET_DUPL_MERGE, 1) < 0) {
			return KNOTDZCOMPILE_EINVAL;
		}
		knot_rrset_free(&rrsig);
	} else {
		if (knot_zone_contents_add_rrsigs(zone, rrsig, &tmp_rrset, &node,
		                           KNOT_RRSET_DUPL_SKIP, 1) < 0) {
			return KNOTDZCOMPILE_EINVAL;
		}
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
	rrset_list_t *tmp = parser->node_rrsigs;
	while (tmp != NULL) {
		if (find_rrset_for_rrsig_in_node(zone, node,
						 tmp->data) != 0) {
			rrset_list_add(&parser->rrsig_orphans,
				       tmp->data);
			parser->rrsig_orphan_count++;
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

	dbg_zp("%s\n", knot_dname_to_str(parser->current_rrset->owner));
	dbg_zp("type: %s\n", knot_rrtype_to_string(parser->current_rrset->type));
	dbg_zp("rdata count: %d\n", parser->current_rrset->rdata->count);
//	hex_print(parser->current_rrset->rdata->items[0].raw_data,
//	          parser->current_rrset->rdata->items[0].raw_data[0]);

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
			if (!knot_rrset_compare(current_rrset,
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
		knot_rrset_t *tmp_rrsig =
			knot_rrset_new(current_rrset->owner,
					     KNOT_RRTYPE_RRSIG,
					     current_rrset->rclass,
					     current_rrset->ttl);
		if (tmp_rrsig == NULL) {
			return KNOTDZCOMPILE_ENOMEM;
		}

		if (knot_rrset_add_rdata(tmp_rrsig,
		                           current_rrset->rdata) != KNOT_EOK) {
			knot_rrset_free(&tmp_rrsig);
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
					return KNOTDZCOMPILE_EBADNODE;
				}
			}
		}

		if (rrset_list_add(&parser->node_rrsigs, tmp_rrsig) != 0) {
			return KNOTDZCOMPILE_ENOMEM;
		}

		return KNOTDZCOMPILE_EOK;
	}

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
			return KNOTDZCOMPILE_ENOMEM;
		}

		if (knot_rrset_add_rdata(rrset, current_rrset->rdata) != 0) {
			free(rrset);
			return KNOTDZCOMPILE_EBRDATA;
		}

		/* I chose skip, but there should not really be
		 * any rrset to skip */
		if (knot_zone_contents_add_rrset(contents, rrset, &node,
		                   KNOT_RRSET_DUPL_SKIP, 1) < 0) {
			free(rrset);
			return KNOTDZCOMPILE_EBRDATA;
		}
	} else {
		if (current_rrset->type !=
				KNOT_RRTYPE_RRSIG && rrset->ttl !=
				current_rrset->ttl) {
			zc_error_prev_line(
				"TTL does not match the TTL of the RRset");
		}

		if (knot_zone_contents_add_rrset(contents, current_rrset,
		                          &node,
		                   KNOT_RRSET_DUPL_MERGE, 1) < 0) {
			return KNOTDZCOMPILE_EBRDATA;
		}
	}

	if (vflag > 1 && totalrrs > 0 && (totalrrs % progress == 0)) {
		zc_error_prev_line("Total errors: %ld\n", totalrrs);
	}

	parser->last_node = node;

	++totalrrs;

	return KNOTDZCOMPILE_EOK;
}

static uint find_rrsets_orphans(knot_zone_contents_t *zone, rrset_list_t
				*head)
{
	uint found_rrsets = 0;
	while (head != NULL) {
		if (find_rrset_for_rrsig_in_zone(zone, head->data) == 0) {
			found_rrsets += 1;
			dbg_zp("RRSET succesfully found: owner %s type %s\n",
				 knot_dname_to_str(head->data->owner),
				 knot_rrtype_to_string(head->data->type));
		}
		else { /* we can throw it away now */
			dbg_zp("RRSet not found for RRSIG: %s (%s)\n",
			       knot_dname_to_str(head->data->owner),
			       knot_rrtype_to_string(
			  knot_rdata_rrsig_type_covered(head->data->rdata)));
			knot_rrset_free(&head->data);
		}
		head = head->next;
	}
	return found_rrsets;
}

static int zone_open(const char *filename, uint32_t ttl, uint16_t rclass,
	  knot_node_t *origin, void *scanner, knot_dname_t *origin_from_config)
{
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

	/*!< \todo #1676 Implement proper locking. */

	zparser_init(filename, ttl, rclass, origin, origin_from_config);

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

	/* Check that we can write to outfile. */
	FILE *f = fopen(outfile, "wb");
	if (f == NULL) {
		fprintf(stderr, "Cannot write zone db to file '%s' (%s).\n",
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
		fprintf(stderr, "Error: given zone origin is not FQDN.\n");
		knot_dname_release(dname);
		return KNOTDZCOMPILE_EINVAL;
	}

	knot_node_t *origin_node = knot_node_new(dname, NULL, 0);

	if (origin_node == NULL) {
		knot_dname_release(dname);
		return KNOTDZCOMPILE_ENOMEM;
	}
	
	assert(knot_node_parent(origin_node) == NULL);

	/*!< \todo Another copy is probably not needed. */
	knot_dname_t *origin_from_config =
		knot_dname_new_from_str(name, strlen(name), NULL);
	if (origin_from_config == NULL) {
		knot_node_free(&origin_node, 0);
		return KNOTDZCOMPILE_ENOMEM;
	}

	void *scanner = NULL;
	zp_lex_init(&scanner);
	if (scanner == NULL) {
		knot_dname_release(origin_from_config);
		knot_node_free(&origin_node, 0);
		return KNOTDZCOMPILE_ENOMEM;
	}

	if (!zone_open(zonefile, 3600, KNOT_CLASS_IN, origin_node, scanner,
	               origin_from_config)) {
		zc_error_prev_line("Cannot open '%s' (%s).",
		                   zonefile, strerror(errno));
		zparser_free();
		zp_lex_destroy(scanner);
		knot_dname_release(origin_from_config);
		knot_node_free(&origin_node, 0);
		return KNOTDZCOMPILE_EZONEINVAL;
	}

	if (zp_parse(scanner) != 0) {
		/*!< \todo #1676 Implement proper locking. */
		FILE *in_file = (FILE *)zp_get_in(scanner);
		fclose(in_file);
		zp_lex_destroy(scanner);
		knot_node_free(&origin_node, 0);
		return KNOTDZCOMPILE_ESYNT;
	}

	knot_zone_contents_t *contents =
			knot_zone_get_contents(parser->current_zone);

	FILE *in_file = (FILE *)zp_get_in(scanner);
	fclose(in_file);
	zp_lex_destroy(scanner);
	
	/*!< \todo #1676 Implement proper locking. */

	dbg_zp("zp complete %p\n", parser->current_zone);

	if (parser->last_node && parser->node_rrsigs != NULL) {
		/* assign rrsigs to last node in the zone*/
		process_rrsigs_in_node(contents,
		                       parser->last_node);
		rrset_list_delete(&parser->node_rrsigs);
	}

	dbg_zp("zone parsed\n");

	if (!(parser->current_zone &&
	      knot_node_rrset(parser->current_zone->contents->apex,
	                        KNOT_RRTYPE_SOA))) {
		zc_error_prev_line("Zone file does not contain SOA record!\n");
		knot_zone_deep_free(&parser->current_zone, 1);
		zparser_free();
		knot_node_free(&origin_node, 0);
		return KNOTDZCOMPILE_EZONEINVAL;
	}

	uint found_orphans;
	found_orphans = find_rrsets_orphans(contents,
					    parser->rrsig_orphans);

	dbg_zp("%u orphans found\n", found_orphans);

	rrset_list_delete(&parser->rrsig_orphans);

	if (found_orphans != parser->rrsig_orphan_count) {
		/*! \todo This might be desired behaviour. */
		fprintf(stderr,
		        "There are unassigned RRSIGs in the zone!\n");
		parser->errors++;
	}

	/*! \todo Check return value. */
	knot_zone_contents_adjust(contents);

	dbg_zp("rdata adjusted\n");

	if (parser->errors != 0) {
		fprintf(stderr,
		        "Parser finished with error, not dumping the zone!\n");
	} else {
		int fd = open(outfile, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG);
		if (fd < 0) {
			fprintf(stderr,
			        "Could not open destination file for db: %s.\n",
			        outfile);
			totalerrors++;
		} else {
			crc_t crc;
			int ret = knot_zdump_binary(contents, fd,
			                            semantic_checks,
			                            zonefile, &crc);
			if (ret != KNOT_EOK) {
				fprintf(stderr, "Could not dump zone, reason: "
				                "%s.\n", knot_strerror(ret));
				remove(outfile);
				totalerrors++;
			} else {
				/* Write CRC file. */
				char *crc_path = knot_zdump_crc_file(outfile);
				if (crc_path == NULL) {
					fprintf(stderr,
					        "Could not get crc file path.\n");
					remove(outfile);
					totalerrors++;
				} else {
					FILE *f_crc = fopen(crc_path, "w");
					if (f_crc == NULL) {
						fprintf(stderr,
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


		dbg_zp("zone dumped.\n");
	}

	fflush(stdout);
	totalerrors += parser->errors;
	zparser_free();

	return totalerrors;
}

/*! @} */
