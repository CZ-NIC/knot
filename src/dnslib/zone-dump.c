#include <config.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include "common.h"
#include "dnslib/zone-dump.h"
#include "dnslib/dnslib.h"
#include "lib/skip-list.h"

#define ZONECHECKS_VERBOSE

/* \note For space and speed purposes, dname ID (to be later used in loading)
 * is being stored in dname->node field. Not to be confused with dname's actual
 * node.
 */

/* \note Contents of dump file:
 * MAGIC(knotxx) NUMBER_OF_NORMAL_NODES NUMBER_OF_NSEC3_NODES
 * [normal_nodes] [nsec3_nodes]
 * node has following format:
 * owner_size owner_wire owner_label_size owner_labels owner_id
 * node_flags node_rrset_count [node_rrsets]
 * rrset has following format:
 * rrset_type rrset_class rrset_ttl rrset_rdata_count rrset_rrsig_count
 * [rrset_rdata] [rrset_rrsigs]
 * rdata can either contain full dnames (that is with labels but without ID)
 * or dname ID, if dname is in the zone
 * or raw data stored like this: data_len [data]
 */

static const uint MAX_CNAME_CYCLE_DEPTH = 15;

struct arg {
	void *arg1; /* FILE *f / zone */
	void *arg2; /* skip_list_t */
	void *arg3; /* zone */
};

typedef struct arg arg_t;

/* we only need ordering for search purposes, therefore it is OK to compare
 * pointers directly */
static int compare_pointers(void *p1, void *p2)
{
	return ((size_t)p1 == (size_t)p2 ? 0 : (size_t)p1 < (size_t)p2 ? -1 : 1);
}

/* Functions for zone traversal are taken from dnslib/zone.c */
static void dnslib_zone_save_encloser_rdata_item(dnslib_rdata_t *rdata,
                                                 dnslib_zone_t *zone, uint pos,
					         skip_list_t *list)
{
	const dnslib_rdata_item_t *dname_item
		= dnslib_rdata_item(rdata, pos);

	if (dname_item != NULL) {
		dnslib_dname_t *dname = dname_item->dname;
		const dnslib_node_t *n = NULL;
		const dnslib_node_t *closest_encloser = NULL;
		const dnslib_node_t *prev = NULL;

		int exact = dnslib_zone_find_dname(zone, dname, &n,
		                                   &closest_encloser, &prev);

//		n = dnslib_zone_find_node(zone, dname);

		assert(!exact || n == closest_encloser);

		if (!exact && (closest_encloser != NULL)) {
			debug_dnslib_zone("Saving closest encloser to RDATA.\n");
			// save pointer to the closest encloser
			dnslib_rdata_item_t *item =
				dnslib_rdata_get_item(rdata, pos);
			assert(item->dname != NULL);
			assert(item->dname->node == NULL);
			skip_insert(list, (void *)item->dname,
				    (void *)closest_encloser->owner, NULL);
		}
	}
}

static void dnslib_zone_save_enclosers_node(dnslib_node_t *node,
                                            dnslib_rr_type_t type,
                                            dnslib_zone_t *zone,
					    skip_list_t *list)
{
	dnslib_rrset_t *rrset = dnslib_node_get_rrset(node, type);
	if (!rrset) {
		return;
	}

	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(type);
	dnslib_rdata_t *rdata_first = dnslib_rrset_get_rdata(rrset);
	dnslib_rdata_t *rdata = rdata_first;

	if (rdata == NULL) {
		return;
	}

	while (rdata->next != rdata_first) {
		for (int i = 0; i < rdata->count; ++i) {
			if (desc->wireformat[i]
			    == DNSLIB_RDATA_WF_COMPRESSED_DNAME
			    || desc->wireformat[i]
			       == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME
			    || desc->wireformat[i]
			       == DNSLIB_RDATA_WF_LITERAL_DNAME) {
				debug_dnslib_zone("Adjusting domain name at "
				  "position %d of RDATA of record with owner "
				  "%s and type %s.\n",
				  i, rrset->owner->name,
				  dnslib_rrtype_to_string(type));

				dnslib_zone_save_encloser_rdata_item(rdata,
				                                     zone,
								     i,
								     list);
			}
		}
		rdata = rdata->next;
	}

	for (int i = 0; i < rdata->count; ++i) {
		if (desc->wireformat[i]
		    == DNSLIB_RDATA_WF_COMPRESSED_DNAME
		    || desc->wireformat[i]
		       == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME
		    || desc->wireformat[i]
		       == DNSLIB_RDATA_WF_LITERAL_DNAME) {
			debug_dnslib_zone("Adjusting domain name at "
			  "position %d of RDATA of record with owner "
			  "%s and type %s.\n",
			  i, rrset->owner->name,
			  dnslib_rrtype_to_string(type));

				dnslib_zone_save_encloser_rdata_item(rdata,
				                                     zone,
								     i,
								     list);
		}
	}
}

/* ret 0 OK, -1 cycle, -2 invalid cycle (destination not found) */
static int check_cname_cycles_in_zone(dnslib_zone_t *zone,
				      const dnslib_rrset_t *rrset)
{
	const dnslib_rrset_t *next_rrset = rrset;
	assert(rrset);
	const dnslib_rdata_t *tmp_rdata = dnslib_rrset_rdata(next_rrset);
	const dnslib_node_t *next_node = NULL;

	uint i = 0;

	assert(tmp_rdata);

	const dnslib_dname_t *next_dname =
		dnslib_rdata_cname_name(tmp_rdata);

	assert(next_dname);

	while (i < MAX_CNAME_CYCLE_DEPTH && next_dname != NULL) {
		next_node = dnslib_zone_get_node(zone, next_dname);
		if (next_node == NULL) {
			next_node =
				dnslib_zone_get_nsec3_node(zone, next_dname);
		}

		if (next_node != NULL) {
			next_rrset = dnslib_node_rrset(next_node,
						       DNSLIB_RRTYPE_CNAME);
			if (next_rrset != NULL) {
				next_dname =
				dnslib_rdata_cname_name(next_rrset->rdata);
			} else {
				next_node = NULL;
				next_dname = NULL;
			}
		} else {
			next_dname = NULL;
		}
		i++;
	}

	/* even if the length is 0, i will be 1 */
	if (i >= MAX_CNAME_CYCLE_DEPTH) {
		return -1;
	}

	return 0;
}

static inline uint16_t *rdata_item_data(const dnslib_rdata_item_t *item)
{
	return (uint16_t *)(item->raw_data + 1);
}

uint16_t type_covered_from_rdata(const dnslib_rdata_t *rdata)
{
	return ntohs(*(uint16_t *) rdata_item_data(&(rdata->items[0])));
}

static int check_dnskey_rdata(const dnslib_rdata_t *rdata)
{
	/* check that Zone key bit it set - position 7 in net order */
	/* FIXME endian */
	uint16_t mask = 0b0000000100000000;

	uint16_t flags =
		dnslib_wire_read_u16((uint8_t *)rdata_item_data
				     (dnslib_rdata_item(rdata, 0)));

	if (flags & mask) {
		return 0;
	} else {
		return -1;
	}
}


/* Taken from RFC 4034 */
/*
 * Assumes that int is at least 16 bits.
 * First octet of the key tag is the most significant 8 bits of the
 * return value;
 * Second octet of the key tag is the least significant 8 bits of the
 * return value.
 */

static uint16_t keytag(uint8_t *key, uint16_t keysize )
{
        uint32_t ac = 0;     /* assumed to be 32 bits or larger */

        for(int i = 0; i < keysize; i++) {
                ac += (i & 1) ? key[i] : key[i] << 8;
        }

        ac += (ac >> 16) & 0xFFFF;
        uint16_t kokotina = (uint16_t) (ac & 0xFFFF);
        return (uint16_t)ac & 0xFFFF;
}

static uint16_t keytag_1(uint8_t *key, uint16_t keysize)
{
        uint16_t ac = 0;
        if (keysize > 4) {
                memmove(&ac, key + keysize - 3, 2);
        }

        ac = ntohs(ac);
        return ac;
}

static inline uint16_t rdata_item_size(const dnslib_rdata_item_t *item)
{
        return item->raw_data[0];
}


uint remove_me = 0;

static uint16_t *dnskey_to_wire(dnslib_rdata_t *rdata)
{
        uint8_t *data =
malloc(sizeof(uint8_t) * (2 + 1 + 1 + rdata->items[3].raw_data[0]));
        remove_me = sizeof(uint8_t) * (2 + 1 + 1 + rdata->items[3].raw_data[0]);
        data[0] = ((uint8_t *)(rdata->items[0].raw_data))[2];
        data[1] = ((uint8_t *)(rdata->items[0].raw_data))[3];

        data[2] = ((uint8_t *)(rdata->items[1].raw_data))[2];
        data[3] = ((uint8_t *)(rdata->items[2].raw_data))[2];
        memcpy(data + 4, rdata->items[3].raw_data + 1,
               rdata->items[3].raw_data[0]);
        return (uint16_t *) data;
}

static int check_rrsig_rdata(const dnslib_rdata_t *rdata_rrsig,
			     const dnslib_rrset_t *rrset,
			     const dnslib_rrset_t *dnskey_rrset)
{
	if (type_covered_from_rdata(rdata_rrsig) !=
	    dnslib_rrset_type(rrset)) {
		/* zoneparser would not let this happen
		 * but to be on the safe side
		 */
		return -1;
	}

	/* label number at the 2nd index should be same as owner's */
	uint16_t *raw_data =
		rdata_item_data(dnslib_rdata_item(rdata_rrsig, 2));

	uint8_t labels_rdata = ((uint8_t *)raw_data)[0];

	if (labels_rdata !=
            dnslib_dname_label_count(dnslib_rrset_owner(rrset))) {
#ifdef ZONECHECKS_VERBOSE
                log_zone_error("Label counts do not match: in rdata: %d "
                               "in owner: %d\n", labels_rdata,
                        dnslib_dname_label_count(dnslib_rrset_owner(rrset)));
#endif
                return -2;
	}

	/* check original TTL */
	uint32_t original_ttl =
		dnslib_wire_read_u32((uint8_t *)rdata_item_data(
				     dnslib_rdata_item(rdata_rrsig, 3)));

	if (original_ttl != dnslib_rrset_ttl(rrset)) {
		return -3;
	}

	/* signer's name is same as in the zone apex */
	dnslib_dname_t *signer_name =
		dnslib_rdata_item(rdata_rrsig, 7)->dname;

	/* dnskey is in the apex node */
	if (dnslib_dname_compare(signer_name,
				 dnslib_rrset_owner(dnskey_rrset)) != 0) {
		return -4;
	}

	/* Compare algorithm, key tag and signer's name with DNSKEY rrset
	 * one of the records has to match. Signer name has been checked
	 * before */
	char match = 0;
	const dnslib_rdata_t *tmp_dnskey_rdata =
		dnslib_rrset_rdata(dnskey_rrset);
	do {
		uint8_t alg =
                ((uint8_t *)(dnslib_rdata_item(rdata_rrsig, 1)->raw_data))[2];
		uint8_t alg_dnskey =
		((uint8_t *)(dnslib_rdata_item(tmp_dnskey_rdata,
                                               2)->raw_data))[2];

		raw_data = rdata_item_data(dnslib_rdata_item(rdata_rrsig, 6));
		uint16_t key_tag_rrsig =
			dnslib_wire_read_u16((uint8_t *)raw_data);

                raw_data =
			rdata_item_data(dnslib_rdata_item(
                                        tmp_dnskey_rdata, 3));

                uint16_t raw_length = rdata_item_size(dnslib_rdata_item(
                                                     tmp_dnskey_rdata, 3));

                uint16_t key_tag_dnskey = keytag(dnskey_to_wire(tmp_dnskey_rdata),
                                                 remove_me);

		match = (alg == alg_dnskey) &&
			(key_tag_rrsig == key_tag_dnskey) &&
                        !check_dnskey_rdata(tmp_dnskey_rdata);

	} while (!match &&
		 ((tmp_dnskey_rdata =
			dnslib_rrset_rdata_next(dnskey_rrset,
						tmp_dnskey_rdata))
		!= NULL));

	if (!match) {
		return -5;
	}

	return 0;
}

/*
  return 0 - Ok
  return -1 NO RRSIGS
  return -2

 */
static int check_rrsig_in_rrset(const dnslib_rrset_t *rrset,
				const dnslib_rrset_t *dnskey_rrset,
				char nsec3)
{
	assert(dnskey_rrset && rrset);

	const dnslib_rrset_t *rrsigs = dnslib_rrset_rrsigs(rrset);

	if (rrsigs == NULL) {
		return -1;
	}

	/* signed rrsig - nonsense */
	if (dnslib_rrset_rrsigs(rrsigs) != NULL) {
		return -2;
	}

	/* Different owner, class, ttl */

	if (dnslib_dname_compare(dnslib_rrset_owner(rrset),
				 dnslib_rrset_owner(rrsigs)) != 0) {
		return -3;
	}

	if (dnslib_rrset_class(rrset) != dnslib_rrset_class(rrsigs)) {
		return -4;
	}

	if (dnslib_rrset_ttl(rrset) != dnslib_rrset_ttl(rrset)) {
		return -5;
	}

	/* Check whether all rrsets have their rrsigs */
	const dnslib_rdata_t *tmp_rdata = dnslib_rrset_rdata(rrset);
	const dnslib_rdata_t *tmp_rrsig_rdata = dnslib_rrset_rdata(rrsigs);

	assert(tmp_rdata);
	assert(tmp_rrsig_rdata);
	int ret = 0;
	do {
		if ((ret = check_rrsig_rdata(tmp_rrsig_rdata,
					     rrset,
					     dnskey_rrset)) != 0) {
			return ret * 10;
		}
	} while ((tmp_rdata = dnslib_rrset_rdata_next(rrset, tmp_rdata))
		!= NULL &&
		((tmp_rrsig_rdata =
			dnslib_rrset_rdata_next(rrsigs, tmp_rrsig_rdata))
		!= NULL));

	if (tmp_rdata != NULL &&
	    tmp_rrsig_rdata != NULL) {
		/* Not all records in rrset are signed */
		return -6;
	}

	return 0;
}

int get_bit(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	return bits[index / 8] & (1 << (7 - index % 8));
}

static int rdata_nsec_to_type_array(const dnslib_rdata_item_t *item,
			      uint16_t **array,
			      uint *count)
{
	assert(*array == NULL);

        hex_print(rdata_item_data(item), rdata_item_size(item));

	uint8_t *data = (uint8_t *)rdata_item_data(item);

	int increment = 1;

        for (int i = 1; i < rdata_item_size(item); i += increment) {
                *count = 0;
		uint8_t window = data[i];
		/* TODO probably wrong set in parser, should
		 *be 0 in most of the cases.
		 */
                window = 0;
		uint8_t bitmap_size = data[i+1];
                uint8_t *bitmap =
			malloc(sizeof(uint8_t) * (bitmap_size >
						  rdata_item_size(item) ?
						  bitmap_size :
                                                  rdata_item_size(item)));

		memset(bitmap, 0,
		       sizeof(uint8_t) *  bitmap_size > rdata_item_size(item) ?
		       bitmap_size :
		       rdata_item_size(item));

		memcpy(bitmap, data + i + 1, rdata_item_size(item) - (i + 1));

		increment += bitmap_size + 3;

		for (int j = 0; j < bitmap_size * 8; j++) {
                        if (get_bit(bitmap, j)) {
                                (*count)++;
				void *tmp = realloc(*array,
						    sizeof(uint16_t) *
						    *count);
				CHECK_ALLOC_LOG(tmp, -1);
				*array = tmp;
                                (*array)[*count - 1] = j + window * 256;
			}
		}
		free(bitmap);
        }

	return 0;
}

static int check_nsec3_node_in_zone(dnslib_zone_t *zone, dnslib_node_t *node)
{
	const dnslib_node_t *nsec3_node = dnslib_node_nsec3_node(node);

	if (nsec3_node == NULL) {
		/* I know it's probably not what RFCs say, but it will have to
		 * do for now. */
		if (dnslib_node_rrset(node, DNSLIB_RRTYPE_DS) != NULL) {
			return -1;
		} else {
			/* Unsecured delegation, check whether it is part of
			 * opt-out span */
			/* TODO */
			;
		}
	}

	const dnslib_rrset_t *nsec3_rrset =
		dnslib_node_rrset(nsec3_node, DNSLIB_RRTYPE_NSEC3);

	assert(nsec3_rrset);

	uint32_t minimum_ttl =
		dnslib_wire_read_u32((uint8_t *)
		rdata_item_data(
		dnslib_rdata_item(
		dnslib_rrset_rdata(
		dnslib_node_rrset(
		dnslib_zone_apex(zone), DNSLIB_RRTYPE_SOA)), 6)));
	/* are those getter even worth this? */

	if (dnslib_rrset_ttl(nsec3_rrset) != minimum_ttl) {
		return -2;
	}

	/* check that next dname is in the zone */

	dnslib_dname_t *next_dname =
		dnslib_rdata_item(
		dnslib_rrset_rdata(nsec3_rrset), 6)->dname;

	if (dnslib_zone_find_nsec3_node(zone, next_dname) == NULL) {
		return -3;
	}

	/* This is probably not sufficient, but again, it is covered in
	 * zone load time */

	/* TODO bitmap, but that is buggy right now */

	return 0;
}

static void dnslib_zone_save_enclosers_in_tree(dnslib_node_t *node, void *data)
{
	assert(data != NULL);
	arg_t *args = (arg_t *)data;

	char do_checks = *((char *)(args->arg3));

	for (int i = 0; i < DNSLIB_COMPRESSIBLE_TYPES; ++i) {
		dnslib_zone_save_enclosers_node(node,
						dnslib_compressible_types[i],
						(dnslib_zone_t *)args->arg1,
						(skip_list_t *)args->arg2);
	}

	/* TODO move to separate function */
	if (do_checks) {
		const dnslib_rrset_t *cname_rrset =
			dnslib_node_rrset(node, DNSLIB_RRTYPE_CNAME);
		if (cname_rrset != NULL) {
			if (check_cname_cycles_in_zone((dnslib_zone_t *)
				args->arg1,
				cname_rrset) != 0) {
				char *name =
				dnslib_dname_to_str(dnslib_node_owner(node));
				log_zone_error("Node %s contains "
					       "CNAME cycle!\n", name);
				free(name);

				/* TODO how to propagate the error */
			}
		}

		/* TODO move things below to the if above */

		/* No DNSSEC and yet there is more than one rrset in node */
		if (cname_rrset &&
		    dnslib_node_rrset_count(node) != 1 && do_checks == 1) {
			char *name =
			dnslib_dname_to_str(dnslib_node_owner(node));
			log_zone_error("Node %s contains more than one RRSet "
				       "but has CNAME record!\n", name);
			free(name);
		} else if (cname_rrset &&
			   dnslib_node_rrset_count(node) != 1) {
			/* With DNSSEC node can contain RRSIG or NSEC */
			if (!(dnslib_node_rrset(node, DNSLIB_RRTYPE_RRSIG) ||
			    dnslib_node_rrset(node, DNSLIB_RRTYPE_NSEC))) {
				char *name =
				dnslib_dname_to_str(dnslib_node_owner(node));
				log_zone_error("Node %s contains other records "
				"than RRSIG and/or NSEC together with CNAME "
				"record!\n", name);
				free(name);
			}
		}

		/* same thing */

		if (cname_rrset &&
		    dnslib_rrset_rdata(cname_rrset)->count != 1) {
			char *name =
				dnslib_dname_to_str(dnslib_node_owner(node));
			log_zone_error("Node %s contains more than one CNAME "
				       "record!\n", name);
			free(name);
		}

		/* check for glue records at zone cuts */
		if (dnslib_node_is_deleg_point(node)) {
			const dnslib_rrset_t *ns_rrset =
				dnslib_node_rrset(node, DNSLIB_RRTYPE_NS);
			assert(ns_rrset);
			//FIXME this should be an error as well ! (i guess)

			const dnslib_dname_t *ns_dname =
				dnslib_rdata_get_item(dnslib_rrset_rdata
						      (ns_rrset), 0)->dname;

			assert(ns_dname);

			const dnslib_node_t *glue_node =
				dnslib_zone_find_node((dnslib_zone_t *)
						      args->arg1, ns_dname);

			if (glue_node == NULL) {
				char *name =
					dnslib_dname_to_str(ns_dname);
				log_zone_error("Glue node not found "
					       "for dname: %s\n",
					       name);
				free(name);
				return;
			}

			if ((dnslib_node_rrset(glue_node,
					       DNSLIB_RRTYPE_A) == NULL) &&
			    (dnslib_node_rrset(glue_node,
					       DNSLIB_RRTYPE_AAAA) == NULL)) {
				char *name =
					dnslib_dname_to_str(ns_dname);
				log_zone_error("Glue address not found "
					       "for dname: %s\n",
					       name);
				free(name);
				return;
			}
		}
	}

	if (do_checks > 1) {
		char auth = !dnslib_node_is_non_auth(node);
		char deleg = dnslib_node_is_deleg_point(node);
		uint rrset_count = dnslib_node_rrset_count(node);
		const dnslib_rrset_t **rrsets = dnslib_node_rrsets(node);
		const dnslib_rrset_t *dnskey_rrset =
			dnslib_node_rrset(dnslib_zone_apex(
					  (dnslib_zone_t *)args->arg1),
					  DNSLIB_RRTYPE_DNSKEY);

                char nsec3 = do_checks == 3;

                int ret = 0;

		/* there is no point in checking non_authoritative node */
		for (int i = 0; i < rrset_count && auth; i++) {
                        const dnslib_rrset_t *rrset = rrsets[i];
                        if ((ret = check_rrsig_in_rrset(rrset, dnskey_rrset,
                                                 nsec3)) != 0) {
                                log_zone_error("RRSIG %d node %s\n", ret,
                                               dnslib_dname_to_str(node->owner));
			}

			if (!nsec3 && auth) {
				/* check for NSEC record */
				const dnslib_rrset_t *nsec_rrset =
					dnslib_node_rrset(node,
							  DNSLIB_RRTYPE_NSEC);

				if (nsec_rrset == NULL) {
					log_zone_error("TODO nsec");
					return;
				}

				/* check NSEC/NSEC3 bitmap */

				uint count;

				uint16_t *array = NULL;

				if (rdata_nsec_to_type_array(
				    dnslib_rdata_item(
                                    dnslib_rrset_rdata(nsec_rrset),1),
                                    &array, &count) != 0) {
                                        assert(0);
					//error
					;
				}

				uint16_t type = 0;
				for (int j = 0; j < count; j++) {
					/* test for each type's presence */
                                        type = array[j];
                                        if (type == DNSLIB_RRTYPE_RRSIG) {
                                                continue;
                                        }
					if (dnslib_node_rrset(node,
							      type) == NULL) {
						char *name =
						dnslib_dname_to_str(
						dnslib_node_owner(node));

						log_zone_error("Node %s does "
						"not contain RRSet of type %s "
						"but NSEC bitmap says "
						"it does!\n", name,
						dnslib_rrtype_to_string(type));

						free(name);
					}
				}

				/* Test that only one record is in the
				 * NSEC RRSet */

                                if (dnslib_rrset_rdata(nsec_rrset)->next !=
                                    dnslib_rrset_rdata(nsec_rrset)) {
					char *name =
						dnslib_dname_to_str(
						dnslib_node_owner(node));
					log_zone_error("Node %s contains more "
						       "than one NSEC "
                                                       "record!\n", name);
                                        printf("FDASDF %d\n", nsec_rrset->rdata->count);
                                        dnslib_rrset_dump(nsec_rrset, 0);
					free(name);
				}

				/*
				 * Test that NSEC chain is coherent.
				 * We have already checked that every
				 * authoritative node contains NSEC record
				 * so checking should only be matter of testing
				 * the next link in each node.
				 */

				dnslib_dname_t *next_domain =
					dnslib_rdata_item(
					dnslib_rrset_rdata(nsec_rrset),
					0)->dname;

				assert(next_domain);

				/* TODO do this at the beginning! */
				dnslib_zone_t *zone =
					(dnslib_zone_t *)args->arg1;

				if (dnslib_zone_find_node(zone, next_domain) ==
				    NULL) {
					log_zone_error("NSEC chain is not "
						       "coherent!\n");
				}
			} else if (auth || deleg) { /* nsec3 */
				/* TODO do this at the beginning! */
				dnslib_zone_t *zone =
					(dnslib_zone_t *)args->arg1;
				if (check_nsec3_node_in_zone(zone, node) != 0) {
					log_zone_error("TODO nsec3");
				}
			}
		}
	}
}

void zone_save_enclosers_sem_check(dnslib_zone_t *zone, skip_list_t *list,
				   char do_checks)
{
	arg_t arguments;
	arguments.arg1 = zone;
	arguments.arg2 = list;
	arguments.arg3 = &do_checks;

	dnslib_zone_tree_apply_inorder(zone,
	                   dnslib_zone_save_enclosers_in_tree,
			   (void *)&arguments);
}

/* TODO Think of a better way than a global variable */
static uint node_count = 0;

static void dnslib_labels_dump_binary(dnslib_dname_t *dname, FILE *f)
{
	debug_zp("label count: %d\n", dname->label_count);
	fwrite(&(dname->label_count), sizeof(dname->label_count), 1, f);
//	hex_print(dname->labels, dname->label_count);
	fwrite(dname->labels, sizeof(uint8_t), dname->label_count, f);
}

static void dnslib_dname_dump_binary(dnslib_dname_t *dname, FILE *f)
{
	fwrite(&(dname->size), sizeof(uint8_t), 1, f);
	fwrite(dname->name, sizeof(uint8_t), dname->size, f);
	debug_zp("dname size: %d\n", dname->size);
	dnslib_labels_dump_binary(dname, f);
}

static dnslib_dname_t *dnslib_find_wildcard(dnslib_dname_t *dname,
					    skip_list_t *list)
{
	dnslib_dname_t *d = (dnslib_dname_t *)skip_find(list, (void *)dname);
	return d;
}

static void dnslib_rdata_dump_binary(dnslib_rdata_t *rdata,
                                     uint32_t type, void *data)
{
	FILE *f = (FILE *)((arg_t *)data)->arg1;
	skip_list_t *list = (skip_list_t *)((arg_t *)data)->arg2;
	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(type);
	assert(desc != NULL);

	debug_zp("dumping type: %s\n", dnslib_rrtype_to_string(type));

	for (int i = 0; i < desc->length; i++) {
		if (&(rdata->items[i]) == NULL) {
			debug_zp("Item n. %d is not set!\n", i);
			continue;
		}
		debug_zp("Item n: %d\n", i);
		if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
		desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME )	{
			/* TODO some temp variables - this is way too long */
			assert(rdata->items[i].dname != NULL);
			dnslib_dname_t *wildcard = NULL;

			if (rdata->items[i].dname->node == NULL) {
				wildcard =
					dnslib_find_wildcard(rdata->items[i].dname,
						     list);
				debug_zp("Not in the zone: %s\n",
				       dnslib_dname_to_str((rdata->items[i].dname)));

				fwrite((uint8_t *)"\0", sizeof(uint8_t), 1, f);
				dnslib_dname_dump_binary(rdata->items[i].dname, f);
				if (wildcard) {
					fwrite((uint8_t *)"\1",
					       sizeof(uint8_t), 1, f);
					fwrite(&wildcard->node,
					       sizeof(void *), 1, f);
				} else {
					fwrite((uint8_t *)"\0", sizeof(uint8_t), 1, f);
				}
			} else {
				debug_zp("In the zone\n");
				fwrite((uint8_t *)"\1", sizeof(uint8_t), 1, f);
				fwrite(&(rdata->items[i].dname->node),
				       sizeof(void *), 1, f);
			}

		} else {
			assert(rdata->items[i].raw_data != NULL);
			fwrite(rdata->items[i].raw_data, sizeof(uint8_t),
			       rdata->items[i].raw_data[0] + 2, f);

			debug_zp("Written %d long raw data\n",
			         rdata->items[i].raw_data[0]);
		}
	}
}

static void dnslib_rrsig_set_dump_binary(dnslib_rrset_t *rrsig, arg_t *data)
{
	assert(rrsig->type == DNSLIB_RRTYPE_RRSIG);
	FILE *f = (FILE *)((arg_t *)data)->arg1;
	fwrite(&rrsig->type, sizeof(rrsig->type), 1, f);
	fwrite(&rrsig->rclass, sizeof(rrsig->rclass), 1, f);
	fwrite(&rrsig->ttl, sizeof(rrsig->ttl), 1, f);

	uint8_t rdata_count = 0;

	fpos_t rrdata_count_pos;

	fgetpos(f, &rrdata_count_pos);

	fwrite(&rdata_count, sizeof(rdata_count), 1, f);

	assert(rrsig->rdata);

	dnslib_rdata_t *tmp_rdata = rrsig->rdata;

	while (tmp_rdata->next != rrsig->rdata) {
		dnslib_rdata_dump_binary(tmp_rdata, DNSLIB_RRTYPE_RRSIG, data);
		tmp_rdata = tmp_rdata->next;
		rdata_count++;
	}
	dnslib_rdata_dump_binary(tmp_rdata, DNSLIB_RRTYPE_RRSIG, data);
	rdata_count++;

	fpos_t tmp_pos;

	fgetpos(f, &tmp_pos);

	fsetpos(f, &rrdata_count_pos);

	fwrite(&rdata_count, sizeof(rdata_count), 1, f);

	fsetpos(f, &tmp_pos);
}

static void dnslib_rrset_dump_binary(dnslib_rrset_t *rrset, void *data)
{
	FILE *f = (FILE *)((arg_t *)data)->arg1;

	fwrite(&rrset->type, sizeof(rrset->type), 1, f);
	fwrite(&rrset->rclass, sizeof(rrset->rclass), 1, f);
	fwrite(&rrset->ttl, sizeof(rrset->ttl), 1, f);

	uint8_t rdata_count = 0;
	uint8_t rrsig_count = 0;

	fpos_t rrdata_count_pos;

	fgetpos(f, &rrdata_count_pos);

	fwrite(&rdata_count, sizeof(rdata_count), 1, f);
	fwrite(&rrsig_count, sizeof(rrsig_count), 1, f);

	dnslib_rdata_t *tmp_rdata = rrset->rdata;

	while (tmp_rdata->next != rrset->rdata) {
		dnslib_rdata_dump_binary(tmp_rdata, rrset->type, data);
		tmp_rdata = tmp_rdata->next;
		rdata_count++;
	}
	dnslib_rdata_dump_binary(tmp_rdata, rrset->type, data);
	rdata_count++;

	/* This is now obsolete, although I'd rather not use recursion - that
	 * would probably not work */

	if (rrset->rrsigs != NULL) {
		dnslib_rrsig_set_dump_binary(rrset->rrsigs, data);
		rrsig_count = 1;
	}

	fpos_t tmp_pos;

	fgetpos(f, &tmp_pos);

	fsetpos(f, &rrdata_count_pos);

	fwrite(&rdata_count, sizeof(rdata_count), 1, f);
	fwrite(&rrsig_count, sizeof(rrsig_count), 1, f);

	fsetpos(f, &tmp_pos);
}

static void dnslib_node_dump_binary(dnslib_node_t *node, void *data)
{
	arg_t *args = (arg_t *)data;

	dnslib_zone_t *zone = (dnslib_zone_t *)args->arg3;

	FILE *f = (FILE *)args->arg1;


	node_count++;
	/* first write dname */
	assert(node->owner != NULL);

	if (!dnslib_node_is_non_auth(node)) {
		zone->node_count++;
	}

	dnslib_dname_dump_binary(node->owner, f);

	fwrite(&(node->owner->node), sizeof(void *), 1, f);

	debug_zp("Written id: %p\n", node->owner->node);

	/* TODO investigate whether this is necessary */
	if (node->parent != NULL) {
		fwrite(&(node->parent->owner->node), sizeof(void *), 1, f);
	} else {
		fwrite(&(node->parent), sizeof(void *), 1, f);
	}

	fwrite(&(node->flags), sizeof(node->flags), 1, f);

	debug_zp("Written flags: %u\n", node->flags);

	if (node->nsec3_node != NULL) {
		fwrite(&node->nsec3_node->owner->node, sizeof(void *), 1, f);
		debug_zp("Written nsec3 node id: %p\n",
			 node->nsec3_node->owner->node);
	} else {
		fwrite(&node->nsec3_node, sizeof(void *), 1, f);
		debug_zp("Written nsec3 node id: %p\n",
			 node->nsec3_node);
	}

	/* Now we need (or do we?) count of rrsets to be read
	 * but that number is yet unknown */

	fpos_t rrset_count_pos;

	fgetpos(f, &rrset_count_pos);

	debug_zp("Position rrset_count: %ld\n", ftell(f));

	uint8_t rrset_count = 0;

	fwrite(&rrset_count, sizeof(rrset_count), 1, f);

	const skip_node_t *skip_node = skip_first(node->rrsets);

	if (skip_node == NULL) {
		/* we can return, count is set to 0 */
		return;
	}

	dnslib_rrset_t *tmp;

	do {
		tmp = (dnslib_rrset_t *)skip_node->value;
		rrset_count++;
		dnslib_rrset_dump_binary(tmp, data);
	} while ((skip_node = skip_next(skip_node)) != NULL);

	fpos_t tmp_pos;

	fgetpos(f, &tmp_pos);

	debug_zp("Position after all rrsets: %ld\n", ftell(f));

	fsetpos(f, &rrset_count_pos);

	debug_zp("Writing here: %ld\n", ftell(f));

	fwrite(&rrset_count, sizeof(rrset_count), 1, f);

	fsetpos(f, &tmp_pos);

	debug_zp("Function ends with: %ld\n\n", ftell(f));

}

static int zone_is_secure(dnslib_zone_t *zone)
{
	if (dnslib_node_rrset(dnslib_zone_apex(zone),
			      DNSLIB_RRTYPE_DNSKEY) == NULL) {
		return 0;
	} else {
		if (dnslib_node_rrset(dnslib_zone_apex(zone),
				      DNSLIB_RRTYPE_NSEC3PARAM) != NULL) {
			return 2;
		} else {
			return 1;
		}
	}
}

int dnslib_zdump_binary(dnslib_zone_t *zone, const char *filename,
			char do_checks, const char *sfilename)
{
	FILE *f;

	f = fopen(filename, "wb");

	if (f == NULL) {
		return -1;
        }

//        dnslib_zone_dump(zone, 0);

	zone->node_count = 0;

	skip_list_t *encloser_list = skip_create_list(compare_pointers);

	if (do_checks && zone_is_secure(zone)) {
		do_checks = 2;
	}

	zone_save_enclosers_sem_check(zone, encloser_list, do_checks);

	/* Start writing header - magic bytes. */
	size_t header_len = MAGIC_LENGTH;
	static const uint8_t MAGIC[MAGIC_LENGTH] = MAGIC_BYTES;
	fwrite(&MAGIC, sizeof(uint8_t), MAGIC_LENGTH, f);

	/* Write source file length. */
	uint32_t sflen = 0;
	if (sfilename) {
		sflen = strlen(sfilename) + 1;
	}
	fwrite(&sflen, sizeof(uint32_t), 1, f);
	header_len += sizeof(uint32_t);

	/* Write source file. */
	fwrite(sfilename, sflen, 1, f);
	header_len += sflen;

	/* Notice: End of header,
	 * length must be marked for future return.
	 */

	/* Start writing compiled data. */
	fwrite(&node_count, sizeof(node_count), 1, f);
	fwrite(&node_count, sizeof(node_count), 1, f);
	fwrite(&zone->node_count,
	       sizeof(zone->node_count),
	       1, f);

	arg_t arguments;

	arguments.arg1 = f;
	arguments.arg2 = encloser_list;
	arguments.arg3 = zone;

	/* TODO is there a way how to stop the traversal upon error? */
	dnslib_zone_tree_apply_inorder(zone, dnslib_node_dump_binary,
	                               (void *)&arguments);

	uint tmp_count = node_count;

	node_count = 0;
	dnslib_zone_nsec3_apply_inorder(zone, dnslib_node_dump_binary,
	                                (void *)&arguments);

	/* Update counters. */
	fseek(f, header_len, SEEK_SET);
	fwrite(&tmp_count, sizeof(tmp_count), 1, f);
	fwrite(&node_count, sizeof(node_count), 1, f);
	fwrite(&zone->node_count,
	       sizeof(zone->node_count),
	       1, f);

	debug_zp("written %d normal nodes\n", tmp_count);

	debug_zp("written %d nsec3 nodes\n", node_count);

	debug_zp("authorative nodes: %u\n", zone->node_count);

	fclose(f);

	return 0;
}

