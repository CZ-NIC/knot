#include <stdio.h>
#include <assert.h>

#include <urcu.h>

#include "name-server.h"
#include "stat.h"
#include "dnslib.h"
#include "dnslib/debug.h"

//static const uint8_t  RCODE_MASK           = 0xf0;
static const int      OFFSET_FLAGS2        = 3;
static const size_t   RR_FIXED_SIZE        = 10;
static const size_t   QUESTION_FIXED_SIZE  = 4;
static const uint16_t MAX_UDP_PAYLOAD_EDNS = 4096;
static const uint16_t MAX_UDP_PAYLOAD      = 512;
static const uint8_t  EDNS_VERSION         = 0;
static const uint8_t  OPT_SIZE             = 11;
static const int      EDNS_ENABLED         = 1;
static const uint32_t SYNTH_CNAME_TTL      = 0;

/*----------------------------------------------------------------------------*/
/* Private functions                                                          */
/*----------------------------------------------------------------------------*/

static inline void ns_error_response(ns_nameserver *nameserver,
                                     const uint8_t *query_wire,
                                     uint8_t rcode,
                                     uint8_t *response_wire,
                                     size_t *rsize)
{
	memcpy(response_wire, nameserver->err_response,
	       nameserver->err_resp_size);
	// copy ID of the query
	memcpy(response_wire, query_wire, 2);
	// set the RCODE
	dnslib_packet_set_rcode(response_wire, rcode);
	*rsize = nameserver->err_resp_size;
}

/*----------------------------------------------------------------------------*/

static const dnslib_zone_t *ns_get_zone_for_qname(dnslib_zonedb_t *zdb,
                                                  const dnslib_dname_t *qname,
                                                  uint16_t qtype)
{
	const dnslib_zone_t *zone;
	/*
	 * Find a zone in which to search.
	 *
	 * In case of DS query, we strip the leftmost label when searching for
	 * the zone (but use whole qname in search for the record), as the DS
	 * records are only present in a parent zone.
	 */
	if (qtype == DNSLIB_RRTYPE_DS) {
		/*
		 * TODO: optimize!!!
		 *  1) do not copy the name!
		 */
		dnslib_dname_t *name = dnslib_dname_left_chop(qname);
		zone = dnslib_zonedb_find_zone_for_name(zdb, name);
		dnslib_dname_free(&name);
	} else {
		zone = dnslib_zonedb_find_zone_for_name(zdb, qname);
	}

	return zone;
}

/*----------------------------------------------------------------------------*/

dnslib_rrset_t *ns_synth_from_wildcard(const dnslib_rrset_t *wildcard_rrset,
                                       const dnslib_dname_t *qname)
{
	// TODO: test!!
	debug_ns("Synthetizing RRSet from wildcard...\n");

	dnslib_dname_t *owner = dnslib_dname_copy(qname);

	dnslib_rrset_t *synth_rrset = dnslib_rrset_new(
			owner, dnslib_rrset_type(wildcard_rrset),
			dnslib_rrset_class(wildcard_rrset),
			dnslib_rrset_ttl(wildcard_rrset));

	if (synth_rrset == NULL) {
		dnslib_dname_free(&owner);
		return NULL;
	}

	debug_ns("Created RRSet header:\n");
	dnslib_rrset_dump(synth_rrset);

	// copy all RDATA
	const dnslib_rdata_t *rdata = dnslib_rrset_rdata(wildcard_rrset);
	while (rdata != NULL) {
		// we could use the RDATA from the wildcard rrset
		// but there is no way to distinguish it when deleting
		// temporary RRSets
		dnslib_rdata_t *rdata_copy = dnslib_rdata_copy(rdata,
		                                dnslib_rrset_type(synth_rrset));
		if (rdata_copy == NULL) {
			dnslib_rrset_deep_free(&synth_rrset, 1, 0);
			return NULL;
		}

		debug_ns("Copied RDATA:\n");
		dnslib_rdata_dump(rdata_copy, dnslib_rrset_type(synth_rrset));

		dnslib_rrset_add_rdata(synth_rrset, rdata_copy);
		rdata = dnslib_rrset_rdata_next(wildcard_rrset, rdata);
	}

	return synth_rrset;
}

/*----------------------------------------------------------------------------*/

static void ns_follow_cname(const dnslib_node_t **node,
                            const dnslib_dname_t **qname,
                            dnslib_response_t *resp,
                            int (*add_rrset_to_resp)(dnslib_response_t *,
                                                     const dnslib_rrset_t *,
                                                     int, int))
{
	// TODO: test!!

	debug_ns("Resolving CNAME chain...\n");
	const dnslib_rrset_t *cname_rrset;

	while (*node != NULL
	       && (cname_rrset = dnslib_node_rrset(*node, DNSLIB_RRTYPE_CNAME))
	          != NULL) {
		/* put the CNAME record to answer, but replace the possible
		   wildcard name with qname */

		assert(cname_rrset != NULL);

		const dnslib_rrset_t *rrset = cname_rrset;

		// ignoring other than the first record
		if (dnslib_dname_is_wildcard(dnslib_node_owner(*node))) {
			/* if wildcard node, we must copy the RRSet and
			   replace its owner */
			rrset = ns_synth_from_wildcard(cname_rrset, *qname);
			dnslib_response_add_tmp_rrset(resp,
			                              (dnslib_rrset_t *)rrset);
		}

		add_rrset_to_resp(resp, rrset, 1, 0);
DEBUG_NS(
		char *name = dnslib_dname_to_str(dnslib_rrset_owner(rrset));
		debug_ns("CNAME record for owner %s put to response.\n",
			 name);
		free(name);
);

		// get the name from the CNAME RDATA
		const dnslib_dname_t *cname = dnslib_rdata_cname_name(
				dnslib_rrset_rdata(rrset));
		// change the node to the node of that name
		(*node) = dnslib_dname_node(cname);

		// save the new name which should be used for replacing wildcard
		*qname = cname;
	};
}

/*----------------------------------------------------------------------------*/

static void ns_check_wildcard(const dnslib_dname_t *name,
                              dnslib_response_t *resp,
                              const dnslib_rrset_t **rrset)
{
	if (dnslib_dname_is_wildcard((*rrset)->owner)) {
		dnslib_rrset_t *synth_rrset =
			ns_synth_from_wildcard(*rrset, name);
		debug_ns("Synthetized RRSet:\n");
		dnslib_rrset_dump(synth_rrset);
		dnslib_response_add_tmp_rrset(resp, synth_rrset);
		*rrset = synth_rrset;
	}
}

/*----------------------------------------------------------------------------*/

static int ns_put_answer(const dnslib_node_t *node, const dnslib_dname_t *name,
                          uint16_t type, dnslib_response_t *resp)
{
	int added = 0;
DEBUG_NS(
	char *name_str = dnslib_dname_to_str(node->owner);
	debug_ns("Putting answers from node %s.\n", name_str);
	free(name_str);
);
	if (type == DNSLIB_RRTYPE_ANY) {
		// TODO
	} else {
		const dnslib_rrset_t *rrset = dnslib_node_rrset(node, type);
		if (rrset != NULL) {
			debug_ns("Found RRSet of type %s\n",
				 dnslib_rrtype_to_string(type));
			ns_check_wildcard(name, resp, &rrset);
			dnslib_response_add_rrset_answer(resp, rrset, 1, 0);
			added = 1;
		}
	}
	dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);
	return added;
}

/*----------------------------------------------------------------------------*/

static void ns_put_additional_for_rrset(dnslib_response_t *resp,
                                        const dnslib_rrset_t *rrset)
{
	const dnslib_node_t *node = NULL;
	const dnslib_rdata_t *rdata = NULL;
	const dnslib_dname_t *dname = NULL;

	// for all RRs in the RRset
	rdata = dnslib_rrset_rdata(rrset);
	while (rdata != NULL) {
		debug_ns("Getting name from RDATA, type %s..\n",
			 dnslib_rrtype_to_string(dnslib_rrset_type(rrset)));
		dname = dnslib_rdata_get_name(rdata,
					      dnslib_rrset_type(rrset));
		assert(dname != NULL);
		node = dnslib_dname_node(dname);

		const dnslib_rrset_t *rrset_add;

		if (node != NULL) {
DEBUG_NS(
			char *name = dnslib_dname_to_str(node->owner);
			debug_ns("Putting additional from node %s\n", name);
			free(name);
);
			debug_ns("Checking CNAMEs...\n");
			if (dnslib_node_rrset(node, DNSLIB_RRTYPE_CNAME)
			    != NULL) {
				debug_ns("Found CNAME in node, following...\n");
				const dnslib_dname_t *dname
						= dnslib_node_owner(node);
				ns_follow_cname(&node, &dname, resp,
					dnslib_response_add_rrset_additional);
			}

			// A RRSet
			debug_ns("A RRSets...\n");
			rrset_add = dnslib_node_rrset(node, DNSLIB_RRTYPE_A);
			if (rrset_add != NULL) {
				debug_ns("Found A RRsets.\n");
				ns_check_wildcard(dname, resp, &rrset_add);
				dnslib_response_add_rrset_additional(
					resp, rrset_add, 0, 1);
			}

			// AAAA RRSet
			debug_ns("AAAA RRSets...\n");
			rrset_add = dnslib_node_rrset(node, DNSLIB_RRTYPE_AAAA);
			if (rrset_add != NULL) {
				debug_ns("Found AAAA RRsets.\n");
				ns_check_wildcard(dname, resp, &rrset_add);
				dnslib_response_add_rrset_additional(
					resp, rrset_add, 0, 1);
			}
		}

		assert(rrset != NULL);
		assert(rdata != NULL);
		rdata = dnslib_rrset_rdata_next(rrset, rdata);
	}
}

/*----------------------------------------------------------------------------*/

static int ns_additional_needed(uint16_t qtype)
{
	return (qtype == DNSLIB_RRTYPE_MX ||
	        qtype == DNSLIB_RRTYPE_NS ||
		qtype == DNSLIB_RRTYPE_SRV);
}

/*----------------------------------------------------------------------------*/

static void ns_put_additional(dnslib_response_t *resp)
{
        debug_ns("ADDITIONAL SECTION PROCESSING\n");

	const dnslib_rrset_t *rrset = NULL;

	for (int i = 0; i < dnslib_response_answer_rrset_count(resp); ++i) {
		rrset = dnslib_response_answer_rrset(resp, i);
		assert(rrset != NULL);
		if (ns_additional_needed(dnslib_rrset_type(rrset))) {
			ns_put_additional_for_rrset(resp, rrset);
		}
	}

	for (int i = 0; i < dnslib_response_authority_rrset_count(resp); ++i) {
		rrset = dnslib_response_authority_rrset(resp, i);
		if (ns_additional_needed(dnslib_rrset_type(rrset))) {
			ns_put_additional_for_rrset(resp, rrset);
		}
	}
}

/*----------------------------------------------------------------------------*/

static void ns_put_authority_ns(const dnslib_zone_t *zone,
                                dnslib_response_t *resp)
{
	const dnslib_rrset_t *ns_rrset =
		dnslib_node_rrset(zone->apex, DNSLIB_RRTYPE_NS);
	assert(ns_rrset != NULL);

	dnslib_response_add_rrset_authority(resp, ns_rrset, 0, 1);
}

/*----------------------------------------------------------------------------*/

static void ns_put_authority_soa(const dnslib_zone_t *zone,
                                 dnslib_response_t *resp)
{
	const dnslib_rrset_t *soa_rrset =
		dnslib_node_rrset(zone->apex, DNSLIB_RRTYPE_SOA);
	assert(soa_rrset != NULL);

	dnslib_response_add_rrset_authority(resp, soa_rrset, 0, 0);
}

/*----------------------------------------------------------------------------*/

static inline void ns_referral(const dnslib_node_t *node,
                               dnslib_response_t *resp)
{
	debug_ns("Referral response.\n");

	while (!dnslib_node_is_deleg_point(node)) {
		assert(node->parent != NULL);
		node = node->parent;
	}

	const dnslib_rrset_t *ns_rrset =
		dnslib_node_rrset(node, DNSLIB_RRTYPE_NS);
	assert(ns_rrset != NULL);

	dnslib_response_add_rrset_authority(resp, ns_rrset, 1, 0);
	ns_put_additional(resp);

	dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);
}

/*----------------------------------------------------------------------------*/

static void ns_answer_from_node(const dnslib_node_t *node,
                                const dnslib_zone_t *zone,
                                const dnslib_dname_t *qname, uint16_t qtype,
                                dnslib_response_t *resp)
{
	debug_ns("Putting answers from found node to the response...\n");
	int answers = ns_put_answer(node, qname, qtype, resp);

	if (answers == 0) {  // if NODATA response, put SOA
		ns_put_authority_soa(zone, resp);
	} else {  // else put authority NS
		ns_put_authority_ns(zone, resp);
	}

	ns_put_additional(resp);
}

/*----------------------------------------------------------------------------*/

static dnslib_rrset_t *ns_cname_from_dname(const dnslib_rrset_t *dname_rrset,
                                           const dnslib_dname_t *qname)
{
	debug_ns("Synthetizing CNAME from DNAME...\n");

	// create new CNAME RRSet

	dnslib_dname_t *owner = dnslib_dname_copy(qname);
	if (owner == NULL) {
		return NULL;
	}

	dnslib_rrset_t *cname_rrset = dnslib_rrset_new(
			owner, DNSLIB_RRTYPE_CNAME,
			DNSLIB_CLASS_IN, SYNTH_CNAME_TTL);

	if (cname_rrset == NULL) {
		dnslib_dname_free(&owner);
		return NULL;
	}

	// replace last labels of qname with DNAME
	dnslib_dname_t *cname = dnslib_dname_replace_suffix(qname,
	      dnslib_dname_size(dnslib_rrset_owner(dname_rrset)),
	      dnslib_rdata_get_item(dnslib_rrset_rdata(dname_rrset), 0)->dname);
DEBUG_NS(
	char *name = dnslib_dname_to_str(cname);
	debug_ns("CNAME canonical name: %s.\n", name);
	free(name);
);
	dnslib_rdata_t *cname_rdata = dnslib_rdata_new();
	dnslib_rdata_item_t cname_rdata_item;
	cname_rdata_item.dname = cname;
	dnslib_rdata_set_items(cname_rdata, &cname_rdata_item, 1);

	dnslib_rrset_add_rdata(cname_rrset, cname_rdata);

	return cname_rrset;
}

/*----------------------------------------------------------------------------*/

static int ns_dname_is_too_long(const dnslib_rrset_t *dname_rrset,
                                const dnslib_dname_t *qname)
{
	// TODO: add function for getting DNAME target
	if (dnslib_dname_label_count(qname)
	        - dnslib_dname_label_count(dnslib_rrset_owner(dname_rrset))
	        + dnslib_dname_label_count(dnslib_rdata_get_item(
				dnslib_rrset_rdata(dname_rrset), 0)->dname)
	        > DNSLIB_MAX_DNAME_LENGTH) {
		return 1;
	} else {
		return 0;
	}
}

/*----------------------------------------------------------------------------*/

static void ns_process_dname(const dnslib_rrset_t *dname_rrset,
                             const dnslib_dname_t *qname,
                             dnslib_response_t *resp)
{
DEBUG_NS(
	char *name = dnslib_dname_to_str(dnslib_rrset_owner(dname_rrset));
	debug_ns("Processing DNAME for owner %s...\n", name);
	free(name);
);
	// TODO: check the number of RRs in the RRSet??

	// put the DNAME RRSet into the answer
	dnslib_response_add_rrset_answer(resp, dname_rrset, 1, 0);

	if (ns_dname_is_too_long(dname_rrset, qname)) {
		dnslib_response_set_rcode(resp, DNSLIB_RCODE_YXDOMAIN);
		return;
	}

	// synthetize CNAME (no way to tell that client supports DNAME)
	dnslib_rrset_t *synth_cname = ns_cname_from_dname(dname_rrset, qname);
	// add the synthetized RRSet to the Answer
	dnslib_response_add_rrset_answer(resp, synth_cname, 1, 0);
	// add the synthetized RRSet into list of temporary RRSets of response
	dnslib_response_add_tmp_rrset(resp, synth_cname);

	// do not search for the name in new zone (out-of-bailiwick)
}

/*----------------------------------------------------------------------------*/

static void ns_answer_from_zone(const dnslib_zone_t *zone,
                                const dnslib_dname_t *qname, uint16_t qtype,
                                dnslib_response_t *resp)
{
	const dnslib_node_t *node = NULL;
	const dnslib_node_t *closest_encloser = NULL;
	int cname = 0;
	//dnslib_dname_t *qname_old = NULL;
	int auth_soa = 0;

	while (1) {
		//qname_old = dnslib_dname_copy(qname);

#ifdef USE_HASH_TABLE
		int find_ret = dnslib_zone_find_dname_hash(zone, qname,
		                                      &node, &closest_encloser);
#else
		int find_ret = dnslib_zone_find_dname(zone, qname, &node,
		                                         &closest_encloser);
#endif
DEBUG_NS(
		if (node) {
			char *name = dnslib_dname_to_str(node->owner);
			debug_ns("zone_find_dname() returned node %s ", name);
			free(name);
			name = dnslib_dname_to_str(closest_encloser->owner);
			debug_ns("and closest encloser %s.\n", name);
			free(name);
		} else {
			debug_ns("zone_find_dname() returned no node.\n");
		}
);
		if (find_ret == DNSLIB_ZONE_NAME_NOT_IN_ZONE) {
			// possible only if we followed cname
			assert(cname != 0);
			dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);
			auth_soa = 1;
			break;
		}

//		assert(exact_match == 1
//		       || (exact_match == 0 && closest_encloser == node));

		debug_ns("Closest encloser is deleg. point? %s\n",
			 (dnslib_node_is_deleg_point(closest_encloser))
			 ? "yes" : "no");

		debug_ns("Closest encloser is non authoritative? %s\n",
			 (dnslib_node_is_non_auth(closest_encloser))
			 ? "yes" : "no");

		if (dnslib_node_is_deleg_point(closest_encloser)
		    || dnslib_node_is_non_auth(closest_encloser)) {
			ns_referral(closest_encloser, resp);
			break;
		}

		if (find_ret == DNSLIB_ZONE_NAME_NOT_FOUND) {
			// DNAME?
			const dnslib_rrset_t *dname_rrset =
				dnslib_node_rrset(closest_encloser,
				                  DNSLIB_RRTYPE_DNAME);
			if (dname_rrset != NULL) {
				ns_process_dname(dname_rrset, qname, resp);
				auth_soa = 1;
				break;
			}
			// else check for a wildcard child
			const dnslib_node_t *wildcard_node =
				dnslib_node_wildcard_child(closest_encloser);

			if (wildcard_node == NULL) {
				auth_soa = 1;
				if (cname == 0) {
					// return NXDOMAIN
					dnslib_response_set_rcode(resp,
						DNSLIB_RCODE_NXDOMAIN);
				} else {
					dnslib_response_set_rcode(resp,
						DNSLIB_RCODE_NOERROR);
				}
				break;
			}
			// else set the node from which to take the answers to
			// the wildcard node
			node = wildcard_node;
		}

		// now we have the node for answering

		if (dnslib_node_rrset(node, DNSLIB_RRTYPE_CNAME) != NULL) {
DEBUG_NS(
			char *name = dnslib_dname_to_str(node->owner);
			debug_ns("Node %s has CNAME record, resolving...\n",
				 name);
			free(name);
);
			const dnslib_dname_t *act_name = qname;
			ns_follow_cname(&node, &act_name, resp,
			                dnslib_response_add_rrset_answer);
DEBUG_NS(
			char *name2 = dnslib_dname_to_str(act_name);
			debug_ns("Canonical name: %s, node found: %p\n",
			         name2, node);
			free(name2);
);
			if (act_name != qname) {
				qname = act_name;
			}
			cname = 1;

			// otherwise search for the new name
			if (node == NULL) {
				continue; // infinite loop better than goto? :)
			}
			// if the node is delegation point, return referral
			if (dnslib_node_is_deleg_point(node)) {
				ns_referral(node, resp);
				break;
			}
		}

		ns_answer_from_node(node, zone, qname, qtype, resp);
		dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);
		break;
	}

	if (auth_soa) {
		ns_put_authority_soa(zone, resp);
	}
	//dnslib_dname_free(&qname_old);
}

/*----------------------------------------------------------------------------*/

static void ns_answer(dnslib_zonedb_t *db, dnslib_response_t *resp)
{
	// TODO: the copying is not needed maybe
	dnslib_dname_t *qname = /*dnslib_dname_copy(*/resp->question.qname/*)*/;
	uint16_t qtype = resp->question.qtype;
DEBUG_NS(
	char *name_str = dnslib_dname_to_str(qname);
	debug_ns("Trying to find zone for QNAME %s\n", name_str);
	free(name_str);
);
	// find zone in which to search for the name
	const dnslib_zone_t *zone =
		ns_get_zone_for_qname(db, qname, qtype);

	// if no zone found, return REFUSED
	if (zone == NULL) {
		debug_ns("No zone found.\n");
		dnslib_response_set_rcode(resp, DNSLIB_RCODE_REFUSED);
		//dnslib_dname_free(&qname);
		return;
	}
DEBUG_NS(
	char *name_str2 = dnslib_dname_to_str(zone->apex->owner);
	debug_ns("Found zone for QNAME %s\n", name_str2);
	free(name_str2);
);
	ns_answer_from_zone(zone, qname, qtype, resp);

	//dnslib_dname_free(&qname);
}

/*----------------------------------------------------------------------------*/

static int ns_response_to_wire(dnslib_response_t *resp, uint8_t *wire,
                               size_t *wire_size)
{
	uint8_t *rwire = NULL;
	size_t rsize = 0;
	int ret = 0;

	if ((ret = dnslib_response_to_wire(resp, &rwire, &rsize)) != 0) {
		log_error("Error converting response packet to wire format. "
		          "dnslib returned: %d\n", ret);
		return -1;
	}

	assert(rsize <= *wire_size);
	memcpy(wire, rwire, rsize);
	*wire_size = rsize;
	free(rwire);

	return 0;
}

/*----------------------------------------------------------------------------*/
/* Public functions                                                           */
/*----------------------------------------------------------------------------*/

ns_nameserver *ns_create(dnslib_zonedb_t *database)
{
	ns_nameserver *ns = malloc(sizeof(ns_nameserver));
	if (ns == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	ns->zone_db = database;

	// prepare empty response with SERVFAIL error
	dnslib_response_t *err = dnslib_response_new_empty(NULL, 0);
	if (err == NULL) {
		return NULL;
	}

	debug_ns("Created default empty response...\n");

	dnslib_response_set_rcode(err, DNSLIB_RCODE_SERVFAIL);
	ns->err_response = NULL;
	ns->err_resp_size = 0;

	debug_ns("Converting default empty response to wire format...\n");

	if (dnslib_response_to_wire(err, &ns->err_response, &ns->err_resp_size)
	    != 0) {
		log_error("Error while converting default error resposne to "
		          "wire format \n");
		dnslib_response_free(&err);
		free(ns);
		return NULL;
	}

	debug_ns("Done..\n");

	//stat

	stat_static_gath_init();

	//!stat

	dnslib_response_free(&err);

	return ns;
}

/*----------------------------------------------------------------------------*/

int ns_answer_request(ns_nameserver *nameserver, const uint8_t *query_wire,
                      size_t qsize, uint8_t *response_wire, size_t *rsize)
{
	debug_ns("ns_answer_request() called with query size %zu.\n", qsize);
	debug_ns_hex((char *)query_wire, qsize);

	if (qsize < 2) {
		return -1;
	}

//	debug_ns("Sending default error response...\n");

//	ns_error_response(nameserver, query_wire, DNSLIB_RCODE_FORMAT,
//	                  response_wire, rsize);

	// 1) create empty response
	debug_ns("Parsing query using new dnslib structure...\n");
	dnslib_response_t *resp = dnslib_response_new_empty(NULL, 0);

	if (resp == NULL) {
		log_error("Error while creating response packet!\n");
		ns_error_response(nameserver, query_wire, DNSLIB_RCODE_SERVFAIL,
		                  response_wire, rsize);
		return 0;
	}

	int ret = 0;

	// 2) parse the query
	if ((ret = dnslib_response_parse_query(resp, query_wire, qsize)) != 0) {
		log_info("Error while parsing query, dnslib returned: %d\n",
			 ret);
		ns_error_response(nameserver, query_wire, DNSLIB_RCODE_FORMERR,
		                  response_wire, rsize);
		dnslib_response_free(&resp);
		return 0;
	}

	debug_ns("Query parsed.\n");
	dnslib_response_dump(resp);

	// 3) get the answer for the query
	rcu_read_lock();

	ns_answer(nameserver->zone_db, resp);

	debug_ns("Created response packet.\n");
	dnslib_response_dump(resp);

	// 4) Transform the packet into wire format
	if (ns_response_to_wire(resp, response_wire, rsize) != 0) {
		// send back SERVFAIL (as this is our problem)
		ns_error_response(nameserver, query_wire, DNSLIB_RCODE_SERVFAIL,
		                  response_wire, rsize);
	}

	dnslib_response_free(&resp);
	rcu_read_unlock();

	debug_ns("Returning response with wire size %zu\n", *rsize);
	debug_ns_hex((char *)response_wire, *rsize);

	return 0;
}

/*----------------------------------------------------------------------------*/

void ns_destroy(ns_nameserver **nameserver)
{
	// do nothing with the zone database!
	free((*nameserver)->err_response);
	free(*nameserver);
	*nameserver = NULL;
}

