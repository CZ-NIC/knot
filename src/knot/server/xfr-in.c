#include <assert.h>

#include "knot/server/xfr-in.h"

#include "knot/common.h"
#include "knot/other/error.h"
#include "dnslib/packet.h"
#include "dnslib/dname.h"
#include "dnslib/zone.h"
#include "dnslib/query.h"
#include "dnslib/error.h"
#include "knot/other/log.h"
#include "knot/server/name-server.h"
#include "dnslib/debug.h"

static const size_t XFRIN_CHANGESET_COUNT = 5;
static const size_t XFRIN_CHANGESET_STEP = 5;
static const size_t XFRIN_CHANGESET_RRSET_COUNT = 5;
static const size_t XFRIN_CHANGESET_RRSET_STEP = 5;
static const size_t XFRIN_CHANGESET_BINARY_SIZE = 100;
static const size_t XFRIN_CHANGESET_BINARY_STEP = 100;

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static int xfrin_create_query(const dnslib_dname_t *qname, uint16_t qtype,
                              uint16_t qclass, uint8_t *buffer, size_t *size)
{
	dnslib_packet_t *pkt = dnslib_packet_new(DNSLIB_PACKET_PREALLOC_QUERY);
	CHECK_ALLOC_LOG(pkt, KNOT_ENOMEM);

	/*! \todo Get rid of the numeric constant. */
	int rc = dnslib_packet_set_max_size(pkt, 512);
	if (rc != DNSLIB_EOK) {
		dnslib_packet_free(&pkt);
		return KNOT_ERROR;
	}

	rc = dnslib_query_init(pkt);
	if (rc != DNSLIB_EOK) {
		dnslib_packet_free(&pkt);
		return KNOT_ERROR;
	}

	dnslib_question_t question;

	// this is ugly!!
	question.qname = (dnslib_dname_t *)qname;
	question.qtype = qtype;
	question.qclass = qclass;

	rc = dnslib_query_set_question(pkt, &question);
	if (rc != DNSLIB_EOK) {
		dnslib_packet_free(&pkt);
		return KNOT_ERROR;
	}

	/*! \todo Set some random ID!! */

	/*! \todo OPT RR ?? */

	uint8_t *wire = NULL;
	size_t wire_size = 0;
	rc = dnslib_packet_to_wire(pkt, &wire, &wire_size);
	if (rc != DNSLIB_EOK) {
		dnslib_packet_free(&pkt);
		return KNOT_ERROR;
	}

	if (wire_size > *size) {
		log_answer_warning("Not enough space provided for the wire "
		                   "format of the query.\n");
		dnslib_packet_free(&pkt);
		return KNOT_ESPACE;
	}

	memcpy(buffer, wire, wire_size);
	*size = wire_size;

	debug_ns("Created query of size %zu.\n", *size);
	dnslib_packet_dump(pkt);

	dnslib_packet_free(&pkt);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static uint32_t xfrin_serial_difference(uint32_t local, uint32_t remote)
{
	return (((int64_t)remote - local) % ((int64_t)1 << 32));
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int xfrin_create_soa_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                           size_t *size)
{
	return xfrin_create_query(zone_name, DNSLIB_RRTYPE_SOA,
	                           DNSLIB_CLASS_IN, buffer, size);
}

/*----------------------------------------------------------------------------*/

int xfrin_transfer_needed(const dnslib_zone_t *zone,
                          dnslib_packet_t *soa_response)
{
	// first, parse the rest of the packet
	assert(!dnslib_packet_is_query(soa_response));
	debug_ns("Response - parsed: %zu, total wire size: %zu\n",
	         soa_response->parsed, soa_response->size);
	int ret;

	if (soa_response->parsed < soa_response->size) {
		ret = dnslib_packet_parse_rest(soa_response);
		if (ret != DNSLIB_EOK) {
			return KNOT_EMALF;
		}
	}

	/*
	 * Retrieve the local Serial
	 */
	const dnslib_rrset_t *soa_rrset =
		dnslib_node_rrset(dnslib_zone_apex(zone), DNSLIB_RRTYPE_SOA);
	if (soa_rrset == NULL) {
		char *name = dnslib_dname_to_str(dnslib_node_owner(
				dnslib_zone_apex(zone)));
		log_answer_warning("SOA RRSet missing in the zone %s!\n", name);
		free(name);
		return KNOT_ERROR;
	}

	int64_t local_serial = dnslib_rdata_soa_serial(
		dnslib_rrset_rdata(soa_rrset));
	if (local_serial < 0) {
		char *name = dnslib_dname_to_str(dnslib_rrset_owner(soa_rrset));
		log_answer_warning("Malformed data in SOA of zone %s\n", name);
		free(name);
		return KNOT_EMALF;	// maybe some other error
	}

	/*
	 * Retrieve the remote Serial
	 */
	// the SOA should be the first (and only) RRSet in the response
	soa_rrset = dnslib_packet_answer_rrset(soa_response, 0);
	if (soa_rrset == NULL
	    || dnslib_rrset_type(soa_rrset) != DNSLIB_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	int64_t remote_serial = dnslib_rdata_soa_serial(
		dnslib_rrset_rdata(soa_rrset));
	if (remote_serial < 0) {
		return KNOT_EMALF;	// maybe some other error
	}

	uint32_t diff = xfrin_serial_difference(local_serial, remote_serial);
	return (diff >= 1 && diff <= (((uint32_t)1 << 31) - 1)) ? 1 : 0;
}

/*----------------------------------------------------------------------------*/

int xfrin_create_axfr_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                            size_t *size)
{
	return xfrin_create_query(zone_name, DNSLIB_RRTYPE_AXFR,
	                           DNSLIB_CLASS_IN, buffer, size);
}

/*----------------------------------------------------------------------------*/

int xfrin_create_ixfr_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                            size_t *size)
{
	return xfrin_create_query(zone_name, DNSLIB_RRTYPE_IXFR,
	                           DNSLIB_CLASS_IN, buffer, size);
}

/*----------------------------------------------------------------------------*/

int xfrin_zone_transferred(ns_nameserver_t *nameserver, dnslib_zone_t *zone)
{
	debug_xfr("Switching zone in nameserver.\n");
	return ns_switch_zone(nameserver, zone);
	//return KNOT_ENOTSUP;
}

/*----------------------------------------------------------------------------*/

int xfrin_process_axfr_packet(const uint8_t *pkt, size_t size,
                              dnslib_zone_t **zone)
{
	if (pkt == NULL || zone == NULL) {
		debug_xfr("Wrong parameters supported.\n");
		return KNOT_EINVAL;
	}

	dnslib_packet_t *packet =
			dnslib_packet_new(DNSLIB_PACKET_PREALLOC_NONE);
	if (packet == NULL) {
		debug_xfr("Could not create packet structure.\n");
		return KNOT_ENOMEM;
	}

	int ret = dnslib_packet_parse_from_wire(packet, pkt, size, 1);
	if (ret != DNSLIB_EOK) {
		debug_xfr("Could not parse packet: %s.\n",
		          dnslib_strerror(ret));
		dnslib_packet_free(&packet);
		/*! \todo Cleanup. */
		return KNOT_EMALF;
	}

	dnslib_rrset_t *rr = NULL;
	ret = dnslib_packet_parse_next_rr_answer(packet, &rr);

	if (ret != DNSLIB_EOK) {
		debug_xfr("Could not parse first Answer RR: %s.\n",
		          dnslib_strerror(ret));
		dnslib_packet_free(&packet);
		/*! \todo Cleanup. */
		return KNOT_EMALF;
	}

	if (rr == NULL) {
		debug_xfr("No RRs in the packet.\n");
		dnslib_packet_free(&packet);
		/*! \todo Cleanup. */
		return KNOT_EMALF;
	}

	dnslib_node_t *node = NULL;
	int in_zone = 0;

	if (*zone == NULL) {
		// create new zone
		/*! \todo Ensure that the packet is the first one. */
		if (dnslib_rrset_type(rr) != DNSLIB_RRTYPE_SOA) {
			debug_xfr("No zone created, but the first RR in Answer"
			          " is not a SOA RR.\n");
			dnslib_packet_free(&packet);
			dnslib_node_free(&node, 0);
			dnslib_rrset_deep_free(&rr, 1, 1, 1);
			/*! \todo Cleanup. */
			return KNOT_EMALF;
		}

		if (dnslib_dname_compare(dnslib_rrset_owner(rr),
		                         dnslib_packet_qname(packet)) != 0) {
DEBUG_XFR(
			char *rr_owner =
				dnslib_dname_to_str(dnslib_rrset_owner(rr));
			char *qname = dnslib_dname_to_str(
				dnslib_packet_qname(packet));

			debug_xfr("Owner of the first SOA RR (%s) does not "
			          "match QNAME (%s).\n", rr_owner, qname);

			free(rr_owner);
			free(qname);
);
			/*! \todo Cleanup. */
			dnslib_packet_free(&packet);
			dnslib_node_free(&node, 0);
			dnslib_rrset_deep_free(&rr, 1, 1, 1);
			return KNOT_EMALF;
		}

		node = dnslib_node_new(rr->owner, NULL);
		if (node == NULL) {
			debug_xfr("Failed to create new node.\n");
			dnslib_packet_free(&packet);
			dnslib_rrset_deep_free(&rr, 1, 1, 1);
			return KNOT_ENOMEM;
		}

		// the first RR is SOA and its owner and QNAME are the same
		// create the zone
		*zone = dnslib_zone_new(node, 0, 1);
		if (*zone == NULL) {
			debug_xfr("Failed to create new zone.\n");
			dnslib_packet_free(&packet);
			dnslib_node_free(&node, 0);
			dnslib_rrset_deep_free(&rr, 1, 1, 1);
			/*! \todo Cleanup. */
			return KNOT_ENOMEM;
		}

		in_zone = 1;
		assert(node->owner == rr->owner);
		// add the RRSet to the node
		//ret = dnslib_node_add_rrset(node, rr, 0);
		ret = dnslib_zone_add_rrset(*zone, rr, &node,
		                            DNSLIB_RRSET_DUPL_MERGE, 1);
		if (ret < 0) {
			debug_xfr("Failed to add RRSet to zone node: %s.\n",
			          dnslib_strerror(ret));
			dnslib_packet_free(&packet);
			dnslib_node_free(&node, 0);
			dnslib_rrset_deep_free(&rr, 1, 1, 1);
			/*! \todo Cleanup. */
			return KNOT_ERROR;
		} else if (ret > 0) {
			// merged, free the RRSet
			dnslib_rrset_deep_free(&rr, 1, 0, 0);
		}

		// take next RR
		ret = dnslib_packet_parse_next_rr_answer(packet, &rr);
	}

	while (ret == DNSLIB_EOK && rr != NULL) {
		// process the parsed RR

		debug_xfr("\nNext RR:\n\n");
		dnslib_rrset_dump(rr, 0);

		if (node != NULL
		    && dnslib_dname_compare(rr->owner, node->owner) != 0) {
			if (!in_zone) {
				// this should not happen
				assert(0);
				// the node is not in the zone and the RR has
				// other owner, so a new node must be created
				// insert the old node to the zone
//	DEBUG_XFR(
//				char *name = dnslib_dname_to_str(node->owner);
//				debug_xfr("Inserting node %s to the zone.\n",
//				          name);
//				free(name);
//	);
//				ret = dnslib_zone_add_node(*zone, node, 1, 1);
//				if (ret != DNSLIB_EOK) {
//					debug_xfr("Failed to add node into "
//					          "zone.\n");
//					dnslib_packet_free(&packet);
//					dnslib_node_free(&node, 1);
//					dnslib_rrset_deep_free(&rr, 1, 1, 1);
//					return KNOT_ERROR;	/*! \todo Other error */
//				}
			}

			node = NULL;
		}

		if (dnslib_rrset_type(rr) == DNSLIB_RRTYPE_SOA) {
			// this must be the last SOA, do not do anything more
			// discard the RR
			assert((*zone)->apex != NULL);
			assert(dnslib_node_rrset((*zone)->apex,
			                         DNSLIB_RRTYPE_SOA) != NULL);
			debug_xfr("Found last SOA, transfer finished.\n");
			dnslib_rrset_deep_free(&rr, 1, 1, 1);
			dnslib_packet_free(&packet);
			return 1;
		}

		if (dnslib_rrset_type(rr) == DNSLIB_RRTYPE_RRSIG) {
			// RRSIGs require special handling, as there are no
			// nodes for them
			dnslib_rrset_t *tmp_rrset = NULL;
			ret = dnslib_zone_add_rrsigs(*zone, rr, &tmp_rrset,
			                     &node, DNSLIB_RRSET_DUPL_MERGE, 1);
			if (ret < 0) {
				debug_xfr("Failed to add RRSIGs.\n");
				dnslib_packet_free(&packet);
				dnslib_node_free(&node, 1); // ???
				dnslib_rrset_deep_free(&rr, 1, 1, 1);
				return KNOT_ERROR;  /*! \todo Other error code. */
			} else if (ret == 1) {
				dnslib_rrset_deep_free(&rr, 1, 0, 0);
			} else if (ret == 2) {
				// should not happen
				assert(0);
//				dnslib_rrset_deep_free(&rr, 1, 1, 1);
			} else {
				assert(tmp_rrset->rrsigs == rr);
			}

			// parse next RR
			ret = dnslib_packet_parse_next_rr_answer(packet, &rr);

			continue;
		}

		dnslib_node_t *(*get_node)(const dnslib_zone_t *,
		                           const dnslib_dname_t *) = NULL;
		int (*add_node)(dnslib_zone_t *, dnslib_node_t *, int, int)
		      = NULL;

		if (dnslib_rrset_type(rr) == DNSLIB_RRTYPE_NSEC3) {
			get_node = dnslib_zone_get_nsec3_node;
			add_node = dnslib_zone_add_nsec3_node;
		} else {
			get_node = dnslib_zone_get_node;
			add_node = dnslib_zone_add_node;
		}

		if (node == NULL && (node = get_node(
		                     *zone, dnslib_rrset_owner(rr))) != NULL) {
			// the node for this RR was found in the zone
			debug_xfr("Found node for the record in zone.\n");
			in_zone = 1;
		}

		if (node == NULL) {
			// a new node for the RR is required but it is not
			// in the zone
			node = dnslib_node_new(rr->owner, NULL);
			if (node == NULL) {
				debug_xfr("Failed to create new node.\n");
				dnslib_packet_free(&packet);
				dnslib_rrset_deep_free(&rr, 1, 1, 1);
				return KNOT_ENOMEM;
			}
			debug_xfr("Created new node for the record.\n");

			// insert the node into the zone
			ret = dnslib_node_add_rrset(node, rr, 1);
			if (ret < 0) {
				debug_xfr("Failed to add RRSet to node.\n");
				dnslib_packet_free(&packet);
				dnslib_node_free(&node, 1); // ???
				dnslib_rrset_deep_free(&rr, 1, 1, 1);
				return KNOT_ERROR;
			} else if (ret > 0) {
				// should not happen, this is new node
				assert(0);
//				dnslib_rrset_deep_free(&rr, 1, 0, 0);
			}

			ret = add_node(*zone, node, 1, 1);
			if (ret != DNSLIB_EOK) {
				debug_xfr("Failed to add node to zone.\n");
				dnslib_packet_free(&packet);
				dnslib_node_free(&node, 1); // ???
				dnslib_rrset_deep_free(&rr, 1, 1, 1);
				return KNOT_ERROR;
			}

			in_zone = 1;
		} else {
			assert(in_zone);

			ret = dnslib_zone_add_rrset(*zone, rr, &node,
			                            DNSLIB_RRSET_DUPL_MERGE, 1);
			if (ret < 0) {
				debug_xfr("Failed to add RRSet to zone: %s.\n",
				          dnslib_strerror(ret));
				return KNOT_ERROR;
			} else if (ret > 0) {
				// merged, free the RRSet
				dnslib_rrset_deep_free(&rr, 1, 0, 0);
			}

		}

		rr = NULL;

		// parse next RR
		ret = dnslib_packet_parse_next_rr_answer(packet, &rr);
	}

	assert(ret != DNSLIB_EOK || rr == NULL);

	if (ret < 0) {
		// some error in parsing
		debug_xfr("Could not parse next RR: %s.\n",
		          dnslib_strerror(ret));
		dnslib_packet_free(&packet);
		dnslib_node_free(&node, 0);
		dnslib_rrset_deep_free(&rr, 1, 1, 1);
		/*! \todo Cleanup. */
		return KNOT_EMALF;
	}

	assert(ret == DNSLIB_EOK);
	assert(rr == NULL);

	// if the last node is not yet in the zone, insert
	if (!in_zone) {
		assert(node != NULL);
		ret = dnslib_zone_add_node(*zone, node, 1, 1);
		if (ret != DNSLIB_EOK) {
			debug_xfr("Failed to add last node into zone.\n");
			dnslib_packet_free(&packet);
			dnslib_node_free(&node, 1);
			return KNOT_ERROR;	/*! \todo Other error */
		}
	}

	dnslib_packet_free(&packet);
	debug_xfr("Processed one AXFR packet successfully.\n");

	return (ret == DNSLIB_EOK) ? KNOT_EOK : KNOT_EMALF;
}

/*----------------------------------------------------------------------------*/

static int xfrin_parse_first_rr(dnslib_packet_t **packet, const uint8_t *pkt,
                                size_t size, dnslib_rrset_t **rr)
{
	*packet = dnslib_packet_new(DNSLIB_PACKET_PREALLOC_NONE);
	if (packet == NULL) {
		debug_xfr("Could not create packet structure.\n");
		return KNOT_ENOMEM;
	}

	int ret = dnslib_packet_parse_from_wire(*packet, pkt, size, 1);
	if (ret != DNSLIB_EOK) {
		debug_xfr("Could not parse packet: %s.\n",
		          dnslib_strerror(ret));
		dnslib_packet_free(packet);
		return KNOT_EMALF;
	}

	ret = dnslib_packet_parse_next_rr_answer(*packet, rr);

	if (ret != DNSLIB_EOK) {
		debug_xfr("Could not parse first Answer RR: %s.\n",
		          dnslib_strerror(ret));
		dnslib_packet_free(packet);
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_changesets_check_size(xfrin_changesets_t *changesets)
{
	if (changesets->allocated == changesets->count) {
		xfrin_changeset_t *sets = (xfrin_changeset_t *)calloc(
			changesets->allocated + XFRIN_CHANGESET_STEP,
			sizeof(xfrin_changeset_t));
		if (sets == NULL) {
			return KNOT_ENOMEM;
		}

		memcpy(sets, changesets->sets, changesets->count);
		xfrin_changeset_t *old_sets = changesets->sets;
		changesets->sets = sets;
		changesets->count += XFRIN_CHANGESET_STEP;
		free(old_sets);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_allocate_changesets(xfrin_changesets_t **changesets)
{
	// create new changesets
	*changesets = (xfrin_changesets_t *)(
			calloc(1, sizeof(xfrin_changesets_t)));

	if (*changesets == NULL) {
		return KNOT_ENOMEM;
	}

	assert((*changesets)->allocated == 0);
	assert((*changesets)->count == 0);
	assert((*changesets)->sets = NULL);

	return xfrin_changesets_check_size(*changesets);
}

/*----------------------------------------------------------------------------*/

static void xfrin_free_changesets(xfrin_changesets_t **changesets)
{
	/*! \todo Implement */
	*changesets = NULL;
}

/*----------------------------------------------------------------------------*/

static int xfrin_changeset_check_count(dnslib_rrset_t ***rrsets, size_t count,
                                       size_t *allocated)
{
	// this should also do for the initial case (*rrsets == NULL)
	if (count == *allocated) {
		dnslib_rrset_t **rrsets_new = (dnslib_rrset_t **)calloc(
			*allocated + XFRIN_CHANGESET_RRSET_STEP,
			sizeof(dnslib_rrset_t *));
		if (rrsets_new == NULL) {
			return KNOT_ENOMEM;
		}

		memcpy(rrsets_new, *rrsets, count);

		dnslib_rrset_t **rrsets_old = *rrsets;
		*rrsets = rrsets_new;
		*allocated += XFRIN_CHANGESET_RRSET_STEP;
		free(rrsets_old);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_changeset_add_rrset(dnslib_rrset_t ***rrsets,
                                     size_t *count, size_t *allocated,
                                     dnslib_rrset_t *rrset)
{
	int ret = xfrin_changeset_check_count(rrsets, *count, allocated);
	if (ret != KNOT_EOK) {
		return ret;
	}

	(*rrsets)[(*count)++] = rrset;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static void xfrin_changeset_remove_last_rrset(dnslib_rrset_t **rrsets,
                                              size_t *count)
{
	rrsets[--(*count)] = NULL;
}

/*----------------------------------------------------------------------------*/

static int xfrin_check_binary_size(uint8_t **data, size_t *allocated,
                                   size_t required)
{
	if (required > *allocated) {
		size_t new_size = *allocated;
		while (new_size <= required) {
			new_size += XFRIN_CHANGESET_BINARY_STEP;
		}
		uint8_t *new_data = (uint8_t *)malloc(new_size);
		if (new_data == NULL) {
			return KNOT_ENOMEM;
		}

		memcpy(new_data, *data, *allocated);
		uint8_t *old_data = *data;
		*data = new_data;
		*allocated = new_size;
		free(old_data);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_changeset_rrset_to_binary(uint8_t **data, size_t *size,
                                           size_t *allocated,
                                           dnslib_rrset_t *rrset)
{
	assert(data != NULL);
	assert(size != NULL);
	assert(allocated != NULL);

	/*
	 * In *data, there is the whole changeset in the binary format,
	 * the actual RRSet will be just appended to it
	 */

	uint8_t *binary = NULL;
	size_t actual_size = 0;

	/*! \todo Call function for serializing RRSet. */

	int ret = xfrin_check_binary_size(data, allocated, *size + actual_size);
	if (ret != KNOT_EOK) {
		free(binary);
		return ret;
	}

	memcpy(*data + *size, binary, actual_size);
	*size += actual_size;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

typedef enum {
	XFRIN_CHANGESET_ADD,
	XFRIN_CHANGESET_REMOVE
} xfrin_changeset_part_t;

static int xfrin_changeset_append_rrset(xfrin_changeset_t *changeset,
                                        dnslib_rrset_t *rrset,
                                        xfrin_changeset_part_t part)
{
	dnslib_rrset_t ***rrsets = NULL;
	size_t *count = NULL;
	size_t *allocated = NULL;

	switch (part) {
	case XFRIN_CHANGESET_ADD:
		rrsets = &changeset->add;
		count = &changeset->add_count;
		allocated = &changeset->add_allocated;
		break;
	case XFRIN_CHANGESET_REMOVE:
		rrsets = &changeset->remove;
		count = &changeset->remove_count;
		allocated = &changeset->remove_allocated;
		break;
	default:
		assert(0);
	}

	assert(rrsets != NULL);
	assert(count != NULL);
	assert(allocated != NULL);

	int ret = xfrin_changeset_add_rrset(rrsets, count, allocated, rrset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = xfrin_changeset_rrset_to_binary(&changeset->data,
	                                      &changeset->size,
	                                      &changeset->allocated, rrset);
	if (ret != KNOT_EOK) {
		xfrin_changeset_remove_last_rrset(*rrsets, count);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

static int xfrin_changeset_add_soa(xfrin_changeset_t *changeset,
                                   dnslib_rrset_t *soa,
                                   xfrin_changeset_part_t part)
{
	dnslib_rrset_t **rrset = NULL;
	uint32_t *serial = NULL;

	switch (part) {
	case XFRIN_CHANGESET_ADD:
		changeset->soa_to = soa;
		changeset->serial_to = dnslib_rdata_soa_serial(
				dnslib_rrset_rdata(soa));
		break;
	case XFRIN_CHANGESET_REMOVE:
		changeset->soa_from = soa;
		changeset->serial_from = dnslib_rdata_soa_serial(
				dnslib_rrset_rdata(soa));
		break;
	default:
		assert(0);
	}

	/*! \todo Remove return value? */
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int xfrin_process_ixfr_packet(const uint8_t *pkt, size_t size,
                              xfrin_changesets_t **changesets)
{
	if (pkt == NULL || changesets == NULL) {
		debug_xfr("Wrong parameters supported.\n");
		return KNOT_EINVAL;
	}

	dnslib_packet_t *packet = NULL;
	dnslib_rrset_t *soa1 = NULL;
	dnslib_rrset_t *soa2 = NULL;
	dnslib_rrset_t *rr = NULL;

	int ret;

	if ((ret = xfrin_parse_first_rr(&packet, pkt, size, &soa1))
	     != KNOT_EOK) {
		return ret;
	}

	assert(packet != NULL);

	if (soa1 == NULL) {
		debug_xfr("No RRs in the packet.\n");
		dnslib_packet_free(&packet);
		/*! \todo Some other action??? */
		return KNOT_EMALF;
	}

	assert(soa1 != NULL);

	if (*changesets == NULL
	    && (ret = xfrin_allocate_changesets(changesets)) != KNOT_EOK) {
		dnslib_packet_free(&packet);
		return ret;
	}

	/*! \todo Do some checking about what is the first and second SOA. */

	if (dnslib_rrset_type(soa1) != DNSLIB_RRTYPE_SOA) {
		debug_xfr("First RR is not a SOA RR!\n");
		dnslib_packet_free(&packet);
		return KNOT_EMALF;
	}

	// we may drop this SOA, not needed right now; parse the next one
	ret = dnslib_packet_parse_next_rr_answer(packet, &rr);

	/*! \todo replace by (*changesets)->count */
	int i = 0;

	while (ret == DNSLIB_EOK && rr != NULL) {
		if (dnslib_rrset_type(rr) != DNSLIB_RRTYPE_SOA) {
			debug_xfr("Next RR is not a SOA RR as it should be!\n");
			ret = KNOT_EMALF;
			goto cleanup;
		}

		if (dnslib_rdata_soa_serial(dnslib_rrset_rdata(rr))
		    == dnslib_rdata_soa_serial(dnslib_rrset_rdata(soa1))) {
			soa2 = rr;
			break;
		}

		if ((ret = xfrin_changesets_check_size(*changesets))
		     != KNOT_EOK) {
			dnslib_rrset_deep_free(&rr, 1, 1, 1);
			goto cleanup;
		}

		// save the origin SOA of the remove part
		ret = xfrin_changeset_add_soa(&(*changesets)->sets[i], rr,
		                              XFRIN_CHANGESET_REMOVE);
		if (ret != KNOT_EOK) {
			dnslib_rrset_deep_free(&rr, 1, 1, 1);
			goto cleanup;
		}

		ret = dnslib_packet_parse_next_rr_answer(packet, &rr);
		while (ret == DNSLIB_EOK && rr != NULL) {
			if (dnslib_rrset_type(rr) == DNSLIB_RRTYPE_SOA) {
				break;
			}

			assert(dnslib_rrset_type(rr) != DNSLIB_RRTYPE_SOA);
			if ((ret = xfrin_changeset_append_rrset(
			             &(*changesets)->sets[i], rr,
			             XFRIN_CHANGESET_ADD)) != KNOT_EOK) {
				dnslib_rrset_deep_free(&rr, 1, 1, 1);
				goto cleanup;
			}
		}

		/*! \todo Replace by check. */
		assert(rr != NULL
		       && dnslib_rrset_type(rr) == DNSLIB_RRTYPE_SOA);

		// save the origin SOA of the add part
		ret = xfrin_changeset_add_soa(&(*changesets)->sets[i], rr,
		                              XFRIN_CHANGESET_ADD);
		if (ret != KNOT_EOK) {
			dnslib_rrset_deep_free(&rr, 1, 1, 1);
			goto cleanup;
		}

		ret = dnslib_packet_parse_next_rr_answer(packet, &rr);
		while (ret == DNSLIB_EOK && rr != NULL) {
			if (dnslib_rrset_type(rr) == DNSLIB_RRTYPE_SOA) {
				break;
			}

			assert(dnslib_rrset_type(rr) != DNSLIB_RRTYPE_SOA);
			if ((ret = xfrin_changeset_append_rrset(
			             &(*changesets)->sets[i], rr,
			             XFRIN_CHANGESET_REMOVE)) != KNOT_EOK) {
				dnslib_rrset_deep_free(&rr, 1, 1, 1);
				goto cleanup;
			}
		}

		/*! \todo Replace by check. */
		assert(rr != NULL
		       && dnslib_rrset_type(rr) == DNSLIB_RRTYPE_SOA);

		// next chunk, continue the whole loop
		++i;
	}

	if (ret != DNSLIB_EOK) {
		debug_xfr("Could not parse next Answer RR: %s.\n",
		          dnslib_strerror(ret));
		ret = KNOT_EMALF;
		goto cleanup;
	}

	/*! \todo Replace by checks? */
	assert(soa2 != NULL);
	assert(dnslib_rrset_type(soa2) == DNSLIB_RRTYPE_SOA);
	assert(dnslib_rdata_soa_serial(dnslib_rrset_rdata(soa1))
	       == dnslib_rdata_soa_serial(dnslib_rrset_rdata(soa2)));

	dnslib_rrset_deep_free(&soa2, 1, 1, 1);

	return KNOT_EOK;

cleanup:
	xfrin_free_changesets(changesets);
	dnslib_packet_free(&packet);
	return ret;
}
