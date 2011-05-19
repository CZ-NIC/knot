#include <assert.h>

#include "knot/server/notify.h"

#include "dnslib/dname.h"
#include "dnslib/packet.h"
#include "dnslib/rrset.h"
#include "dnslib/response2.h"
#include "dnslib/query.h"
#include "dnslib/consts.h"
#include "knot/other/error.h"
#include "dnslib/zonedb.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static int notify_request(const dnslib_rrset_t *rrset,
                          uint8_t *buffer, size_t *size)
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
	question.qname = rrset->owner;
	question.qtype = rrset->type;
	question.qclass = rrset->rclass;

	rc = dnslib_query_set_question(pkt, &question);
	if (rc != DNSLIB_EOK) {
		dnslib_packet_free(&pkt);
		return KNOT_ERROR;
	}

	/*! \todo Set some random ID!! */

	/*! \todo add the SOA RR to the Answer section as a hint */
	/*! \todo this should not use response API!! */
//	rc = dnslib_response2_add_rrset_answer(pkt, rrset, 0, 0, 0);
//	if (rc != DNSLIB_EOK) {
//		dnslib_packet_free(&pkt);
//		return rc;
//	}

	/*! \todo this should not use response API!! */
	dnslib_response2_set_aa(pkt);

	dnslib_query_set_opcode(pkt, DNSLIB_OPCODE_NOTIFY);

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

int notify_create_response(dnslib_packet_t *request, uint8_t *buffer,
                           size_t *size)
{
	dnslib_packet_t *response =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_QUERY);
	CHECK_ALLOC_LOG(response, KNOT_ENOMEM);

	dnslib_response2_init_from_query(response, request);

	// TODO: copy the SOA in Answer section

	uint8_t *wire = NULL;
	size_t wire_size = 0;
	rc = dnslib_packet_to_wire(response, &wire, &wire_size);
	if (rc != DNSLIB_EOK) {
		dnslib_packet_free(&response);
		return rc;
	}

	if (wire_size > *size) {
		log_answer_warning("Not enough space provided for the wire "
		                   "format of the query.\n");
		dnslib_packet_free(&response);
		return KNOT_ESPACE;
	}

	memcpy(buffer, wire, wire_size);
	*size = wire_size;

	debug_ns("Created query of size %zu.\n", *size);
	dnslib_packet_dump(response);

	dnslib_packet_free(&response);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int notify_create_request(const dnslib_zone_t *zone, uint8_t *buffer,
                          size_t *size)
{
	dnslib_rrset_t *soa_rrset =
		dnslib_node_rrset(dnslib_zone_apex(zone), DNSLIB_RRTYPE_SOA);
	if (soa_rrset == NULL) {
		return KNOT_ERROR;
	}

	return notify_request(soa_rrset, buffer, size);
}

/*----------------------------------------------------------------------------*/

int notify_process_request(dnslib_packet_t *notify,
                           const dnslib_zonedb_t *zonedb,
                           const dnslib_zone_t **zone,
                           uint8_t *buffer, size_t *size)
{
	/*! \todo Most of this function is identical to xfrin_transfer_needed()
	 *        - it will be fine to merge the code somehow.
	 */

	if (notify == NULL || zone == NULL || buffer == NULL || size == NULL) {
		return KNOT_EINVAL;
	}

	*zone = NULL;

	debug_ns("Notify request - parsed: %zu, total wire size: %zu\n",
	         notify->parsed, notify->size);
	int ret;

	if (notify->parsed < notify->size) {
		ret = dnslib_packet_parse_rest(notify);
		if (ret != DNSLIB_EOK) {
			return KNOT_EMALF;
		}
	}

	// create NOTIFY response
	ret = notify_create_response(notify, buffer, size);
	if (ret != KNOT_EOK) {
		return KNOT_ERROR;	/*! \todo Some other error. */
	}

	// find the zone
	dnslib_dname_t *qname = dnslib_packet_qname(notify);
	*zone = dnslib_zonedb_find_zone_for_name(zonedb, qname);
	if (*zone == NULL) {
		return KNOT_ERROR;	/*! \todo Some other error. */
	}

	/*! \todo Merge this with ns_answer_notify().
	 *        According to RFC 1996, slave should
	 *        behave as if the REFRESH timer has expired
	 *        i.e. it should send SOA query to the master.
	 *        No further processing after this comment is needed.
	 */


	// check if the zone needs an update
	dnslib_rrset_t *soa_rrset = dnslib_node_rrset(dnslib_zone_apex(*zone),
	                                              DNSLIB_RRTYPE_SOA);
	if (soa_rrset == NULL) {
		char *name = dnslib_dname_to_str(dnslib_rrset_owner(soa_rrset));
		log_answer_warning("SOA RRSet missing in the zone %s!\n", name);
		free(name);
		return KNOT_ERROR;	/*! \todo Some other error. */
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
	soa_rrset = dnslib_packet_answer_rrset(notify, 0);
	if (soa_rrset == NULL
	    || dnslib_rrset_type(soa_rrset) != DNSLIB_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	int64_t remote_serial = dnslib_rdata_soa_serial(
		dnslib_rrset_rdata(soa_rrset));
	if (remote_serial < 0) {
		return KNOT_EMALF;	// maybe some other error
	}

	// if the Serials are identical, no transfer is needed
	if (local_serial == remote_serial) {
		*zone = NULL;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int notify_process_response(const dnslib_zone_t *zone, dnslib_packet_t *notify)
{
	return KNOT_ENOTSUP;
}

