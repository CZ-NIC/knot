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
#include "dnslib/dnslib-common.h"
#include "dnslib/error.h"

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
		dnslib_packet_free(&pkt);
		return KNOT_ESPACE;
	}

	memcpy(buffer, wire, wire_size);
	*size = wire_size;

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
	int rc = dnslib_packet_to_wire(response, &wire, &wire_size);
	if (rc != DNSLIB_EOK) {
		dnslib_packet_free(&response);
		return rc;
	}

	if (wire_size > *size) {
		dnslib_packet_free(&response);
		return KNOT_ESPACE;
	}

	memcpy(buffer, wire, wire_size);
	*size = wire_size;

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
	const dnslib_rrset_t *soa_rrset =
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

	//debug_ns("Notify request - parsed: %zu, total wire size: %zu\n",
	//         notify->parsed, notify->size);
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
	const dnslib_dname_t *qname = dnslib_packet_qname(notify);
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

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int notify_process_response(const dnslib_zone_t *zone, dnslib_packet_t *notify)
{
	return KNOT_ENOTSUP;
}

