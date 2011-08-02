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
#include "knot/server/zones.h"
#include "common/acl.h"
#include "common/evsched.h"
#include "knot/other/debug.h"
#include "knot/server/server.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static int notify_request(const knot_rrset_t *rrset,
                          uint8_t *buffer, size_t *size)
{
	knot_packet_t *pkt = knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	CHECK_ALLOC_LOG(pkt, KNOTD_ENOMEM);

	/*! \todo Get rid of the numeric constant. */
	int rc = knot_packet_set_max_size(pkt, 512);
	if (rc != KNOT_EOK) {
		knot_packet_free(&pkt);
		return KNOTD_ERROR;
	}

	rc = knot_query_init(pkt);
	if (rc != KNOT_EOK) {
		knot_packet_free(&pkt);
		return KNOTD_ERROR;
	}

	knot_question_t question;

	// this is ugly!!
	question.qname = rrset->owner;
	question.qtype = rrset->type;
	question.qclass = rrset->rclass;

	rc = knot_query_set_question(pkt, &question);
	if (rc != KNOT_EOK) {
		knot_packet_free(&pkt);
		return KNOTD_ERROR;
	}

	/*! \todo Set some random ID!! */

	/*! \todo add the SOA RR to the Answer section as a hint */
	/*! \todo this should not use response API!! */
//	rc = knot_response2_add_rrset_answer(pkt, rrset, 0, 0, 0);
//	if (rc != KNOT_EOK) {
//		knot_packet_free(&pkt);
//		return rc;
//	}

	/*! \todo this should not use response API!! */
	knot_response2_set_aa(pkt);

	knot_query_set_opcode(pkt, KNOT_OPCODE_NOTIFY);

	/*! \todo OPT RR ?? */

	uint8_t *wire = NULL;
	size_t wire_size = 0;
	rc = knot_packet_to_wire(pkt, &wire, &wire_size);
	if (rc != KNOT_EOK) {
		knot_packet_free(&pkt);
		return KNOTD_ERROR;
	}

	if (wire_size > *size) {
		knot_packet_free(&pkt);
		return KNOTD_ESPACE;
	}

	memcpy(buffer, wire, wire_size);
	*size = wire_size;

	knot_packet_dump(pkt);

	knot_packet_free(&pkt);

	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int notify_create_response(knot_packet_t *request, uint8_t *buffer,
                           size_t *size)
{
	knot_packet_t *response =
		knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	CHECK_ALLOC_LOG(response, KNOTD_ENOMEM);

	knot_response2_init_from_query(response, request);

	// TODO: copy the SOA in Answer section

	uint8_t *wire = NULL;
	size_t wire_size = 0;
	int rc = knot_packet_to_wire(response, &wire, &wire_size);
	if (rc != KNOT_EOK) {
		knot_packet_free(&response);
		return rc;
	}

	if (wire_size > *size) {
		knot_packet_free(&response);
		return KNOTD_ESPACE;
	}

	memcpy(buffer, wire, wire_size);
	*size = wire_size;

	knot_packet_dump(response);

	knot_packet_free(&response);

	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int notify_create_request(const knot_zone_contents_t *zone, uint8_t *buffer,
                          size_t *size)
{
	const knot_rrset_t *soa_rrset = knot_node_rrset(
		            knot_zone_contents_apex(zone), KNOT_RRTYPE_SOA);
	if (soa_rrset == NULL) {
		return KNOTD_ERROR;
	}

	return notify_request(soa_rrset, buffer, size);
}

/*----------------------------------------------------------------------------*/

static int notify_check_and_schedule(const knot_nameserver_t *nameserver,
                                     const knot_zone_t *zone,
                                     sockaddr_t *from)
{
	if (zone == NULL || from == NULL || knot_zone_data(zone) == NULL) {
		return KNOTD_EINVAL;
	}
	
	/* Check ACL for notify-in. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (from) {
		if (acl_match(zd->notify_in, from) == ACL_DENY) {
			/* rfc1996: Ignore request and report incident. */
			char straddr[SOCKADDR_STRLEN];
			sockaddr_tostr(from, straddr, sizeof(straddr));
			debug_notify("Unauthorized NOTIFY request "
			                 "from %s:%d.\n",
			                 straddr, sockaddr_portnum(from));
			return KNOT_ERROR;
		} else {
			debug_notify("notify: authorized NOTIFY query.\n");
		}
	}

	/*! \todo Packet may contain updated RRs. */

	/* Cancel EXPIRE timer. */
	evsched_t *sched = nameserver->server->sched;
	event_t *expire_ev = zd->xfr_in.expire;
	if (expire_ev) {
		debug_notify("notify: canceling EXPIRE timer\n");
		evsched_cancel(sched, expire_ev);
		evsched_event_free(sched, expire_ev);
		zd->xfr_in.expire = 0;
	}

	/* Cancel REFRESH/RETRY timer. */
	event_t *refresh_ev = zd->xfr_in.timer;
	if (refresh_ev) {
		debug_notify("notify: canceling REFRESH timer for XFRIN\n");
		evsched_cancel(sched, refresh_ev);

		/* Set REFRESH timer for now. */
		evsched_schedule(sched, refresh_ev, 0);
	}
	
	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int notify_process_request(const knot_nameserver_t *nameserver,
                           knot_packet_t *notify,
                           sockaddr_t *from,
                           uint8_t *buffer, size_t *size)
{
	/*! \todo Most of this function is identical to xfrin_transfer_needed()
	 *        - it will be fine to merge the code somehow.
	 */

	if (notify == NULL || nameserver == NULL || buffer == NULL 
	    || size == NULL || from == NULL) {
		return KNOTD_EINVAL;
	}

	int ret;

	if (notify->parsed < notify->size) {
		ret = knot_packet_parse_rest(notify);
		if (ret != KNOT_EOK) {
			return KNOTD_EMALF;
		}
	}

	// create NOTIFY response
	ret = notify_create_response(notify, buffer, size);
	if (ret != KNOTD_EOK) {
		return KNOTD_ERROR;	/*! \todo Some other error. */
	}

	// find the zone
	const knot_dname_t *qname = knot_packet_qname(notify);
	const knot_zone_t *z = knot_zonedb_find_zone_for_name(
			nameserver->zone_db, qname);
	if (z == NULL) {
		return KNOTD_ERROR;	/*! \todo Some other error. */
	}

	notify_check_and_schedule(nameserver, z, from);
	
	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int notify_process_response(const knot_nameserver_t *nameserver,
                            knot_packet_t *notify,
                            sockaddr_t *from,
                            uint8_t *buffer, size_t *size)
{
	if (nameserver == NULL || notify == NULL || from == NULL 
	    || buffer == NULL || size == NULL) {
		return KNOTD_EINVAL;
	}

	/* Assert no response size. */
	*size = 0;

	/* Find matching zone. */
	const knot_dname_t *zone_name = knot_packet_qname(notify);
	knot_zone_t *zone = knot_zonedb_find_zone(nameserver->zone_db,
	                                              zone_name);
	if (!zone) {
		return KNOTD_ENOENT;
	}
	if (!knot_zone_data(zone)) {
		return KNOTD_ENOENT;
	}

	/* Match ID against awaited. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	uint16_t pkt_id = knot_packet_id(notify);
	notify_ev_t *ev = 0, *match = 0;
	WALK_LIST(ev, zd->notify_pending) {
		if ((int)pkt_id == ev->msgid) {
			match = ev;
			break;
		}
	}

	/* Found waiting NOTIFY query? */
	if (!match) {
		debug_notify("notify: no pending NOTIFY query found for ID=%u\n",
			 pkt_id);
		return KNOTD_ERROR;
	}

	/* Cancel RETRY timer, NOTIFY is now finished. */
	evsched_t *sched = nameserver->server->sched;
	if (match->timer) {
		evsched_cancel(sched, match->timer);
		evsched_event_free(sched, match->timer);
		match->timer = 0;
		rem_node(&match->n);
		free(match);
	}

	debug_notify("notify: received response for pending NOTIFY query ID=%u\n",
		 pkt_id);

	return KNOTD_EOK;
}

