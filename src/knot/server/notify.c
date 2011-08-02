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

int notify_create_request(const dnslib_zone_contents_t *zone, uint8_t *buffer,
                          size_t *size)
{
	const dnslib_rrset_t *soa_rrset = dnslib_node_rrset(
		            dnslib_zone_contents_apex(zone), DNSLIB_RRTYPE_SOA);
	if (soa_rrset == NULL) {
		return KNOT_ERROR;
	}

	return notify_request(soa_rrset, buffer, size);
}

/*----------------------------------------------------------------------------*/

static int notify_check_and_schedule(const dnslib_nameserver_t *nameserver,
                                     const dnslib_zone_t *zone,
                                     sockaddr_t *from)
{
	if (zone == NULL || from == NULL || dnslib_zone_data(zone) == NULL) {
		return KNOT_EINVAL;
	}
	
	/* Check ACL for notify-in. */
	zonedata_t *zd = (zonedata_t *)dnslib_zone_data(zone);
	if (from) {
		if (acl_match(zd->notify_in, from) == ACL_DENY) {
			/* rfc1996: Ignore request and report incident. */
			char straddr[SOCKADDR_STRLEN];
			sockaddr_tostr(from, straddr, sizeof(straddr));
			debug_notify("Unauthorized NOTIFY request "
			                 "from %s:%d.\n",
			                 straddr, sockaddr_portnum(from));
			return DNSLIB_ERROR;
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
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int notify_process_request(const dnslib_nameserver_t *nameserver,
                           dnslib_packet_t *notify,
                           sockaddr_t *from,
                           uint8_t *buffer, size_t *size)
{
	/*! \todo Most of this function is identical to xfrin_transfer_needed()
	 *        - it will be fine to merge the code somehow.
	 */

	if (notify == NULL || nameserver == NULL || buffer == NULL 
	    || size == NULL || from == NULL) {
		return KNOT_EINVAL;
	}

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
	const dnslib_zone_t *z = dnslib_zonedb_find_zone_for_name(
			nameserver->zone_db, qname);
	if (z == NULL) {
		return KNOT_ERROR;	/*! \todo Some other error. */
	}

	notify_check_and_schedule(nameserver, z, from);
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int notify_process_response(const dnslib_nameserver_t *nameserver,
                            dnslib_packet_t *notify,
                            sockaddr_t *from,
                            uint8_t *buffer, size_t *size)
{
	if (nameserver == NULL || notify == NULL || from == NULL 
	    || buffer == NULL || size == NULL) {
		return KNOT_EINVAL;
	}

	/* Assert no response size. */
	*size = 0;

	/* Find matching zone. */
	const dnslib_dname_t *zone_name = dnslib_packet_qname(notify);
	dnslib_zone_t *zone = dnslib_zonedb_find_zone(nameserver->zone_db,
	                                              zone_name);
	if (!zone) {
		return KNOT_ENOENT;
	}
	if (!dnslib_zone_data(zone)) {
		return KNOT_ENOENT;
	}

	/* Match ID against awaited. */
	zonedata_t *zd = (zonedata_t *)dnslib_zone_data(zone);
	uint16_t pkt_id = dnslib_packet_id(notify);
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
		return KNOT_ERROR;
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

	return KNOT_EOK;
}

