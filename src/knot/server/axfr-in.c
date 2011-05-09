#include "knot/server/axfr-in.h"

#include "knot/common.h"
#include "knot/other/error.h"
#include "dnslib/packet.h"
#include "dnslib/dname.h"
#include "dnslib/zone.h"
#include "dnslib/query.h"
#include "dnslib/error.h"
#include "knot/other/log.h"

/*----------------------------------------------------------------------------*/

int axfrin_create_soa_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                            size_t *size)
{
	dnslib_packet_t *pkt = dnslib_packet_new(DNSLIB_PACKET_PREALLOC_QUERY);
	CHECK_ALLOC_LOG(pkt, KNOT_ENOMEM);

	/*! \todo Get rid of the numeric constant. */
	int rc = dnslib_packet_set_max_size(pkt, 512);
	if (rc != DNSLIB_EOK) {
		dnslib_packet_free(&pkt);
		return rc;
	}

	rc = dnslib_query_init(pkt);
	if (rc != DNSLIB_EOK) {
		dnslib_packet_free(&pkt);
		return rc;
	}

	dnslib_question_t question;

	// this is ugly!!
	question.qname = (dnslib_dname_t *)zone_name;
	question.qtype = DNSLIB_RRTYPE_SOA;
	question.qclass = DNSLIB_CLASS_IN;

	rc = dnslib_query_set_question(pkt, &question);
	if (rc != DNSLIB_EOK) {
		dnslib_packet_free(&pkt);
		return rc;
	}

	/*! \todo OPT RR ?? */

	uint8_t *wire = NULL;
	size_t wire_size = 0;
	rc = dnslib_packet_to_wire(pkt, &wire, &wire_size);
	if (rc != DNSLIB_EOK) {
		dnslib_packet_free(&pkt);
		return rc;
	}

	if (wire_size > *size) {
		log_answer_warning("Not enough space provided for the wire "
		                   "format of the query.\n");
		dnslib_packet_free(&pkt);
		return KNOT_ESPACE;
	}

	memcpy(buffer, wire, wire_size);
	*size = wire_size;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int axfrin_transfer_needed(const dnslib_zone_t *zone,
                           const dnslib_packet_t *soa_response)
{
	return KNOT_ERROR;
}

/*----------------------------------------------------------------------------*/

int axfrin_create_axfr_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                             size_t *size)
{
	return KNOT_ERROR;
}
