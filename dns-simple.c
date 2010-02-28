#include "dns-simple.h"

#define HEADER_SET_QR(flags) (flags |= (1 << 15))
#define HEADER_SET_AA(flags) (flags |= (1 << 10))

/*----------------------------------------------------------------------------*/

dnss_rr *dnss_create_rr( unsigned char *data, uint length, void *place )
{
	dnss_rr *rr;
	unsigned char *rdata;

	rr = (place == NULL) ? malloc(sizeof(dnss_rr) + length) : place;

	rdata = rr + sizeof(dnss_rr);

	memcpy(rdata, data, length);

	rr->rrtype = RRTYPE_DEFAULT;
	rr->rrclass = RRCLASS_DEFAULT;
	rr->ttl = TTL_DEFAULT;
	rr->rdlength = length;
	rr->rdata = rdata;

	return rr;
}

/*----------------------------------------------------------------------------*/

dnss_question *dnss_create_question( unsigned char *qname, uint length )
{
	dnss_question *question = malloc(sizeof(dnss_question) + length);
	question->qname = question + sizeof(dnss_question);
	memcpy(question->qname, qname, length);
	question->qclass = RRCLASS_DEFAULT;
	question->qtype = RRTYPE_DEFAULT;

	return question;
}

/*----------------------------------------------------------------------------*/

dnss_packet *dnss_create_response( dnss_packet *query, dnss_rr *answers,
								   uint count )
{
	dnss_packet *packet = malloc(sizeof(dnss_packet));

	// header
	memcpy(packet->header, query->header, sizeof(dnss_header));	// copy header
	HEADER_SET_AA(packet->header);
	HEADER_SET_QR(packet->header);

	// questions; assuming that the domain names will not be deleted
	packet->questions = malloc(packet->header.qdcount * sizeof(dnss_question));
	memcpy(packet->questions, query->questions,
		   packet->header.qdcount * sizeof(dnss_question));

	// answers;
	packet->header.ancount = count;
	packet->answers = answers;

	packet->header.nscount = 0;
	packet->authority = NULL;
	packet->header.arcount = 0;
	packet->additional = NULL;

	return packet;
}

/*----------------------------------------------------------------------------*/

unsigned char *dnss_wire_format( dnss_packet *packet )
{

}
