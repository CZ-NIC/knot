#ifndef DNS_SIMPLE
#define DNS_SIMPLE

#include <stdint.h>

#define RRTYPE_DEFAULT		1		// A
#define RRCLASS_DEFAULT		1		// IN
#define TTL_DEFAULT			3600

typedef unsigned int uint;

/*----------------------------------------------------------------------------*/

struct dnss_rr {
	uint16_t rrtype;
	uint16_t rrclass;
	uint32_t ttl;
	uint16_t rdlength;
	unsigned char *rdata;
};	// size: (14 + rdlength) B

typedef struct dnss_rr dnss_rr;

/*----------------------------------------------------------------------------*/

struct dnss_header {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

typedef struct dnss_header dnss_header;

/*----------------------------------------------------------------------------*/

struct dnss_question {
	unsigned char *qname;
	uint16_t qtype;
	uint16_t qclass;
};

typedef struct dnss_question dnss_question;

/*----------------------------------------------------------------------------*/

struct dnss_packet {
	dnss_header header;
	dnss_question *questions;
	dnss_rr *answers;
	dnss_rr *authority;
	dnss_rr *additional;
};

typedef struct dnss_packet dnss_packet;

/*----------------------------------------------------------------------------*/

dnss_rr *dnss_create_rr( unsigned char *data, uint length, void *place );

dnss_question *dnss_create_question( unsigned char *qname, uint length );

dnss_packet *dnss_create_response( dnss_question *question, dnss_rr *answers );

unsigned char *dnss_wire_format( dnss_packet *packet );

#endif /* DNS_SIMPLE */
