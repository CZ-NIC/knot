#ifndef DNS_SIMPLE
#define DNS_SIMPLE

#include <stdint.h>
#include <string.h>
#include "common.h"

static const unsigned int HEADER_SIZE =    12;
static const unsigned int MAX_DNAME_SIZE = 255; // contains the ending 0?

/*----------------------------------------------------------------------------*/

struct dnss_rr {
    char *owner;        // domain name in wire format
    uint16_t rrtype;
    uint16_t rrclass;
    uint32_t ttl;
    uint16_t rdlength;
    unsigned char *rdata;
};  // size: (10 + rdlength + strlen(owner) + 1) B

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
    char *qname;        // domain name in wire format
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

dnss_rr *dnss_create_rr( char *owner );

dnss_question *dnss_create_question( char *qname, uint length );

dnss_packet *dnss_create_empty_packet();

int dnss_create_response( dnss_packet *query, dnss_rr *answers,
                           uint count, dnss_packet **response );

int dnss_create_error_response( dnss_packet *query, dnss_packet **response );

dnss_packet *dnss_parse_query( const char *query_wire, uint size );

int dnss_wire_format( dnss_packet *packet, char *packet_wire,
                      uint *packet_size );

int dnss_dname_to_wire( char *dname, char *dname_wire, uint size  );

inline uint dnss_wire_dname_size( char *dname );

void dnss_destroy_rr( dnss_rr **rr );

void dnss_destroy_question( dnss_question **question );

void dnss_destroy_packet( dnss_packet **packet );

#endif /* DNS_SIMPLE */
