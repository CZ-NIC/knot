#include "dns-simple.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

//#define DNSS_DEBUG

#define HEADER_SET_QR(flags) (flags |= (1 << 15))
#define HEADER_SET_AA(flags) (flags |= (1 << 10))

// RCODEs
static const uint16_t RCODE_NOERR = 0;		// 0..000000000
static const uint16_t RCODE_FORMERR = 1;	// 0..000000001
static const uint16_t RCODE_SERVFAIL = 2;	// 0..000000010
static const uint16_t RCODE_NXDOMAIN = 3;	// 0..000000011
static const uint16_t RCODE_NOTIMPL = 4;	// 0..000000100
static const uint16_t RCODE_REFUSED = 5;	// 0..000000101
static const uint16_t RCODE_YXDOMAIN = 6;	// 0..000000110
static const uint16_t RCODE_YXRRSET = 7;	// 0..000000111
static const uint16_t RCODE_NXRRSET = 8;	// 0..000001000
static const uint16_t RCODE_NOTAUTH = 9;	// 0..000001001
static const uint16_t RCODE_NOTZONE = 10;	// 0..000001010
static const uint16_t RCODE_CLEAR = 65520;  // 1..111110000

// assuming flags is 16bit integer
#define RCODE_SET(flags, rcode) flags = (flags & RCODE_CLEAR) | rcode

/*----------------------------------------------------------------------------*/

dnss_rr *dnss_create_rr( char *owner )
{
    // assuming owner is in natural format => conversion to wire format needed

	dnss_rr *rr;

#ifdef DNSS_DEBUG
    printf("Converting domain name to wire format.\n");
#endif

    // convert domain name to wire format
    char *owner_wire = dnss_dname_to_wire(owner);
    if (owner_wire == NULL) {
        return NULL;
    }

#ifdef DNSS_DEBUG
    printf("Creating RR structure.\n");
#endif
    rr = malloc(sizeof(dnss_rr) + RDLENGTH_DEFAULT);

    if (rr == NULL) {
        free(owner_wire);
        return NULL;
    }

    // rdata will be saved at the end of the RR
    rr->rdata = (unsigned char *)rr + sizeof(dnss_rr);
    memcpy(rr->rdata, RDATA_DEFAULT, RDLENGTH_DEFAULT);

    rr->rrtype = RRTYPE_DEFAULT;
	rr->rrclass = RRCLASS_DEFAULT;
	rr->ttl = TTL_DEFAULT;
    rr->rdlength = RDLENGTH_DEFAULT;

    rr->owner = owner_wire;

    // owner will be saved at the end of the RR behind rdata
    //rr->owner = (char *)rr->rdata + RDLENGTH_DEFAULT;
    //memcpy(rr->owner, owner_wire, strlen(owner_wire) + 1);
    //free(owner_wire);

#ifdef DNSS_DEBUG
    printf("Done.\n");
#endif
	return rr;
}

/*----------------------------------------------------------------------------*/

dnss_question *dnss_create_question( char *qname, uint length )
{
	dnss_question *question = malloc(sizeof(dnss_question) + length);
    question->qname = (char *)question + sizeof(dnss_question);
	memcpy(question->qname, qname, length);
	question->qclass = RRCLASS_DEFAULT;
	question->qtype = RRTYPE_DEFAULT;

	return question;
}

/*----------------------------------------------------------------------------*/

dnss_packet *dnss_create_empty_packet()
{
    dnss_packet *packet = malloc(sizeof(dnss_packet));
    memset(packet, 0, sizeof(dnss_packet));
    return packet;
}

/*----------------------------------------------------------------------------*/

void dnss_create_response( dnss_packet *query, dnss_rr *answers,
                           uint count, dnss_packet **response )
{
	// header
    memcpy(&(*response)->header, &query->header, sizeof(dnss_header));
    HEADER_SET_AA((*response)->header.flags);
    HEADER_SET_QR((*response)->header.flags);
    // copying other flags (maybe set TC, RA, AD, CD)

	// questions; assuming that the domain names will not be deleted
    // (maybe some copying function would be useful?)
    (*response)->questions = malloc(
            (*response)->header.qdcount * sizeof(dnss_question));
    memcpy((*response)->questions, query->questions,
           (*response)->header.qdcount * sizeof(dnss_question));

	// answers;
    (*response)->header.ancount = count;
    (*response)->answers = (count == 0) ? NULL : answers;
        // distinguish between NODATA (good as it is) and NXDOMAIN (set RCODE)

    (*response)->header.nscount = 0;
    (*response)->authority = NULL;
    (*response)->header.arcount = 0;
    (*response)->additional = NULL;
}

/*----------------------------------------------------------------------------*/

void dnss_create_error_response( dnss_packet *query, dnss_packet **response )
{
    // header
    memcpy(&(*response)->header, &query->header, sizeof(dnss_header));
    HEADER_SET_AA((*response)->header.flags);
    HEADER_SET_QR((*response)->header.flags);
    // copying other flags (maybe set TC, RA, AD, CD)

    // set SERVFAIL RCODE
    RCODE_SET((*response)->header.flags, RCODE_SERVFAIL);

    // questions; assuming that the domain names will not be deleted
    // (maybe some copying function would be useful?)
    (*response)->questions = malloc((*response)->header.qdcount * sizeof(dnss_question));
    memcpy((*response)->questions, query->questions,
           (*response)->header.qdcount * sizeof(dnss_question));

    // no answers
    (*response)->header.ancount = 0;
    (*response)->answers = NULL;
    (*response)->header.nscount = 0;
    (*response)->authority = NULL;
    (*response)->header.arcount = 0;
    (*response)->additional = NULL;
}

/*----------------------------------------------------------------------------*/

void dnss_wire_format( dnss_packet *packet, char *packet_wire,
                       unsigned int *packet_size  )
{
    /* We can assume that the domain names are kept in the wire format during
     * copying among the application. Thus no conversion needed here.
     * All integers must be converted to the network byte order.
     */

    // in *packet_size there should be the max size of the wire format

    // determine the size of the packet
    uint real_size = HEADER_SIZE;
    real_size = HEADER_SIZE;
    for (int i = 0; i < packet->header.qdcount; ++i) {
        real_size += strlen(packet->questions[i].qname) + 5;
    }
    for (int i = 0; i < packet->header.ancount; ++i) {
        real_size += strlen(packet->answers[i].owner)
                       + 11 + packet->answers[i].rdlength;
    }
    for (int i = 0; i < packet->header.nscount; ++i) {
        real_size += strlen(packet->authority[i].owner)
                       + 11 + packet->authority[i].rdlength;
    }
    for (int i = 0; i < packet->header.arcount; ++i) {
        real_size += strlen(packet->additional[i].owner)
                       + 11 + packet->additional[i].rdlength;
    }

    if (real_size > *packet_size) {
        *packet_size = 0;
        return;
    }

    *packet_size = real_size;

    //packet_wire = malloc(*packet_size);

//    if (packet_wire == NULL) {
//        fprintf(stderr, "Allocation failed in dnss_wire_format().\n");
//        *packet_size = 0;
//        return;
//    }

    char *p = packet_wire;

    ((dnss_header *)p)->id = htons(packet->header.id);
    ((dnss_header *)p)->flags = htons(packet->header.flags);
    ((dnss_header *)p)->qdcount = htons(packet->header.qdcount);
    ((dnss_header *)p)->ancount = htons(packet->header.ancount);
    ((dnss_header *)p)->nscount = htons(packet->header.nscount);
    ((dnss_header *)p)->arcount = htons(packet->header.arcount);

    p += sizeof(dnss_header);

    for (int i = 0; i < packet->header.qdcount; ++i) {
        memcpy(p, packet->questions[i].qname,
               strlen(packet->questions[i].qname) + 1); // copy domain name
        p += strlen(packet->questions[i].qname) + 1;
        *((uint16_t *)p) = htons(packet->questions[i].qtype);
        p += 2;
        *((uint16_t *)p) = htons(packet->questions[i].qclass);
        p += 2;
    }
    for (int i = 0; i < packet->header.ancount; ++i) {
        memcpy(p, packet->answers[i].owner,
               strlen(packet->answers[i].owner) + 1);   // copy owner name
        p += strlen(packet->answers[i].owner) + 1;
        *((uint16_t *)p) = htons(packet->answers[i].rrtype);
        p += 2;
        *((uint16_t *)p) = htons(packet->answers[i].rrclass);
        p += 2;
        *((uint32_t *)p) = htonl(packet->answers[i].ttl);
        p += 4;
        *((uint16_t *)p) = htons(packet->answers[i].rdlength);
        p += 2;
        memcpy(p, packet->answers[i].rdata,
               packet->answers[i].rdlength);        // copy rdata
        p += packet->answers[i].rdlength;
    }
    for (int i = 0; i < packet->header.nscount; ++i) {
        memcpy(p, packet->authority[i].owner,
               strlen(packet->authority[i].owner) + 1);   // copy owner name
        p += strlen(packet->authority[i].owner) + 1;
        *((uint16_t *)p) = htons(packet->authority[i].rrtype);
        p += 2;
        *((uint16_t *)p) = htons(packet->authority[i].rrclass);
        p += 2;
        *((uint32_t *)p) = htonl(packet->authority[i].ttl);
        p += 4;
        *((uint16_t *)p) = htons(packet->authority[i].rdlength);
        p += 2;
        memcpy(p, packet->authority[i].rdata,
               packet->authority[i].rdlength);        // copy rdata
        p += packet->authority[i].rdlength;
    }
    for (int i = 0; i < packet->header.ancount; ++i) {
        memcpy(p, packet->additional[i].owner,
               strlen(packet->additional[i].owner) + 1);   // copy owner name
        p += strlen(packet->additional[i].owner) + 1;
        *((uint16_t *)p) = htons(packet->additional[i].rrtype);
        p += 2;
        *((uint16_t *)p) = htons(packet->additional[i].rrclass);
        p += 2;
        *((uint32_t *)p) = htonl(packet->additional[i].ttl);
        p += 4;
        *((uint16_t *)p) = htons(packet->additional[i].rdlength);
        p += 2;
        memcpy(p, packet->additional[i].rdata,
               packet->additional[i].rdlength);        // copy rdata
        p += packet->additional[i].rdlength;
    }
}

/*----------------------------------------------------------------------------*/

char *dnss_dname_to_wire( char *dname )   // NEEDS TESTING!!
{
    // if there is a trailing dot, size of the wire name will be the same as the
    // size of the normal domain name (for each dot there is a number of chars)
    // otherwise it is +1
    char *wire_name = malloc((dname[strlen(dname) - 1] == '.')
                                      ? (strlen(dname) + 1)
                                      : (strlen(dname) + 2) );

    if (wire_name == NULL) {
        return NULL;
    }

    int w = 0;

    char *c = dname;

    char *buffer = malloc(strlen(dname) + 1);
    if (buffer == NULL) {
        free(wire_name);
        return NULL;
    }

    uint8_t chars = 0;

    while (*c != '\0') {
        memset(buffer, 0, strlen(dname) + 1);   // maybe not needed
        chars = 0;
        while (*c != '.' && *c != '\0') {   // read next label
            buffer[++chars] = *c++;
        }
        buffer[0] = chars;    // number of characters in this label

#ifdef DNSS_DEBUG
        printf("Chars: %d, Buffer: %*s\n", chars, chars + 1, buffer);
#endif

        memcpy(&wire_name[w], buffer, chars + 1);   // copy the label
        w += chars + 1;

        if (*c == '.') {
            c++;
        }
    }

    wire_name[w] = '\0';

#ifdef DNSS_DEBUG
    printf("Wire format of the domain name: %*s\n", w + 1, wire_name);
#endif

    free(buffer);
    return wire_name;
}

/*----------------------------------------------------------------------------*/

uint dnss_wire_dname_size( char *dname )
{
    return (dname[strlen(dname) - 1] == '.')
            ? (strlen(dname) + 1)
            : (strlen(dname) + 2);
}

/*----------------------------------------------------------------------------*/

dnss_packet *dnss_parse_query( const char *query_wire, uint size )
{
    assert(size > 12);

#ifdef DNSS_DEBUG
    printf("dnss_parse_query() called with query size %d.\n", size);
    hex_print(query_wire, size);
#endif

    dnss_packet *query = malloc(sizeof(dnss_packet));
    //const char *p = query_wire;
    int p = 0;

    printf("Query packet pointer: %p, header pointer: %p.\n",
           query, &query->header);

    // parse header - convert from network byte order
    memcpy(&(query->header), query_wire, sizeof(dnss_header));

#ifdef DNSS_DEBUG
    printf("Header copied.\n");
#endif
    query->header.id = ntohs(query->header.id);
    query->header.flags = ntohs(query->header.flags);
    query->header.qdcount = ntohs(query->header.qdcount);
    query->header.ancount = ntohs(query->header.ancount);
    query->header.nscount = ntohs(query->header.nscount);
    query->header.arcount = ntohs(query->header.arcount);

#ifdef DNSS_DEBUG
    printf("Header parsed: \n");
    printf("ID: %u\n", query->header.id);
    printf("Flags: %u\n", query->header.flags);
    printf("QDCOUNT: %u\n", query->header.qdcount);
    printf("ANCOUNT: %u\n", query->header.ancount);
    printf("NSCOUNT: %u\n", query->header.nscount);
    printf("ARCOUNT: %u\n", query->header.arcount);
#endif

    p += sizeof(dnss_header);

    /*
     * parse questions
     */
    query->questions = malloc(query->header.qdcount * sizeof(dnss_question));

    char *buffer = malloc(MAX_DNAME_SIZE * sizeof(char));
    uint b;

    for (int i = 0; i < query->header.qdcount; ++i) {
        // we do not clear the buffer, hope it's not needed
        b = 0;
        // parse domain name - just copy it (ignoring possible compression!!)
        while (query_wire[p] != '\0' && p < size) {
            assert(b != size && b < MAX_DNAME_SIZE); // instead return FORMERR
            buffer[b++] = query_wire[p++];
        }

#ifdef DNSS_DEBUG
        printf("Domain name parsed: \n");
        hex_print(buffer, b);
#endif

        assert(b < MAX_DNAME_SIZE); // instead return FORMERR
        assert(p + 4 < size);      // instead return FORMERR
        assert(query_wire[p] == '\0');

        buffer[b++] = '\0';
        p++;

        //dnss_question *quest = malloc(sizeof(dnss_question) + b * sizeof(char));

        //quest->qname = (char *)(quest) + sizeof(dnss_question);
        query->questions[i].qname = malloc(b * sizeof(char));
        memcpy(query->questions[i].qname, buffer, b);

#ifdef DNSS_DEBUG
        printf("QNAME: \n");
        hex_print(query->questions[i].qname, b);
       // printf("QTYPE: %u\n", *((uint16_t *)(&(query_wire[p]))));
#endif

        query->questions[i].qtype = ntohs(*((uint16_t *)(&(query_wire[p]))));
#ifdef DNSS_DEBUG
        printf("QTYPE: %u\n", query->questions[i].qtype);
#endif
        p += 2;
        query->questions[i].qclass = ntohs(*((uint16_t *)(&(query_wire[p]))));
#ifdef DNSS_DEBUG
        printf("QCLASS: %u\n",  query->questions[i].qclass);
#endif
        p += 2;
    }

    // TODO: add more checks for the length of the packet

    // ignore rest of the packet    (TODO: should parse additional for OPT)
    query->answers = NULL;
    query->authority = NULL;
    query->additional = NULL;

    return query;
}
