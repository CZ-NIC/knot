#include "dns-simple.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>

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

// default test values
static const uint16_t RRTYPE_DEFAULT       = 1;		// A
static const uint16_t RRCLASS_DEFAULT      = 1;		// IN
static const uint32_t TTL_DEFAULT          = 3600;
static const unsigned int RDLENGTH_DEFAULT = 4;
static const uint8_t RDATA_DEFAULT[4] = { 127, 0, 0, 1 };

// assuming flags is 16bit integer
#define RCODE_SET(flags, rcode) flags = (flags & RCODE_CLEAR) | rcode

/*----------------------------------------------------------------------------*/

void dnss_copy_questions( dnss_question *from, dnss_question *to, uint count )
{
    for (uint i = 0; i < count; ++i) {
        to[i].qclass = from[i].qclass;
        to[i].qtype = from[i].qtype;
        to[i].qname = malloc(strlen(from[i].qname) + 1);
        memcpy(to[i].qname, from[i].qname, strlen(from[i].qname) + 1);
    }
}

/*----------------------------------------------------------------------------*/

void dnss_copy_rrs( dnss_rr *from, dnss_rr *to, uint count )
{
    for (uint i = 0; i < count; ++i) {
        to[i].rdlength = from[i].rdlength;
        to[i].rrclass = from[i].rrclass;
        to[i].rrtype = from[i].rrtype;
        to[i].ttl = from[i].ttl;

        to[i].owner = malloc(strlen(from[i].owner) + 1);
        // replace by check and error
        assert(to[i].owner != NULL);
        memcpy(to[i].owner, from[i].owner, strlen(from[i].owner) + 1);

        to[i].rdata = malloc(from[i].rdlength);
        // replace by check and error
        assert(to[i].rdata != NULL);
        memcpy(to[i].rdata, from[i].rdata, from[i].rdlength);
    }
}

/*----------------------------------------------------------------------------*/

dnss_rr *dnss_create_rr( char *owner )
{
	dnss_rr *rr;

    // assuming owner is in natural format => conversion to wire format needed
#ifdef DNSS_DEBUG
    printf("Converting domain name to wire format.\n");
#endif

    // convert domain name to wire format
    uint wire_size = dnss_wire_dname_size(owner);
    assert(wire_size > 0);
    char *owner_wire = malloc(wire_size);
    if (dnss_dname_to_wire(owner, owner_wire, wire_size) != 0) {
        free(owner_wire);
        return NULL;
    }

#ifdef DNSS_DEBUG
    printf("Creating RR structure.\n");
#endif
    rr = malloc(sizeof(dnss_rr));

    if (rr == NULL) {
        free(owner_wire);
        return NULL;
    }

    // rdata will be saved at the end of the RR
    //rr->rdata = (unsigned char *)rr + sizeof(dnss_rr);
    rr->rdata = malloc(RDLENGTH_DEFAULT);
    memcpy(rr->rdata, RDATA_DEFAULT, RDLENGTH_DEFAULT);

    rr->rrtype = RRTYPE_DEFAULT;
	rr->rrclass = RRCLASS_DEFAULT;
	rr->ttl = TTL_DEFAULT;
    rr->rdlength = RDLENGTH_DEFAULT;

    rr->owner = owner_wire;
#ifdef DNSS_DEBUG
    printf("Created RR: owner: %s, type: %u, rdlength: %u.\n", rr->owner,
           rr->rrtype, rr->rdlength);
    hex_print(rr->owner, strlen(rr->owner));
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
        // this should produce consistent packet structure
    return packet;
}

/*----------------------------------------------------------------------------*/

int dnss_create_response( dnss_packet *query, dnss_rr *answers,
                           uint count, dnss_packet **response )
    /** @todo change last argument to dnss_packet * ?? */
{
	// header
    memcpy(&(*response)->header, &query->header, sizeof(dnss_header));
    HEADER_SET_AA((*response)->header.flags);
    HEADER_SET_QR((*response)->header.flags);
    // copying other flags (maybe set TC, RA, AD, CD)

    (*response)->questions = malloc(
            (*response)->header.qdcount * sizeof(dnss_question));
    if ((*response)->questions == NULL) {
        fprintf(stderr, "dnss_create_response(): Allocation failed.\n");
        return -1;
    }
    dnss_copy_questions(query->questions, (*response)->questions,
                        (*response)->header.qdcount);
    // answers
    (*response)->header.ancount = count;

    (*response)->answers = malloc(
            (*response)->header.ancount * sizeof(dnss_rr));
    dnss_copy_rrs(answers, (*response)->answers, count);
        // distinguish between NODATA (good as it is) and NXDOMAIN (set RCODE)

    (*response)->header.nscount = 0;
    (*response)->authority = NULL;
    (*response)->header.arcount = 0;
    (*response)->additional = NULL;

    return 0;
}

/*----------------------------------------------------------------------------*/

int dnss_create_error_response( dnss_packet *query, dnss_packet **response )
        /** @todo change last argument to dnss_packet * ?? */
{
    // header
    memcpy(&(*response)->header, &query->header, sizeof(dnss_header));
    HEADER_SET_AA((*response)->header.flags);
    HEADER_SET_QR((*response)->header.flags);
    // copying other flags (maybe set TC, RA, AD, CD)

    // set SERVFAIL RCODE
    RCODE_SET((*response)->header.flags, RCODE_SERVFAIL);

    (*response)->questions = malloc(
            (*response)->header.qdcount * sizeof(dnss_question));
    if ((*response)->questions == NULL) {
        fprintf(stderr, "dnss_create_error_response(): Allocation failed.\n");
        return -1;
    }
    dnss_copy_questions(query->questions, (*response)->questions,
                        (*response)->header.qdcount);

    // no answers
    (*response)->header.ancount = 0;
    (*response)->answers = NULL;
    (*response)->header.nscount = 0;
    (*response)->authority = NULL;
    (*response)->header.arcount = 0;
    (*response)->additional = NULL;

    return 0;
}

/*----------------------------------------------------------------------------*/

int dnss_wire_format( dnss_packet *packet, char *packet_wire,
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
        fprintf(stderr, "dnss_wire_format(): Space provided is not enough.");
        return -1;
    }

    *packet_size = real_size;

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
    for (int i = 0; i < packet->header.arcount; ++i) {
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

    return 0;
}

/*----------------------------------------------------------------------------*/

int dnss_dname_to_wire( char *dname, char *dname_wire, uint size ) // TESTING!!
{
    if (dname_wire == NULL) {
        fprintf(stderr, "dnss_dname_to_wire(): Bad buffer pointer provided.");
        return -1;
    }

    // check if there is enough space
    if (dnss_wire_dname_size(dname) > size) {
        fprintf(stderr, "dnss_dname_to_wire(): Given buffer is not big enough.");
        return -1;
    }

#ifdef DNSS_DEBUG
    printf("Domain name to convert: %s.\n", dname);
#endif

    int w = 0;

    char *c = dname;

    char *buffer = malloc(strlen(dname) + 1);
    if (buffer == NULL) {
        fprintf(stderr, "dnss_dname_to_wire(): Allocation failed.");
        return -1;
    }

    uint8_t chars = 0;

    while (*c != '\0') {
        memset(buffer, 0, strlen(dname) + 1);   // maybe not needed
        chars = 0;
        while (*c != '.' && *c != '\0') {   // read next label
            buffer[++chars] = *c++;
        }
        buffer[0] = chars;    // number of characters in this label

//#ifdef DNSS_DEBUG
//        printf("Chars: %d, Buffer: %*s\n", chars, chars + 1, buffer);
//#endif

        memcpy(&dname_wire[w], buffer, chars + 1);   // copy the label
        w += chars + 1;

        if (*c == '.') {
            c++;
        }
    }

    dname_wire[w] = '\0';

#ifdef DNSS_DEBUG
    printf("Wire format of the domain name: %*s\n", w + 1, dname_wire);
    hex_print(dname_wire, w + 1);
#endif

    free(buffer);
    return 0;
}

/*----------------------------------------------------------------------------*/

uint dnss_wire_dname_size( char *dname )
{
    // if there is a trailing dot, size of the wire name will be the same as the
    // size of the normal domain name (for each dot there is a number of chars)
    // otherwise it is +1
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

    dnss_packet *query = dnss_create_empty_packet();
    if (query == NULL) {
        fprintf(stderr, "dnss_parse_query(): Allocation failed.\n");
        return NULL;
    }

    int p = 0;

    memcpy(&(query->header), query_wire, sizeof(dnss_header));

#ifdef DNSS_DEBUG
    printf("Header copied.\n");
#endif

    // parse header - convert from network byte order
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

    char buffer[MAX_DNAME_SIZE];
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

    /** @todo: add more checks for the length of the packet */

    // ignore rest of the packet    (TODO: should parse additional for OPT)
    query->answers = NULL;
    query->authority = NULL;
    query->additional = NULL;

    return query;
}

/*----------------------------------------------------------------------------*/

void dnss_destroy_rr( dnss_rr **rr )
{
    assert(*rr != NULL);
#ifdef DNSS_DEBUG
    printf("Deleting RR: owner: %s, type: %u, rdlength: %u.\n", (*rr)->owner,
           (*rr)->rrtype, (*rr)->rdlength);
    hex_print((*rr)->owner, strlen((*rr)->owner));
#endif
    if ((*rr)->owner != NULL) {
#ifdef DNSS_DEBUG
        printf("Deleting RR's owner on pointer %p\n", (*rr)->owner);
#endif
        free((*rr)->owner);
        (*rr)->owner = NULL;
    }

    if ((*rr)->rdata != NULL) {
#ifdef DNSS_DEBUG
        printf("Deleting RR's rdata on pointer %p\n", (*rr)->rdata);
#endif
        free((*rr)->rdata);
        (*rr)->rdata = NULL;
    }
#ifdef DNSS_DEBUG
    printf("Deleting RR on pointer %p\n", (*rr));
#endif
    free(*rr);
    *rr = NULL;
}

/*----------------------------------------------------------------------------*/

void dnss_destroy_question( dnss_question **question )
{
    assert(*question != NULL);

    if ((*question) != NULL) {
        free((*question)->qname);
        (*question)->qname = NULL;
    }

    free(*question);
    *question = NULL;
}

/*----------------------------------------------------------------------------*/

void dnss_destroy_packet( dnss_packet **packet )
{
    assert(*packet != NULL);

    if ((*packet)->questions != NULL) {
        for (int i = 0; i < (*packet)->header.qdcount; ++i) {
            assert(((*packet)->questions[i].qname != NULL));
            free((*packet)->questions[i].qname);
        }
        free((*packet)->questions);
        (*packet)->questions = NULL;
    }

    if ((*packet)->answers != NULL) {
        for (int i = 0; i < (*packet)->header.ancount; ++i) {
            assert((*packet)->answers[i].owner != NULL);
            assert((*packet)->answers[i].rdata != NULL);
            free((*packet)->answers[i].owner);
            free((*packet)->answers[i].rdata);
        }
        free((*packet)->answers);
        (*packet)->answers = NULL;
    }

    if ((*packet)->answers != NULL) {
        for (int i = 0; i < (*packet)->header.nscount; ++i) {
            assert((*packet)->authority[i].owner != NULL);
            assert((*packet)->authority[i].rdata != NULL);
            free((*packet)->authority[i].owner);
            free((*packet)->authority[i].rdata);
        }
        free((*packet)->authority);
        (*packet)->authority = NULL;
    }

    if ((*packet)->additional != NULL) {
        for (int i = 0; i < (*packet)->header.arcount; ++i) {
            assert((*packet)->additional[i].owner != NULL);
            assert((*packet)->additional[i].rdata != NULL);
            free((*packet)->additional[i].owner);
            free((*packet)->additional[i].rdata);
        }
        free((*packet)->additional);
        (*packet)->additional = NULL;
    }

    free(*packet);
    *packet = NULL;
}
