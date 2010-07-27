#include "dns-simple.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>

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

void dnss_copy_rrs( const dnss_rr *from, dnss_rr *to, uint count )
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

dnss_rr *dnss_create_rr( dnss_dname owner )
{
	dnss_rr *rr;

    // assuming owner is in natural format => conversion to wire format needed
    debug_dnss("Converting domain name to wire format.\n");

    // convert domain name to wire format
    uint wire_size = dnss_wire_dname_size(&owner);
    assert(wire_size > 0);
    dnss_dname_wire owner_wire = malloc(wire_size);
    if (dnss_dname_to_wire(owner, owner_wire, wire_size) != 0) {
        free(owner_wire);
        return NULL;
    }

    debug_dnss("Creating RR structure.\n");

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

    debug_dnss("Created RR: owner: %s, type: %u, rdlength: %u.\n", rr->owner,
               rr->rrtype, rr->rdlength);
    debug_dnss_hex(rr->owner, strlen(rr->owner));
    debug_dnss("Done.\n");

	return rr;
}

/*----------------------------------------------------------------------------*/

dnss_question *dnss_create_question( dnss_dname_wire qname, uint length )
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

int dnss_create_response( const dnss_packet *query, const dnss_rr *answers,
                           uint count, dnss_packet **response )
    /*! @todo change last argument to dnss_packet * ?? */
{
	// header
    memcpy(&(*response)->header, &query->header, sizeof(dnss_header));
    HEADER_SET_AA((*response)->header.flags);
    HEADER_SET_QR((*response)->header.flags);
    // copying other flags (maybe set TC, RA, AD, CD)

    (*response)->questions = malloc(
            (*response)->header.qdcount * sizeof(dnss_question));
    if ((*response)->questions == NULL) {
        ERR_ALLOC_FAILED;
        return -1;
    }
    dnss_copy_questions(query->questions, (*response)->questions,
                        (*response)->header.qdcount);

    // check answer
    if(answers == NULL) {
        count = 0;
    }

    // answers
    (*response)->header.ancount = count;

    (*response)->answers = malloc(count * sizeof(dnss_rr));
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
        /*! @todo change last argument to dnss_packet * ?? */
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
        ERR_ALLOC_FAILED;
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
        log_error("%s: Space provided is not enough.\n", __func__);
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

int dnss_dname_to_wire( dnss_dname dname, dnss_dname_wire dname_wire,
                        uint size ) // TESTING!!
{
    if (dname_wire == NULL) {
        log_error("%s: Bad buffer pointer provided.\n", __func__);
        return -1;
    }

    // check if there is enough space
    if (dnss_wire_dname_size(&dname) > size) {
        log_error("%s: Given buffer is not big enough.\n", __func__);
        return -1;
    }

    debug_dnss("Domain name to convert: %s.\n", dname);

    int w = 0;
    char *c = dname;
    char *buffer = malloc(strlen(dname) + 1);

    if (buffer == NULL) {
        ERR_ALLOC_FAILED;
        return -1;
    }

    while (*c != '\0') {

        // Read label
        uint8_t chars = 0;
        while (*c != '.' && *c != '\0') {
            buffer[++chars] = *c++;
        }
        buffer[0] = chars;    // number of characters in this label

//      dnss_debug("Chars: %d, Buffer: %*s\n", chars, chars + 1, buffer);

        memcpy(&dname_wire[w], buffer, chars + 1);   // copy the label
        w += chars + 1;

        if (*c == '.') {
            c++;
        }
    }

    dname_wire[w] = '\0';

    debug_dnss("Wire format of the domain name: %*s\n", w + 1, dname_wire);
    debug_dnss_hex(dname_wire, w + 1);

    free(buffer);
    return 0;
}

/*----------------------------------------------------------------------------*/

uint dnss_wire_dname_size( const dnss_dname *dname )
{
    // if there is a trailing dot, size of the wire name will be the same as the
    // size of the normal domain name (for each dot there is a number of chars)
    // otherwise it is +1
    return ((*dname)[strlen(*dname) - 1] == '.')
            ? (strlen(*dname) + 1)
            : (strlen(*dname) + 2);
}

/*----------------------------------------------------------------------------*/

dnss_packet *dnss_parse_query( const char *query_wire, uint size )
{
    assert(size > 12);

    debug_dnss("%s called with query size %d.\n", __func__, size);
    debug_dnss_hex(query_wire, size);

    dnss_packet *query = dnss_create_empty_packet();
    if (query == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }

    int p = 0;

    memcpy(&(query->header), query_wire, sizeof(dnss_header));

    debug_dnss("Header copied.\n");

    // parse header - convert from network byte order
    query->header.id = ntohs(query->header.id);
    query->header.flags = ntohs(query->header.flags);
    query->header.qdcount = ntohs(query->header.qdcount);
    query->header.ancount = ntohs(query->header.ancount);
    query->header.nscount = ntohs(query->header.nscount);
    query->header.arcount = ntohs(query->header.arcount);

    debug_dnss("Header parsed: \n");
    debug_dnss("ID: %u\n", query->header.id);
    debug_dnss("Flags: %u\n", query->header.flags);
    debug_dnss("QDCOUNT: %u\n", query->header.qdcount);
    debug_dnss("ANCOUNT: %u\n", query->header.ancount);
    debug_dnss("NSCOUNT: %u\n", query->header.nscount);
    debug_dnss("ARCOUNT: %u\n", query->header.arcount);

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

        debug_dnss("Domain name parsed: \n");
        debug_dnss_hex(buffer, b);

        assert(b < MAX_DNAME_SIZE); // instead return FORMERR
        assert(p + 4 < size);      // instead return FORMERR
        assert(query_wire[p] == '\0');

        buffer[b++] = '\0';
        p++;

        query->questions[i].qname = malloc(b * sizeof(char));
        memcpy(query->questions[i].qname, buffer, b);

        debug_dnss("QNAME: \n");
        debug_dnss_hex(query->questions[i].qname, b);

        query->questions[i].qtype = ntohs(*((uint16_t *)(&(query_wire[p]))));
        debug_dnss("QTYPE: %u\n", query->questions[i].qtype);

        p += 2;
        query->questions[i].qclass = ntohs(*((uint16_t *)(&(query_wire[p]))));
        debug_dnss("QCLASS: %u\n",  query->questions[i].qclass);

        p += 2;
    }

	/*! @todo add more checks for the length of the packet */

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
    debug_dnss("Deleting RR: owner: %s, type: %u, rdlength: %u.\n", (*rr)->owner,
           (*rr)->rrtype, (*rr)->rdlength);
    debug_dnss_hex((*rr)->owner, strlen((*rr)->owner));

    if ((*rr)->owner != NULL) {
        debug_dnss("Deleting RR's owner on pointer %p\n", (*rr)->owner);
        free((*rr)->owner);
        (*rr)->owner = NULL;
    }

    if ((*rr)->rdata != NULL) {
        debug_dnss("Deleting RR's rdata on pointer %p\n", (*rr)->rdata);
        free((*rr)->rdata);
        (*rr)->rdata = NULL;
    }

    debug_dnss("Deleting RR on pointer %p\n", (*rr));
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

/*----------------------------------------------------------------------------*/

char *dnss_dname_wire_to_string( dnss_dname_wire dname_wire )
{
    return dname_wire;
}

/*----------------------------------------------------------------------------*/

size_t dnss_dname_wire_length( dnss_dname_wire dname_wire )
{
    return strlen(dname_wire) + 1;
}

/*----------------------------------------------------------------------------*/

void dnss_dname_wire_cp( dnss_dname_wire from, dnss_dname_wire to )
{
    memcpy(to, from, (strlen(from) + 1));
}

/*----------------------------------------------------------------------------*/

dnss_dname_wire dnss_dname_wire_copy( dnss_dname_wire from )
{
    dnss_dname_wire dw = malloc((strlen(from) + 1) * sizeof(char));

    if (dw == NULL) {
        return NULL;
    }

    dnss_dname_wire_cp(from, dw);
    return dw;
}

/*----------------------------------------------------------------------------*/

int dnss_dname_wire_cmp( dnss_dname_wire dname1, dnss_dname_wire dname2 )
{
    int l1 = dnss_dname_wire_length(dname1);
    int l2 = dnss_dname_wire_length(dname1);

    int res = memcmp(dname1, dname2, (l1 < l2) ? l1 : l2);

    return (res == 0)
            ? ((l1 > l2) ? 1 : ((l1 < l2) ? -1 : 0))
            : res;
}

/*----------------------------------------------------------------------------*/

void dnss_dname_wire_destroy( dnss_dname_wire *dname )
{
    free(*dname);
    *dname = NULL;
}

/*----------------------------------------------------------------------------*/

uint dnss_dname_wire_match( const dnss_dname_wire *dname1,
                            const dnss_dname_wire *dname2 )
{

    int i1 = strlen(*dname1) - 1;  // not counting the last 0
    int i2 = strlen(*dname2) - 1;  // dtto
    uint matched = 0;

    while (i1 >= 0 && i2 >= 0 && ((*dname1)[i1] == (*dname2)[i2])) {
        --i1;
        --i2;
        ++matched;
    }

    return matched;
}
