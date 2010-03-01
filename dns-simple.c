#include "dns-simple.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

//#define DNSS_DEBUG

#define HEADER_SET_QR(flags) (flags |= (1 << 15))
#define HEADER_SET_AA(flags) (flags |= (1 << 10))

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

#ifdef DNSS_DEBUG
    printf("Creating RR structure.\n");
#endif
    rr = malloc(sizeof(dnss_rr) + RDLENGTH_DEFAULT/* + strlen(owner_wire) + 1*/);

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

dnss_packet *dnss_create_response( dnss_packet *query, dnss_rr *answers,
								   uint count )
{
	dnss_packet *packet = malloc(sizeof(dnss_packet));

	// header
    memcpy(&packet->header, &query->header, sizeof(dnss_header));
    HEADER_SET_AA(packet->header.flags);
    HEADER_SET_QR(packet->header.flags);

	// questions; assuming that the domain names will not be deleted
    // (maybe some copying function would be useful?)
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

void dnss_wire_format( dnss_packet *packet, char *packet_wire,
                                 unsigned int packet_size  )
{
    /* We can assume that the domain names are kept in the wire format during
     * copying among the application. Thus no conversion needed here.
     * All integers must be converted to the network byte order.
     */

    // determine the size of the packet
    packet_size = HEADER_SIZE;
    for (int i = 0; i < packet->header.qdcount; ++i) {
        packet_size += strlen(packet->questions[i].qname) + 5;
    }
    for (int i = 0; i < packet->header.ancount; ++i) {
        packet_size += strlen(packet->answers[i].owner)
                       + 11 + packet->answers[i].rdlength;
    }
    for (int i = 0; i < packet->header.nscount; ++i) {
        packet_size += strlen(packet->authority[i].owner)
                       + 11 + packet->authority[i].rdlength;
    }
    for (int i = 0; i < packet->header.arcount; ++i) {
        packet_size += strlen(packet->additional[i].owner)
                       + 11 + packet->additional[i].rdlength;
    }

    packet_wire = malloc(packet_size);

    if (packet_wire == NULL) {
        fprintf(stderr, "Allocation failed in dnss_wire_format().\n");
        return;
    }

    char *p = packet_wire;
    memcpy(p, &packet->header, sizeof(dnss_header));
    p += sizeof(dnss_header);

    for (int i = 0; i < packet->header.qdcount; ++i) {
        memcpy(p, packet->questions[i].qname,
               strlen(packet->questions[i].qname) + 1); // copy domain name
        p += strlen(packet->questions[i].qname) + 1;
        *p = htons(packet->questions[i].qtype);
        p += 2;
        *p = htons(packet->questions[i].qclass);
        p += 2;
    }
    for (int i = 0; i < packet->header.ancount; ++i) {
        memcpy(p, packet->answers[i].owner,
               strlen(packet->answers[i].owner) + 1);   // copy owner name
        p += strlen(packet->answers[i].owner) + 1;
        *p = htons(packet->answers[i].rrtype);
        p += 2;
        *p = htons(packet->answers[i].rrclass);
        p += 2;
        *p = htonl(packet->answers[i].ttl);
        p += 4;
        *p = htons(packet->answers[i].rdlength);
        p += 2;
        memcpy(p, packet->answers[i].rdata,
               packet->answers[i].rdlength);        // copy rdata
        p += packet->answers[i].rdlength;
    }
    for (int i = 0; i < packet->header.nscount; ++i) {
        memcpy(p, packet->authority[i].owner,
               strlen(packet->authority[i].owner) + 1);   // copy owner name
        p += strlen(packet->authority[i].owner) + 1;
        *p = htons(packet->authority[i].rrtype);
        p += 2;
        *p = htons(packet->authority[i].rrclass);
        p += 2;
        *p = htonl(packet->authority[i].ttl);
        p += 4;
        *p = htons(packet->authority[i].rdlength);
        p += 2;
        memcpy(p, packet->authority[i].rdata,
               packet->authority[i].rdlength);        // copy rdata
        p += packet->authority[i].rdlength;
    }
    for (int i = 0; i < packet->header.ancount; ++i) {
        memcpy(p, packet->additional[i].owner,
               strlen(packet->additional[i].owner) + 1);   // copy owner name
        p += strlen(packet->additional[i].owner) + 1;
        *p = htons(packet->additional[i].rrtype);
        p += 2;
        *p = htons(packet->additional[i].rrclass);
        p += 2;
        *p = htonl(packet->additional[i].ttl);
        p += 4;
        *p = htons(packet->additional[i].rdlength);
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
    //char *w = wire_name;
    int w = 0;

    char *c = dname;

    char *buffer = malloc(strlen(dname) + 1);
    //char *b = buffer;
    uint8_t chars = 0;

    while (*c != '\0') {
        memset(buffer, 0, strlen(dname) + 1);   // maybe not needed
        //b = buffer + 1;
        chars = 0;
        while (*c != '.' && *c != '\0') {   // read next label
            //*b++ = *c++;
            buffer[++chars] = *c++;
            //chars++;
        }
        buffer[0] = chars;    // number of characters in this label

#ifdef DNSS_DEBUG
        printf("Chars: %d, Buffer: %*s\n", chars, chars + 1, buffer);
#endif

//        if(!(*c == '\0' &&
//                (w + chars + 1 == ((dname[strlen(dname) - 1] == '.')
//                                    ? (strlen(dname) + 1)
//                                    : (strlen(dname) + 2))))) {
//            if (*c == '\0') {
//                fprintf(stderr, "Wire name will be %d long and it should be"
//                        "max %d chars long.\n", w + chars + 1,
//                        ((dname[strlen(dname) - 1] == '.')
//                        ? (strlen(dname) + 1)
//                        : (strlen(dname) + 2)));
//                assert(0);
//            } else if ((w + chars + 1 >= ((dname[strlen(dname) - 1] == '.')
//                                            ? (strlen(dname) + 1)
//                                            : (strlen(dname) + 2)))) {
//                fprintf(stderr, "Wire name will be more than %d long and it "
//                        "should be max %d chars long.\n", w + chars + 1,
//                        ((dname[strlen(dname) - 1] == '.')
//                        ? (strlen(dname) + 1)
//                        : (strlen(dname) + 2)));
//                assert(0);
//            }
//        }

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

dnss_packet *dnss_parse_query( const char *query_wire, int size )
{
    dnss_packet *query = malloc(sizeof(dnss_packet));
    //const char *p = query_wire;
    int p = 0;

    // parse header - convert from network byte order
    memcpy(&query->header, query_wire, sizeof(dnss_header));
    query->header.id = ntohs(query->header.id);
    query->header.flags = ntohs(query->header.id);
    query->header.qdcount = ntohs(query->header.qdcount);
    query->header.ancount = ntohs(query->header.ancount);
    query->header.nscount = ntohs(query->header.nscount);
    query->header.arcount = ntohs(query->header.arcount);

    p += sizeof(dnss_header);

    /*
     * parse questions
     */
    char *buffer = malloc(MAX_DNAME_SIZE * sizeof(char));
    uint b;

    for (int i = 0; i < query->header.qdcount; ++i) {
        // we do not clear the buffer, hope it's not needed
        b = 0;
        // parse domain name - just copy it (ignoring possible compression!!)
        while (query_wire[p] != '\0') {
            assert(b != size && b < MAX_DNAME_SIZE); // instead return FORMERR
            buffer[b++] = query_wire[p++];
        }
        assert(b < MAX_DNAME_SIZE); // instead return FORMERR
        assert(p + 4 < size);      // instead return FORMERR
        assert(query_wire[p] == '\0');

        buffer[b++] = '\0';
        p++;

        dnss_question *quest = malloc(sizeof(dnss_question) + b * sizeof(char));

        quest->qname = (char *)(quest + sizeof(dnss_question));
        memcpy(quest->qname, buffer, b);

        quest->qtype = ntohs(*((uint16_t *)&query_wire[p]));
        p += 2;
        quest->qclass = ntohs(*((uint16_t *)&query_wire[p]));
        p += 2;
    }

    // ignore rest of the packet    (TODO: should parse additional for OPT)
    query->answers = NULL;
    query->authority = NULL;
    query->additional = NULL;

    return query;
}
