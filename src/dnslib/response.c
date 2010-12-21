#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "response.h"
#include "rrset.h"
#include "common.h"
#include "packet.h"
#include "descriptor.h"

enum {
	DEFAULT_ANCOUNT = 6,
	DEFAULT_NSCOUNT = 8,
	DEFAULT_ARCOUNT = 28,
	DEFAULT_DOMAINS_IN_RESPONSE = 22,
	DEFAULT_TMP_DOMAINS = 5,
	STEP_ANCOUNT = 6,
	STEP_NSCOUNT = 8,
	STEP_ARCOUNT = 8,
	STEP_DOMAINS = 10,
	STEP_TMP_DOMAINS = 5
};

enum {
	PREALLOC_RESPONSE = sizeof(dnslib_response_t),
	PREALLOC_QNAME = 256,

	PREALLOC_ANSWER = DEFAULT_ANCOUNT * sizeof(dnslib_dname_t *),
	PREALLOC_AUTHORITY = DEFAULT_NSCOUNT * sizeof(dnslib_dname_t *),
	PREALLOC_ADDITIONAL = DEFAULT_ARCOUNT * sizeof(dnslib_dname_t *),

	PREALLOC_RRSETS = PREALLOC_ANSWER
	                  + PREALLOC_AUTHORITY
	                  + PREALLOC_ADDITIONAL,
	PREALLOC_DOMAINS =
		DEFAULT_DOMAINS_IN_RESPONSE * sizeof(dnslib_dname_t *),
	PREALLOC_OFFSETS =
		DEFAULT_DOMAINS_IN_RESPONSE * sizeof(short),
	PREALLOC_TMP_DOMAINS =
		DEFAULT_TMP_DOMAINS * sizeof(dnslib_dname_t *),

	PREALLOC_TOTAL = PREALLOC_RESPONSE
	                 + PREALLOC_QNAME
	                 + PREALLOC_RRSETS
	                 + PREALLOC_DOMAINS
	                 + PREALLOC_OFFSETS
	                 + PREALLOC_TMP_DOMAINS,

	PREALLOC_RESPONSE_WIRE = 65535,
	PREALLOC_RRSET_WIRE = 65535
};

static const uint16_t EDNS_NOT_SUPPORTED = 65535;
static const short QUESTION_OFFSET = DNSLIB_PACKET_HEADER_SIZE;

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static void dnslib_response_parse_host_edns(dnslib_response_t *resp,
                                     const uint8_t *edns_wire, short edns_size)
{
	resp->max_size = DNSLIB_MAX_RESPONSE_SIZE;
	// TODO parse
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_init_pointers(dnslib_response_t *resp)
{
	debug_dnslib_response("Response pointer: %p\n", resp);
	// put QNAME directly after the structure
	resp->question.qname =
		(dnslib_dname_t *)((char *)resp + PREALLOC_RESPONSE);

	debug_dnslib_response("QNAME: %p (%d after start of response)\n",
		resp->question.qname,
		(void *)resp->question.qname - (void *)resp);

	// then answer, authority and additional sections
	resp->answer = (const dnslib_rrset_t **)
	                   ((char *)resp->question.qname + PREALLOC_QNAME);
	resp->authority = resp->answer + DEFAULT_ANCOUNT;
	resp->additional = resp->authority + DEFAULT_NSCOUNT;

	debug_dnslib_response("Answer section: %p (%d after QNAME)\n",
		resp->answer,
		(void *)resp->answer - (void *)resp->question.qname);
	debug_dnslib_response("Authority section: %p (%d after Answer)\n",
		resp->authority,
		(void *)resp->authority - (void *)resp->answer);
	debug_dnslib_response("Additional section: %p (%d after Authority)\n",
		resp->additional,
		(void *)resp->additional - (void *)resp->authority);

	resp->max_ancount = DEFAULT_ANCOUNT;
	resp->max_nscount = DEFAULT_NSCOUNT;
	resp->max_arcount = DEFAULT_ARCOUNT;

	// then domain names for compression and offsets
	resp->compression.dnames = (dnslib_dname_t **)
	                               (resp->additional + DEFAULT_ARCOUNT);
	resp->compression.offsets = (short *)
		(resp->compression.dnames + DEFAULT_DOMAINS_IN_RESPONSE);

	debug_dnslib_response("Compression dnames: %p (%d after Additional)\n",
		resp->compression.dnames,
		(void *)resp->compression.dnames - (void *)resp->additional);
	debug_dnslib_response("Compression offsets: %p (%d after c. dnames)\n",
		resp->compression.offsets,
		(void *)resp->compression.offsets
		  - (void *)resp->compression.dnames);

	resp->compression.max = DEFAULT_DOMAINS_IN_RESPONSE;

	resp->tmp_dnames = (dnslib_dname_t **)
		(resp->compression.offsets + DEFAULT_DOMAINS_IN_RESPONSE);

	debug_dnslib_response("Tmp dnames: %p (%d after compression offsets)\n",
		resp->tmp_dnames,
		(void *)resp->tmp_dnames - (void *)resp->compression.offsets);

	resp->tmp_dname_max = DEFAULT_TMP_DOMAINS;

	debug_dnslib_response("End of data: %p (%d after start of response)\n",
		resp->tmp_dnames + DEFAULT_TMP_DOMAINS,
		(void *)(resp->tmp_dnames + DEFAULT_TMP_DOMAINS)
		  - (void *)resp);
	debug_dnslib_response("Allocated total: %u\n", PREALLOC_TOTAL);

	assert((char *)(resp->tmp_dnames + DEFAULT_TMP_DOMAINS)
	       == (char *)resp + PREALLOC_TOTAL);
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_init(dnslib_response_t *resp,
                                 const uint8_t *edns_wire, short edns_size)
{
	memset(resp, 0, PREALLOC_TOTAL);

	resp->edns_wire = edns_wire;
	resp->edns_size = edns_size;

	if (edns_wire != NULL && edns_size > 0) {
		// parse given EDNS record and save max size
		dnslib_response_parse_host_edns(resp, edns_wire, edns_size);
	} else {
		// set default max size of the response
		resp->max_size = DNSLIB_MAX_RESPONSE_SIZE;
	}

	// actual size is always at least the header size + EDNS wire size
	resp->size = DNSLIB_PACKET_HEADER_SIZE + resp->edns_size;

	// save default pointers to the space after the structure
	dnslib_response_init_pointers(resp);
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_parse_header(const uint8_t **pos, size_t *remaining,
                                        dnslib_header_t *header)
{
	if (pos == NULL || *pos == NULL || remaining == NULL
	    || header == NULL) {
		debug_dnslib_response("Missing inputs to header parsing.\n");
		return -1;
	}

	if (*remaining < DNSLIB_PACKET_HEADER_SIZE) {
		debug_dnslib_response("Not enough data to parse header.\n");
		return -2;
	}

	header->id = dnslib_packet_get_id(*pos);
	header->flags1 = dnslib_packet_get_flags1(*pos);
	header->flags2 = dnslib_packet_get_flags2(*pos);
	header->qdcount = dnslib_packet_get_qdcount(*pos);
	header->ancount = dnslib_packet_get_ancount(*pos);
	header->nscount = dnslib_packet_get_nscount(*pos);
	header->arcount = dnslib_packet_get_arcount(*pos);

	*pos += DNSLIB_PACKET_HEADER_SIZE;
	*remaining -= DNSLIB_PACKET_HEADER_SIZE;

	return 0;
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_header_to_wire(const dnslib_header_t *header,
                                           uint8_t **pos, short *size)
{
	dnslib_packet_set_id(*pos, header->id);
	dnslib_packet_set_flags1(*pos, header->flags1);
	dnslib_packet_set_flags2(*pos, header->flags2);
	dnslib_packet_set_qdcount(*pos, header->qdcount);
	dnslib_packet_set_ancount(*pos, header->ancount);
	dnslib_packet_set_nscount(*pos, header->nscount);
	dnslib_packet_set_arcount(*pos, header->arcount);

	*pos += DNSLIB_PACKET_HEADER_SIZE;
	*size += DNSLIB_PACKET_HEADER_SIZE;
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_parse_question(const uint8_t **pos,
                                          size_t *remaining,
                                          dnslib_question_t *question)
{
	if (pos == NULL || *pos == NULL || remaining == NULL
	    || question == NULL) {
		debug_dnslib_response("Missing inputs to question parsing\n");
		return -1;
	}

	if (*remaining < DNSLIB_PACKET_QUESTION_MIN_SIZE) {
		debug_dnslib_response("Not enough data to parse question.\n");
		return -2;  // malformed
	}

	// domain name must end with 0, so just search for 0
	int i = 0;
	while (i < *remaining && (*pos)[i] != 0) {
		++i;
	}

	if (i == *remaining || *remaining - i - 1 < 4) {
		debug_dnslib_response("Not enough data to parse question.\n");
		return -2;  // no 0 found or not enough data left
	}

	question->qname = dnslib_dname_new_from_wire(*pos, i + 1, NULL);
	*pos += i + 1;
	question->qtype = dnslib_packet_read_u16(*pos);
	*pos += 2;
	question->qclass = dnslib_packet_read_u16(*pos);
	*pos += 2;

	*remaining -= (i + 5);

	return 0;
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_question_to_wire(dnslib_question_t *question,
                                            uint8_t **pos, short *size,
                                            short max_size)
{
	if (*size + question->qname->size + sizeof(question->qclass)
	    + sizeof(question->qtype) > max_size) {
		// not enough space in the packet (there should be enough!!)
		return 1;
	}

	memcpy(*pos, question->qname->name, question->qname->size);
	*size += question->qname->size;
	*pos += question->qname->size;

	dnslib_packet_write_u16(*pos, question->qtype);
	*pos += 2;
	dnslib_packet_write_u16(*pos, question->qclass);
	*pos += 2;
	*size += 4;

	return 0;
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_parse_client_edns(const uint8_t **pos,
                                             size_t *remaining,
                                             dnslib_edns_data_t *edns)
{
	if (pos == NULL || *pos == NULL || remaining == NULL
	    || edns == NULL) {
		return -1;
	}

	if (*remaining < DNSLIB_PACKET_RR_MIN_SIZE) {
		debug_dnslib_response("Not enough data to parse ENDS.\n");
		return -2;
	}

	// owner of EDNS OPT RR must be root (0)
	if (**pos != 0) {
		debug_dnslib_response("EDNS packet malformed (expected root "
		                      "domain as owner).\n");
		return -3;
	}
	*pos += 1;

	// check the type of the record (must be OPT)
	if (dnslib_packet_read_u16(*pos) != DNSLIB_RRTYPE_OPT) {
		debug_dnslib_response("EDNS packet malformed (expected OPT type"
		                      ".\n");
		return -2;
	}
	*pos += 2;

	edns->payload = dnslib_packet_read_u16(*pos);
	*pos += 2;
	edns->ext_rcode = *(*pos)++;
	edns->version = *(*pos)++;
	// skip Z
	*pos += 2;

	// ignore RDATA, but move pos behind them
	uint16_t rdlength = dnslib_packet_read_u16(*pos);
	*remaining -= 11;

	if (*remaining < rdlength) {
		debug_dnslib_response("Not enough data to parse ENDS.\n");
		return -3;
	}

	*pos += 2 + rdlength;
	*remaining -= rdlength;

	return 0;
}

/*---------------------------------------------------------------------------*/

static void dnslib_response_compress_dname(const dnslib_dname_t *dname,
	const dnslib_compressed_dnames_t *compr, uint8_t *dname_wire,
	short *dname_size)
{
	/*!
	 * \todo Compress!!
	 */
	// now just copy the dname without compressing
	memcpy(dname_wire, dname->name, dname->size);
	*dname_size = dname->size;
}

/*---------------------------------------------------------------------------*/

static void dnslib_response_rr_to_wire(const uint8_t *owner_wire,
                                       short owner_size,
                                       const dnslib_rrset_t *rrset,
                                       const dnslib_rdata_t *rdata,
                                       dnslib_compressed_dnames_t *compr,
                                       uint8_t **rrset_wire,
                                       short *rrset_size)
{
	// put owner (already compressed)
	memcpy(*rrset_wire, owner_wire, owner_size);
	*rrset_wire += owner_size;
	*rrset_size += owner_size;

	// put rest of RR 'header'
	dnslib_packet_write_u16(*rrset_wire, rrset->type);
	*rrset_wire += 2;

	dnslib_packet_write_u16(*rrset_wire, rrset->rclass);
	*rrset_wire += 2;

	dnslib_packet_write_u32(*rrset_wire, rrset->ttl);
	*rrset_wire += 4;

	// save space for RDLENGTH
	uint8_t *rdlength_pos = *rrset_wire;
	*rrset_wire += 2;

	*rrset_size += 10;

	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(rrset->type);

	uint16_t rdlength = 0;

	for (int i = 0; i < rdata->count; ++i) {
		switch (desc->wireformat[i]) {
		case DNSLIB_RDATA_WF_COMPRESSED_DNAME: {
			short size;
			dnslib_response_compress_dname(
				dnslib_rdata_get_item(rdata, i)->dname,
				compr, *rrset_wire, &size);
			*rrset_wire += size;
			rdlength += size;
			// TODO: compress domain name
			break;
		}
		case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_LITERAL_DNAME: {
			// save whole domain name
			dnslib_dname_t *dname =
				dnslib_rdata_get_item(rdata, i)->dname;
			memcpy(*rrset_wire, dname->name, dname->size);
			*rrset_wire += dname->size;
			rdlength += dname->size;
			break;
		}
		case DNSLIB_RDATA_WF_BINARYWITHLENGTH: {
			// copy also the rdata item size
			uint8_t *raw_data =
				dnslib_rdata_get_item(rdata, i)->raw_data;
			memcpy(*rrset_wire, raw_data, raw_data[0] + 1);
			*rrset_wire += raw_data[0] + 1;
			rdlength += raw_data[0] + 1;
			break;
		}
		default: {
			// copy just the rdata item data (without size)
			uint8_t *raw_data =
				dnslib_rdata_get_item(rdata, i)->raw_data;
			memcpy(*rrset_wire, raw_data + 1, raw_data[0]);
			*rrset_wire += raw_data[0];
			rdlength += raw_data[0];
			break;
		}
		}
	}

	*rrset_size += rdlength;
	dnslib_packet_write_u16(rdlength_pos, rdlength);
}

/*---------------------------------------------------------------------------*/

static int dnslib_response_rrset_to_wire(const dnslib_rrset_t *rrset,
                                         uint8_t **pos, short *size,
                                         short max_size,
                                         dnslib_compressed_dnames_t *compr)
{
	// if no RDATA in RRSet, return
	if (rrset->rdata == NULL) {
		return 0;
	}

	/*!
	 * \todo Do not use two variables: rrset_wire and rrset_size, just one!
	 */

	uint8_t *rrset_wire = (uint8_t *)malloc(PREALLOC_RRSET_WIRE);
	short rrset_size = 0;

	uint8_t *owner_wire = (uint8_t *)malloc(rrset->owner->size);
	short owner_size = 0;

	dnslib_response_compress_dname(rrset->owner, compr, owner_wire,
	                               &owner_size);

	const dnslib_rdata_t *rdata = rrset->rdata;
	do {
		dnslib_response_rr_to_wire(owner_wire, owner_size, rrset,
		                           rdata, compr, &rrset_wire,
		                           &rrset_size);
	} while (rrset_size < max_size
		 && (rdata = dnslib_rrset_rdata_next(rrset, rdata)) != NULL);

	if (rrset_size >= max_size) {
		return 1;
	}

	memcpy(*pos, rrset_wire, rrset_size);
	*size += rrset_size;
	*pos += rrset_size;

	return 0;
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_rrsets_to_wire(const dnslib_rrset_t **rrsets,
                                          short count, uint8_t **pos,
                                          short *size, short max_size,
                                          dnslib_compressed_dnames_t *compr)
{
	// no compression for now
	int i = 0;
	int tc = 0;

	while (i < count && !tc) {
		tc = dnslib_response_rrset_to_wire(rrsets[i], pos, size,
		                                   max_size, compr);
	}

	return tc;
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_free_tmp_domains(dnslib_response_t *resp)
{
	for (int i = 0; i < resp->tmp_dname_count; ++i) {
		dnslib_dname_free(&resp->tmp_dnames[i]);
	}
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_free_allocated_space(dnslib_response_t *resp)
{
	if (resp->max_ancount > DEFAULT_ANCOUNT) {
		free(resp->answer);
	}
	if (resp->max_nscount > DEFAULT_NSCOUNT) {
		free(resp->authority);
	}
	if (resp->max_arcount > DEFAULT_ARCOUNT) {
		free(resp->additional);
	}

	if (resp->compression.max > DEFAULT_DOMAINS_IN_RESPONSE) {
		free(resp->compression.dnames);
		free(resp->compression.offsets);
	}

	if (resp->tmp_dname_max > DEFAULT_TMP_DOMAINS) {
		free(resp->tmp_dnames);
	}
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_dump(const dnslib_response_t *resp)
{
	debug_dnslib_response("DNS response:\n-----------------------------\n");

	debug_dnslib_response("\nHeader:\n");
	debug_dnslib_response("  ID: %u", resp->header.id);
	debug_dnslib_response("  FLAGS: %s %s %s %s %s %s %s\n",
	       dnslib_packet_flags_get_qr(resp->header.flags1) ? "qr" : "",
	       dnslib_packet_flags_get_aa(resp->header.flags1) ? "aa" : "",
	       dnslib_packet_flags_get_tc(resp->header.flags1) ? "tc" : "",
	       dnslib_packet_flags_get_rd(resp->header.flags1) ? "rd" : "",
	       dnslib_packet_flags_get_ra(resp->header.flags2) ? "ra" : "",
	       dnslib_packet_flags_get_ad(resp->header.flags2) ? "ad" : "",
	       dnslib_packet_flags_get_cd(resp->header.flags2) ? "cd" : "");
	debug_dnslib_response("  QDCOUNT: %u\n", resp->header.qdcount);
	debug_dnslib_response("  ANCOUNT: %u\n", resp->header.ancount);
	debug_dnslib_response("  NSCOUNT: %u\n", resp->header.nscount);
	debug_dnslib_response("  ARCOUNT: %u\n", resp->header.arcount);

	debug_dnslib_response("\nQuestion:\n");
	char *qname = dnslib_dname_to_str(resp->question.qname);
	debug_dnslib_response("  QNAME: %s\n", qname);
	free(qname);
	debug_dnslib_response("  QTYPE: %u (%s)\n", resp->question.qtype,
	       dnslib_rrtype_to_string(resp->question.qtype));
	debug_dnslib_response("  QCLASS: %u (%s)\n", resp->question.qclass,
	       dnslib_rrclass_to_string(resp->question.qclass));

	/*! \todo Dumping of Answer, Authority and Additional sections. */

	debug_dnslib_response("\nEDNS - client:\n");
	debug_dnslib_response("  Version: %u\n", resp->edns_query.version);
	debug_dnslib_response("  Payload: %u\n", resp->edns_query.payload);
	debug_dnslib_response("  Extended RCODE: %u\n",
	                      resp->edns_query.ext_rcode);

	debug_dnslib_response("\nResponse size: %d\n", resp->size);
	debug_dnslib_response("\n-----------------------------\n");
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_realloc_rrsets(const dnslib_rrset_t ***rrsets,
                                          short *max_count,
                                          short default_max_count, short step )
{
	int free_old = (*max_count) != default_max_count;
	const dnslib_rrset_t **old = *rrsets;

	short new_max_count = *max_count + step;
	const dnslib_rrset_t **new_rrsets = (const dnslib_rrset_t **)malloc(
		new_max_count * sizeof(dnslib_rrset_t *));
	CHECK_ALLOC_LOG(new_rrsets, -1);

	memcpy(new_rrsets, *rrsets, (*max_count) * sizeof(dnslib_rrset_t *));

	*rrsets = new_rrsets;
	*max_count = new_max_count;

	if (free_old) {
		free(old);
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

short dnslib_response_rrset_size(const dnslib_rrset_t *rrset,
                                 const dnslib_compressed_dnames_t *compr)
{
	// TODO: count in possible compression
	short size = 10;              // 2 type, 2 class, 4 ttl, 2 rdlength
	size += rrset->owner->size;   // owner

	dnslib_rrtype_descriptor_t *desc =
			dnslib_rrtype_descriptor_by_type(rrset->type);

	const dnslib_rdata_t *rdata = dnslib_rrset_rdata(rrset);
	while (rdata != NULL) {
		for (int i = 0; i < rdata->count; ++i) {
			switch (desc->wireformat[i]) {
			case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
			case DNSLIB_RDATA_WF_LITERAL_DNAME:
			case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
				size += rdata->items[i].dname->size;
				break;
			case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
				size += rdata->items[i].raw_data[0] + 1;
				break;
			default:
				size += rdata->items[i].raw_data[0];
				break;
			}
		}

		rdata = dnslib_rrset_rdata_next(rrset, rdata);
	}

	return size;
}

/*----------------------------------------------------------------------------*/

void dnslib_response_try_add_rrset(const dnslib_rrset_t **rrsets,
                                   uint16_t *rrset_count,
                                   dnslib_response_t *resp,
                                   const dnslib_rrset_t *rrset, int tc)
{
	short size = dnslib_response_rrset_size(rrset, &resp->compression);
	if (resp->size + size > resp->max_size) {
		if (tc) {
			dnslib_packet_flags_set_tc(&resp->header.flags1);
		}
	} else {
		rrsets[(*rrset_count)++] = rrset;
		resp->size += size;
	}
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_response_t *dnslib_response_new_empty(const uint8_t *edns_wire,
                                             short edns_size)
{
	dnslib_response_t *resp = (dnslib_response_t *)malloc(PREALLOC_TOTAL);
	CHECK_ALLOC_LOG(resp, NULL);

	dnslib_response_init(resp, edns_wire, edns_size);

	return resp;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_parse_query(dnslib_response_t *resp,
                                 const uint8_t *query_wire, size_t query_size)
{
	int err = 0;

	const uint8_t *pos = query_wire;
	size_t remaining = query_size;

	if ((err = dnslib_response_parse_header(
	               &pos, &remaining, &resp->header))) {
		return err;
	}

	if ((err = dnslib_response_parse_question(
	               &pos, &remaining, &resp->question))) {
		return err;
	}
	resp->size += resp->question.qname->size + 4;

	if (resp->header.arcount > 0) {  // expecting EDNS OPT RR
		if ((err = dnslib_response_parse_client_edns(
			       &pos, &remaining, &resp->edns_query))) {
			return err;
		}
		if (resp->edns_query.payload
		    && resp->edns_query.payload < resp->max_size) {
			resp->max_size = resp->edns_query.payload;
		}
	} else {
		// set client EDNS version to EDNS_NOT_SUPPORTED
		resp->edns_query.version = EDNS_NOT_SUPPORTED;
	}

	// set ANCOUNT, NSCOUNT and ARCOUNT to 0 (response)
	// parsing of ANCOUNT and NSCOUNT is unnecessary then
	resp->header.ancount = 0;
	resp->header.nscount = 0;
	resp->header.arcount = 0;

	// TODO: should we also set the flags, or leave it to the application?

	if (remaining > 0) {
		// some trailing garbage; ignore, but log
		log_info("%d bytes of trailing garbage in query.\n", remaining);
	}

	dnslib_response_dump(resp);

	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_rrset_answer(dnslib_response_t *response,
                                     const dnslib_rrset_t *rrset, int tc)
{
	if (response->header.ancount == response->max_ancount
	    && dnslib_response_realloc_rrsets(&response->answer,
			&response->max_ancount, DEFAULT_ANCOUNT, STEP_ANCOUNT)
		!= 0) {
		return -1;
	}

	dnslib_response_try_add_rrset(response->answer,
	                              &response->header.ancount, response,
	                              rrset, tc);

	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_rrset_authority(dnslib_response_t *response,
                                        const dnslib_rrset_t *rrset, int tc)
{
	if (response->header.nscount == response->max_nscount
	    && dnslib_response_realloc_rrsets(&response->authority,
			&response->max_nscount, DEFAULT_NSCOUNT, STEP_NSCOUNT)
		!= 0) {
		return -1;
	}


	dnslib_response_try_add_rrset(response->authority,
	                              &response->header.nscount, response,
	                              rrset, tc);

	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_rrset_aditional(dnslib_response_t *response,
                                        const dnslib_rrset_t *rrset, int tc)
{
	if (response->header.arcount == response->max_arcount
	    && dnslib_response_realloc_rrsets(&response->additional,
			&response->max_arcount, DEFAULT_ARCOUNT, STEP_ARCOUNT)
		!= 0) {
		return -1;
	}

	dnslib_response_try_add_rrset(response->additional,
	                              &response->header.arcount, response,
	                              rrset, tc);

	return 0;
}

/*----------------------------------------------------------------------------*/

void dnslib_response_set_rcode(dnslib_response_t *response, short rcode)
{
	dnslib_packet_flags_set_rcode(&response->header.flags2, rcode);
}

/*----------------------------------------------------------------------------*/

void dnslib_response_set_aa(dnslib_response_t *response)
{
	dnslib_packet_flags_set_aa(&response->header.flags1);
}

/*----------------------------------------------------------------------------*/

int dnslib_response_to_wire(dnslib_response_t *response,
                            uint8_t **resp_wire, size_t *resp_size)
{
	if (*resp_wire != NULL) {
		return -2;
	}

	uint8_t *wire_tmp = (uint8_t *)malloc(PREALLOC_RESPONSE_WIRE);
	CHECK_ALLOC_LOG(wire_tmp, -1);

	uint8_t *pos = wire_tmp;

	// reserve space for the EDNS OPT RR
	short size = response->edns_size;
	int tc = 0;

	assert(response->max_size > DNSLIB_PACKET_HEADER_SIZE);

	dnslib_response_header_to_wire(&response->header, &pos, &size);

	tc = dnslib_response_question_to_wire(&response->question, &pos, &size,
	                                      response->max_size);

	if (!tc) {
		tc = dnslib_response_rrsets_to_wire(response->answer,
			response->header.ancount, &pos, &size,
			response->max_size, &response->compression);
	}

	if (!tc) {
		tc = dnslib_response_rrsets_to_wire(response->authority,
			response->header.nscount, &pos, &size,
			response->max_size, &response->compression);
	}

	// put EDNS OPT RR
	memcpy(pos, response->edns_wire, response->edns_size);
	pos += response->edns_size;

	if (!tc) {
		tc = dnslib_response_rrsets_to_wire(response->additional,
			response->header.arcount, &pos, &size,
			response->max_size, &response->compression);
	}

	if (tc) {
		dnslib_packet_set_tc(wire_tmp);
	}

	*resp_wire = (uint8_t *)malloc(size);
	if (*resp_wire == NULL) {
		ERR_ALLOC_FAILED;
		free(wire_tmp);
		return -1;
	}

	memcpy(*resp_wire, wire_tmp, size);
	*resp_size = size;
	free(wire_tmp);

	return 0;
}

/*----------------------------------------------------------------------------*/

void dnslib_response_free(dnslib_response_t **response)
{
	if (response == NULL || *response == NULL) {
		return;
	}

	// free temporary domain names
	dnslib_response_free_tmp_domains(*response);
	// check if some additional space was allocated for the response
	dnslib_response_free_allocated_space(*response);

	free(*response);
	*response = NULL;
}
