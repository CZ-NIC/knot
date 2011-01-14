#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "response.h"
#include "rrset.h"
#include "common.h"
#include "packet.h"
#include "descriptor.h"
#include "edns.h"
#include "utils.h"

enum {
	DEFAULT_ANCOUNT = 6,
	DEFAULT_NSCOUNT = 8,
	DEFAULT_ARCOUNT = 28,
	DEFAULT_DOMAINS_IN_RESPONSE = 22,
	DEFAULT_TMP_RRSETS = 5,
	STEP_ANCOUNT = 6,
	STEP_NSCOUNT = 8,
	STEP_ARCOUNT = 8,
	STEP_DOMAINS = 10,
	STEP_TMP_RRSETS = 5
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
	PREALLOC_TMP_RRSETS =
		DEFAULT_TMP_RRSETS * sizeof(dnslib_dname_t *),

	PREALLOC_TOTAL = PREALLOC_RESPONSE
	                 + PREALLOC_QNAME
	                 + PREALLOC_RRSETS
	                 + PREALLOC_DOMAINS
	                 + PREALLOC_OFFSETS
	                 + PREALLOC_TMP_RRSETS,

	PREALLOC_RESPONSE_WIRE = 65535,
	PREALLOC_RRSET_WIRE = 65535
};

static const short QUESTION_OFFSET = DNSLIB_PACKET_HEADER_SIZE;

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static void dnslib_response_parse_host_edns(dnslib_response_t *resp,
                                            const uint8_t *edns_wire,
                                            short edns_size)
{
	resp->max_size = dnslib_edns_get_payload(edns_wire);
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

	resp->tmp_rrsets = (const dnslib_rrset_t **)
		(resp->compression.offsets + DEFAULT_DOMAINS_IN_RESPONSE);

	debug_dnslib_response("Tmp rrsets: %p (%d after compression offsets)\n",
		resp->tmp_rrsets,
		(void *)resp->tmp_rrsets - (void *)resp->compression.offsets);

	resp->tmp_rrsets_max = DEFAULT_TMP_RRSETS;

	debug_dnslib_response("End of data: %p (%d after start of response)\n",
		resp->tmp_rrsets + DEFAULT_TMP_RRSETS,
		(void *)(resp->tmp_rrsets + DEFAULT_TMP_RRSETS)
		  - (void *)resp);
	debug_dnslib_response("Allocated total: %u\n", PREALLOC_TOTAL);

	assert((char *)(resp->tmp_rrsets + DEFAULT_TMP_RRSETS)
	       == (char *)resp + PREALLOC_TOTAL);
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_init(dnslib_response_t *resp,
                                 const uint8_t *edns_wire, short edns_size)
{
	memset(resp, 0, PREALLOC_TOTAL);

	assert(edns_wire != NULL || edns_size == 0);

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

	// set the QR bit
	dnslib_packet_flags_set_qr(&resp->header.flags1);
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
	// copy some of the flags: OPCODE and RD
	// do this by copying flags1 and setting QR to 1, AA to 0 and TC to 0
	header->flags1 = dnslib_packet_get_flags1(*pos);
	dnslib_packet_flags_set_qr(&header->flags1);
	dnslib_packet_flags_clear_aa(&header->flags1);
	dnslib_packet_flags_clear_tc(&header->flags1);
	// do not copy flags2 (all set by server)
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
	if (question->qname == NULL) {
		return -3;  // allocation failed
	}
	*pos += i + 1;
	question->qtype = dnslib_wire_read_u16(*pos);
	*pos += 2;
	question->qclass = dnslib_wire_read_u16(*pos);
	*pos += 2;

	*remaining -= (i + 5);

	return 0;
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_question_to_wire(dnslib_question_t *question,
                                            uint8_t **pos, short *size)
{
	debug_dnslib_response("Copying QNAME, size %d\n",
	                      question->qname->size);
	memcpy(*pos, question->qname->name, question->qname->size);
	*size += question->qname->size;
	*pos += question->qname->size;

	dnslib_wire_write_u16(*pos, question->qtype);
	*pos += 2;
	dnslib_wire_write_u16(*pos, question->qclass);
	*pos += 2;
	*size += 4;
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
	if (dnslib_wire_read_u16(*pos) != DNSLIB_RRTYPE_OPT) {
		debug_dnslib_response("EDNS packet malformed (expected OPT type"
		                      ".\n");
		return -2;
	}
	*pos += 2;

	edns->payload = dnslib_wire_read_u16(*pos);
	*pos += 2;
	edns->ext_rcode = *(*pos)++;
	edns->version = *(*pos)++;
	// skip Z
	*pos += 2;

	// ignore RDATA, but move pos behind them
	uint16_t rdlength = dnslib_wire_read_u16(*pos);
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

	debug_dnslib_response("Wire format:\n");

	// put rest of RR 'header'
	dnslib_wire_write_u16(*rrset_wire, rrset->type);
	debug_dnslib_response("  Type: %u\n", rrset->type);
	debug_dnslib_response("  Type in wire: ");
	debug_dnslib_response_hex((char *)*rrset_wire, 2);
	*rrset_wire += 2;

	dnslib_wire_write_u16(*rrset_wire, rrset->rclass);
	debug_dnslib_response("  Class: %u\n", rrset->rclass);
	debug_dnslib_response("  Class in wire: ");
	debug_dnslib_response_hex((char *)*rrset_wire, 2);
	*rrset_wire += 2;

	dnslib_wire_write_u32(*rrset_wire, rrset->ttl);
	debug_dnslib_response("  TTL: %u\n", rrset->ttl);
	debug_dnslib_response("  TTL in wire: ");
	debug_dnslib_response_hex((char *)*rrset_wire, 4);
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
			short size = 0;
			dnslib_response_compress_dname(
				dnslib_rdata_item(rdata, i)->dname,
				compr, *rrset_wire, &size);
			debug_dnslib_response("Compressed dname size: %d\n",
			                      size);
			*rrset_wire += size;
			rdlength += size;
			// TODO: compress domain name
			break;
		}
		case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_LITERAL_DNAME: {
			// save whole domain name
			dnslib_dname_t *dname =
				dnslib_rdata_item(rdata, i)->dname;
			memcpy(*rrset_wire, dname->name, dname->size);
			debug_dnslib_response("Uncompressed dname size: %d\n",
			                      dname->size);
			*rrset_wire += dname->size;
			rdlength += dname->size;
			break;
		}
		case DNSLIB_RDATA_WF_BINARYWITHLENGTH: {
			// copy also the rdata item size
			uint8_t *raw_data =
				dnslib_rdata_item(rdata, i)->raw_data;
			memcpy(*rrset_wire, raw_data, raw_data[0] + 1);
			debug_dnslib_response("Raw data size: %d\n",
			                      raw_data[0] + 1);
			*rrset_wire += raw_data[0] + 1;
			rdlength += raw_data[0] + 1;
			break;
		}
		default: {
			// copy just the rdata item data (without size)
			uint8_t *raw_data =
				dnslib_rdata_item(rdata, i)->raw_data;
			memcpy(*rrset_wire, raw_data + 1, raw_data[0]);
			debug_dnslib_response("Raw data size: %d\n",
			                      raw_data[0]);
			*rrset_wire += raw_data[0];
			rdlength += raw_data[0];
			break;
		}
		}
	}

	*rrset_size += rdlength;
	dnslib_wire_write_u16(rdlength_pos, rdlength);
}

/*---------------------------------------------------------------------------*/

static int dnslib_response_rrset_to_wire(const dnslib_rrset_t *rrset,
                                              uint8_t **pos, short *size,
                                              dnslib_compressed_dnames_t *compr)
{
DEBUG_DNSLIB_RESPONSE(
	char *name = dnslib_dname_to_str(rrset->owner);
	debug_dnslib_response("Converting RRSet with owner %s, type %s\n",
	                      name, dnslib_rrtype_to_string(rrset->type));
	free(name);
	debug_dnslib_response("  Size before: %d\n", *size);
);
	// if no RDATA in RRSet, return
	if (rrset->rdata == NULL) {
		return 0;
	}

	/*!
	 * \todo Do not use two variables: rrset_wire and rrset_size, just one!
	 */

	//uint8_t *rrset_wire = (uint8_t *)malloc(PREALLOC_RRSET_WIRE);
	//short rrset_size = 0;

	uint8_t *owner_wire = (uint8_t *)malloc(rrset->owner->size);
	short owner_size = 0;

	dnslib_response_compress_dname(rrset->owner, compr, owner_wire,
	                               &owner_size);
	debug_dnslib_response("    Owner size: %d\n", owner_size);

	int rrs = 0;

	const dnslib_rdata_t *rdata = rrset->rdata;
	do {
		dnslib_response_rr_to_wire(owner_wire, owner_size, rrset,
		                           rdata, compr, pos, size);
		++rrs;
	} while ((rdata = dnslib_rrset_rdata_next(rrset, rdata)) != NULL);

	//memcpy(*pos, rrset_wire, rrset_size);
	//*size += rrset_size;
	//*pos += rrset_size;

	debug_dnslib_response("  Size after: %d\n", *size);

	return rrs;
}

/*----------------------------------------------------------------------------*/

static short dnslib_response_rrsets_to_wire(const dnslib_rrset_t **rrsets,
                                            short count, uint8_t **pos,
                                            short *size, short max_size,
                                            dnslib_compressed_dnames_t *compr)
{
	// no compression for now
	int i = 0;

	debug_dnslib_response("Max size: %d\n", max_size);
	short rr_count = 0;

	while (i < count) {
		rr_count +=
		    dnslib_response_rrset_to_wire(rrsets[i], pos, size, compr);
		assert(*size <= max_size);
		++i;
	}

	return rr_count;
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_free_tmp_rrsets(dnslib_response_t *resp)
{
	for (int i = 0; i < resp->tmp_rrsets_count; ++i) {
		// TODO: this is quite ugly, but better than copying whole
		// function (for reallocating rrset array)
		dnslib_rrset_deep_free(
			&(((dnslib_rrset_t **)(resp->tmp_rrsets))[i]), 1);
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

	if (resp->tmp_rrsets_max > DEFAULT_TMP_RRSETS) {
		free(resp->tmp_rrsets);
	}
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_realloc_rrsets(const dnslib_rrset_t ***rrsets,
                                          short *max_count,
                                          short default_max_count, short step)
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
	short size = 0;

	dnslib_rrtype_descriptor_t *desc =
			dnslib_rrtype_descriptor_by_type(rrset->type);

	const dnslib_rdata_t *rdata = dnslib_rrset_rdata(rrset);
	while (rdata != NULL) {
		size += 10;  // 2 type, 2 class, 4 ttl, 2 rdlength
		size += rrset->owner->size;   // owner

		for (int i = 0; i < rdata->count; ++i) {
			switch (desc->wireformat[i]) {
			case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
			case DNSLIB_RDATA_WF_LITERAL_DNAME:
			case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
				debug_dnslib_response("dname size: %d\n",
					rdata->items[i].dname->size);
				size += rdata->items[i].dname->size;
				break;
			case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
				debug_dnslib_response("raw data size: %d\n",
					rdata->items[i].raw_data[0] + 1);
				size += rdata->items[i].raw_data[0] + 1;
				break;
			default:
				debug_dnslib_response("raw data size: %d\n",
					rdata->items[i].raw_data[0]);
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
DEBUG_DNSLIB_RESPONSE(
	char *name = dnslib_dname_to_str(rrset->owner);
	debug_dnslib_response("Adding RRSet with owner %s and type %s, size: "
		"%d.\n", name, dnslib_rrtype_to_string(rrset->type), size);
	free(name);
);
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
	resp->header.qdcount = 1;

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
#ifdef DNSLIB_RESPONSE_DEBUG
	dnslib_response_dump(resp);
#endif /* DNSLIB_RESPONSE_DEBUG */
	return 0;
}

/*----------------------------------------------------------------------------*/

const dnslib_dname_t *dnslib_response_qname(const dnslib_response_t *response)
{
	return response->question.qname;
}

/*----------------------------------------------------------------------------*/

const uint16_t dnslib_response_qtype(const dnslib_response_t *response)
{
	return response->question.qtype;
}

/*----------------------------------------------------------------------------*/

const uint16_t dnslib_response_qclass(const dnslib_response_t *response)
{
	return response->question.qclass;
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

int dnslib_response_add_rrset_additional(dnslib_response_t *response,
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

int dnslib_response_add_tmp_rrset(dnslib_response_t *response,
                                  dnslib_rrset_t *tmp_rrset)
{
	if (response->tmp_rrsets_count == response->tmp_rrsets_max
	    && dnslib_response_realloc_rrsets(&response->tmp_rrsets,
			&response->tmp_rrsets_max, DEFAULT_TMP_RRSETS,
			STEP_TMP_RRSETS)
		!= 0) {
		return -1;
	}

	response->tmp_rrsets[response->tmp_rrsets_count++] = tmp_rrset;

	return 0;
}

/*----------------------------------------------------------------------------*/

short dnslib_response_answer_rrset_count(const dnslib_response_t *response)
{
	return response->header.ancount;
}

/*----------------------------------------------------------------------------*/

short dnslib_response_authority_rrset_count(const dnslib_response_t *response)
{
	return response->header.nscount;
}

/*----------------------------------------------------------------------------*/

short dnslib_response_additional_rrset_count(const dnslib_response_t *response)
{
	return response->header.arcount;
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t *dnslib_response_answer_rrset(
	const dnslib_response_t *response, short pos)
{
	if (pos > response->header.ancount) {
		return NULL;
	}

	return response->answer[pos];
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t *dnslib_response_authority_rrset(
	dnslib_response_t *response, short pos)
{
	if (pos > response->header.nscount) {
		return NULL;
	}

	return response->authority[pos];
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t *dnslib_response_additional_rrset(
	dnslib_response_t *response, short pos)
{
	if (pos > response->header.arcount) {
		return NULL;
	}

	return response->additional[pos];
}

/*----------------------------------------------------------------------------*/

int dnslib_response_to_wire(dnslib_response_t *response,
                            uint8_t **resp_wire, size_t *resp_size)
{
	if (*resp_wire != NULL) {
		return -2;
	}

	assert(response->size <= response->max_size);

	debug_dnslib_response("Converting response to wire format, size: %d\n",
	                      response->size);
	*resp_wire = (uint8_t *)malloc(response->size);
	CHECK_ALLOC_LOG(*resp_wire, -1);

	uint8_t *pos = *resp_wire;

	// reserve space for the EDNS OPT RR
	short size = response->edns_size;

	assert(response->max_size > DNSLIB_PACKET_HEADER_SIZE);

	dnslib_response_header_to_wire(&response->header, &pos, &size);
	debug_dnslib_response("Converted header, size so far: %d\n", size);

	if (response->header.qdcount > 0) {
		dnslib_response_question_to_wire(
			&response->question, &pos, &size);
	}
	debug_dnslib_response("Converted Question, size so far: %d\n", size);

	short rr_count = dnslib_response_rrsets_to_wire(response->answer,
	                               response->header.ancount, &pos, &size,
	                               response->max_size,
	                               &response->compression);
	debug_dnslib_response("Converted Answer, size so far: %d\n", size);
	// set ANCOUNT to the packet
	dnslib_packet_set_ancount(*resp_wire, rr_count);

	rr_count = dnslib_response_rrsets_to_wire(response->authority,
	                               response->header.nscount, &pos, &size,
	                               response->max_size,
	                               &response->compression);
	debug_dnslib_response("Converted Authority, size so far: %d\n", size);
	// set NSCOUNT to the packet
	dnslib_packet_set_nscount(*resp_wire, rr_count);

	// put EDNS OPT RR
	memcpy(pos, response->edns_wire, response->edns_size);
	pos += response->edns_size;
	size += response->edns_size;
	debug_dnslib_response("Converted OPT RR, size so far: %d\n", size);

	rr_count = dnslib_response_rrsets_to_wire(response->additional,
	                               response->header.arcount, &pos, &size,
	                               response->max_size,
	                               &response->compression);
	debug_dnslib_response("Converted Additional, size so far: %d\n", size);
	// set ARCOUNT to the packet
	dnslib_packet_set_arcount(*resp_wire, rr_count + 1);

	assert(response->size == size);
	*resp_size = size;

	return 0;
}

/*----------------------------------------------------------------------------*/

void dnslib_response_free(dnslib_response_t **response)
{
	if (response == NULL || *response == NULL) {
		return;
	}

	// free temporary domain names
	debug_dnslib_response("Freeing tmp domains...\n");
	dnslib_response_free_tmp_rrsets(*response);
	// check if some additional space was allocated for the response
	debug_dnslib_response("Freeing additional allocated space...\n");
	dnslib_response_free_allocated_space(*response);
	debug_dnslib_response("Freeing response structure\n");
	free(*response);
	*response = NULL;
}

/*----------------------------------------------------------------------------*/
#ifdef DNSLIB_RESPONSE_DEBUG
static void dnslib_response_dump_rrsets(const dnslib_rrset_t **rrsets,
                                        int count)
{
	for (int i = 0; i < count; ++i) {
		debug_dnslib_response("  RRSet %d:\n", i + 1);
		char *name = dnslib_dname_to_str(rrsets[i]->owner);
		debug_dnslib_response("    Owner: %s\n", name);
		free(name);
		debug_dnslib_response("    Type: %s\n",
		                      dnslib_rrtype_to_string(rrsets[i]->type));
		debug_dnslib_response("    Class: %s\n",
		                   dnslib_rrclass_to_string(rrsets[i]->rclass));
		debug_dnslib_response("    TTL: %d\n", rrsets[i]->ttl);
		debug_dnslib_response("    RDATA: ");

		dnslib_rrtype_descriptor_t *desc =
			dnslib_rrtype_descriptor_by_type(rrsets[i]->type);

		const dnslib_rdata_t *rdata = dnslib_rrset_rdata(rrsets[i]);
		while (rdata != NULL) {
			for (int j = 0; j < rdata->count; ++j) {
				switch (desc->wireformat[j]) {
				case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
				case DNSLIB_RDATA_WF_LITERAL_DNAME:
				case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
					name = dnslib_dname_to_str(
						rdata->items[j].dname);
					debug_dnslib_response("%s \n",name);
					free(name);
					break;
				case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
					debug_dnslib_response_hex(
					    (char *)rdata->items[j].raw_data,
					    rdata->items[j].raw_data[0]);
					break;
				default:
					debug_dnslib_response_hex(
					   (char *)&rdata->items[j].raw_data[1],
					   rdata->items[j].raw_data[0]);
					break;
				}
			}
			rdata = dnslib_rrset_rdata_next(rrsets[i], rdata);
		}
	}
}
#endif
/*----------------------------------------------------------------------------*/

void dnslib_response_dump(const dnslib_response_t *resp)
{
#ifdef DNSLIB_RESPONSE_DEBUG
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

	debug_dnslib_response("\nAnswer RRSets:\n");
	dnslib_response_dump_rrsets(resp->answer, resp->header.ancount);
	debug_dnslib_response("\nAuthority RRSets:\n");
	dnslib_response_dump_rrsets(resp->authority, resp->header.nscount);
	debug_dnslib_response("\nAdditional RRSets:\n");
	dnslib_response_dump_rrsets(resp->additional, resp->header.arcount);

	/*! \todo Dumping of Answer, Authority and Additional sections. */

	debug_dnslib_response("\nEDNS - client:\n");
	debug_dnslib_response("  Version: %u\n", resp->edns_query.version);
	debug_dnslib_response("  Payload: %u\n", resp->edns_query.payload);
	debug_dnslib_response("  Extended RCODE: %u\n",
	                      resp->edns_query.ext_rcode);

	debug_dnslib_response("\nResponse size: %d\n", resp->size);
	debug_dnslib_response("\n-----------------------------\n");
#endif
}
