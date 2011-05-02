#include "dnslib/packet.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief Default sizes for response structure parts and steps for increasing
 *        them.
 */
enum {
	DEFAULT_ANCOUNT = 6,         /*!< Default count of Answer RRSets. */
	DEFAULT_NSCOUNT = 8,         /*!< Default count of Authority RRSets. */
	DEFAULT_ARCOUNT = 28,        /*!< Default count of Additional RRSets. */

	DEFAULT_ANCOUNT_QUERY = 1,   /*!< Default count of Answer RRSets. */
	DEFAULT_NSCOUNT_QUERY = 0,   /*!< Default count of Authority RRSets. */
	DEFAULT_ARCOUNT_QUERY = 1,  /*!< Default count of Additional RRSets. */
	/*!
	 * \brief Default count of all domain names in response.
	 *
	 * Used for compression table.
	 */
	DEFAULT_DOMAINS_IN_RESPONSE = 22,

	/*! \brief Default count of temporary RRSets stored in response. */
	DEFAULT_TMP_RRSETS = 5,

	/*! \brief Default count of temporary RRSets stored in query. */
	DEFAULT_TMP_RRSETS_QUERY = 2,

	STEP_ANCOUNT = 6, /*!< Step for increasing space for Answer RRSets. */
	STEP_NSCOUNT = 8, /*!< Step for increasing space for Authority RRSets.*/
	STEP_ARCOUNT = 8,/*!< Step for increasing space for Additional RRSets.*/
	STEP_DOMAINS = 10,   /*!< Step for resizing compression table. */
	STEP_TMP_RRSETS = 5  /*!< Step for increasing temorary RRSets count. */
};

/*----------------------------------------------------------------------------*/
#define PREALLOC_RRSETS(count) (count * sizeof(dnslib_rrset_t *))

/*! \brief Sizes for preallocated space in the response structure. */
enum {
	/*! \brief Size of the response structure itself. */
	PREALLOC_PACKET = sizeof(dnslib_packet_t),
	/*! \brief Space for QNAME dname structure. */
	PREALLOC_QNAME_DNAME = sizeof(dnslib_dname_t),
	/*! \brief Space for QNAME name (maximum domain name size). */
	PREALLOC_QNAME_NAME = 256,
	/*! \brief Space for QNAME labels (maximum label count). */
	PREALLOC_QNAME_LABELS = 127,
	/*! \brief Total space for QNAME. */
	PREALLOC_QNAME = PREALLOC_QNAME_DNAME
	                 + PREALLOC_QNAME_NAME
	                 + PREALLOC_QNAME_LABELS,
	/*!
	 * \brief Space for RR owner wire format.
	 *
	 * Temporary buffer, used when putting RRSets to the response.
	 */
	PREALLOC_RR_OWNER = 256,

//	/*! \brief Space for Answer RRSets. */
//	PREALLOC_ANSWER = DEFAULT_ANCOUNT * sizeof(dnslib_dname_t *),
//	/*! \brief Space for Authority RRSets. */
//	PREALLOC_AUTHORITY = DEFAULT_NSCOUNT * sizeof(dnslib_dname_t *),
//	/*! \brief Space for Additional RRSets. */
//	PREALLOC_ADDITIONAL = DEFAULT_ARCOUNT * sizeof(dnslib_dname_t *),
//	/*! \brief Total size for Answer, Authority and Additional RRSets. */
//	PREALLOC_RRSETS = PREALLOC_ANSWER
//	                  + PREALLOC_AUTHORITY
//	                  + PREALLOC_ADDITIONAL,
	/*! \brief Space for one part of the compression table (domain names).*/
	PREALLOC_DOMAINS =
		DEFAULT_DOMAINS_IN_RESPONSE * sizeof(dnslib_dname_t *),
	/*! \brief Space for other part of the compression table (offsets). */
	PREALLOC_OFFSETS =
		DEFAULT_DOMAINS_IN_RESPONSE * sizeof(size_t),
	PREALLOC_COMPRESSION = PREALLOC_DOMAINS + PREALLOC_OFFSETS,

//	/*! \brief Space for temporary RRSets. */
//	PREALLOC_TMP_RRSETS =
//		DEFAULT_TMP_RRSETS * sizeof(dnslib_rrset_t *),

	PREALLOC_QUERY = PREALLOC_PACKET
	                 + PREALLOC_QNAME
	                 + PREALLOC_RRSETS(DEFAULT_ANCOUNT_QUERY)
	                 + PREALLOC_RRSETS(DEFAULT_NSCOUNT_QUERY)
	                 + PREALLOC_RRSETS(DEFAULT_ARCOUNT_QUERY)
	                 + PREALLOC_RRSETS(DEFAULT_TMP_RRSETS_QUERY),

	/*! \brief Total preallocated size for the response. */
	PREALLOC_RESPONSE = PREALLOC_PACKET
	                 + PREALLOC_QNAME
	                 + PREALLOC_RR_OWNER
	                 + PREALLOC_RRSETS(DEFAULT_ANCOUNT)
	                 + PREALLOC_RRSETS(DEFAULT_NSCOUNT)
	                 + PREALLOC_RRSETS(DEFAULT_ARCOUNT)
	                 + PREALLOC_COMPRESSION
	                 + PREALLOC_RRSETS(DEFAULT_TMP_RRSETS)
};

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets all the pointers in the packet structure to the respective
 *        parts of the pre-allocated space.
 */
static void dnslib_packet_init_pointers_response(dnslib_packet_t *pkt)
{
	debug_dnslib_packet("Packet pointer: %p\n", pkt);

	// put QNAME directly after the structure
	pkt->question.qname =
		(dnslib_dname_t *)((char *)pkt + PREALLOC_PACKET);

	debug_dnslib_packet("QNAME: %p (%zu after start of packet)\n",
		pkt->question.qname,
		(void *)pkt->question.qname - (void *)pkt);

	pkt->question.qname->name = (uint8_t *)((char *)pkt->question.qname
	                                         + PREALLOC_QNAME_DNAME);
	pkt->question.qname->labels = (uint8_t *)((char *)
	                                           pkt->question.qname->name
	                                           + PREALLOC_QNAME_NAME);

	pkt->owner_tmp = (uint8_t *)((char *)pkt->question.qname->labels
	                              + PREALLOC_QNAME_LABELS);

	// then answer, authority and additional sections
	pkt->answer = (const dnslib_rrset_t **)
	                   ((char *)pkt->owner_tmp + PREALLOC_RR_OWNER);
	pkt->authority = pkt->answer + DEFAULT_ANCOUNT;
	pkt->additional = pkt->authority + DEFAULT_NSCOUNT;

	debug_dnslib_packet("Answer section: %p (%zu after QNAME)\n",
		pkt->answer,
		(void *)pkt->answer - (void *)pkt->question.qname);
	debug_dnslib_packet("Authority section: %p (%zu after Answer)\n",
		pkt->authority,
		(void *)pkt->authority - (void *)pkt->answer);
	debug_dnslib_packet("Additional section: %p (%zu after Authority)\n",
		pkt->additional,
		(void *)pkt->additional - (void *)pkt->authority);

	pkt->max_an_rrsets = DEFAULT_ANCOUNT;
	pkt->max_ns_rrsets = DEFAULT_NSCOUNT;
	pkt->max_ar_rrsets = DEFAULT_ARCOUNT;

	// then domain names for compression and offsets
	pkt->compression.dnames = (const dnslib_dname_t **)
	                               (pkt->additional + DEFAULT_ARCOUNT);
	pkt->compression.offsets = (size_t *)
		(pkt->compression.dnames + DEFAULT_DOMAINS_IN_RESPONSE);

	debug_dnslib_packet("Compression dnames: %p (%zu after Additional)\n",
		pkt->compression.dnames,
		(void *)pkt->compression.dnames - (void *)pkt->additional);
	debug_dnslib_packet("Compression offsets: %p (%zu after c. dnames)\n",
		pkt->compression.offsets,
		(void *)pkt->compression.offsets
		  - (void *)pkt->compression.dnames);

	pkt->compression.max = DEFAULT_DOMAINS_IN_RESPONSE;

	pkt->tmp_rrsets = (const dnslib_rrset_t **)
		(pkt->compression.offsets + DEFAULT_DOMAINS_IN_RESPONSE);

	debug_dnslib_packet("Tmp rrsets: %p (%zu after compression offsets)"
		"\n", pkt->tmp_rrsets,
		(void *)pkt->tmp_rrsets - (void *)pkt->compression.offsets);

	pkt->tmp_rrsets_max = DEFAULT_TMP_RRSETS;

	debug_dnslib_packet("End of data: %p (%zu after start of packet)\n",
		pkt->tmp_rrsets + DEFAULT_TMP_RRSETS,
		(void *)(pkt->tmp_rrsets + DEFAULT_TMP_RRSETS) - (void *)pkt);
	debug_dnslib_packet("Allocated total: %u\n", PREALLOC_RESPONSE);

	assert((char *)(pkt->tmp_rrsets + DEFAULT_TMP_RRSETS)
	       == (char *)pkt + PREALLOC_RESPONSE);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets all the pointers in the packet structure to the respective
 *        parts of the pre-allocated space.
 */
static void dnslib_packet_init_pointers_query(dnslib_packet_t *pkt)
{
	debug_dnslib_packet("Packet pointer: %p\n", pkt);

	// put QNAME directly after the structure
	pkt->question.qname =
		(dnslib_dname_t *)((char *)pkt + PREALLOC_PACKET);

	debug_dnslib_packet("QNAME: %p (%zu after start of packet)\n",
		pkt->question.qname,
		(void *)pkt->question.qname - (void *)pkt);

	pkt->question.qname->name = (uint8_t *)((char *)pkt->question.qname
	                                         + PREALLOC_QNAME_DNAME);
	pkt->question.qname->labels = (uint8_t *)((char *)
	                                           pkt->question.qname->name
	                                           + PREALLOC_QNAME_NAME);



	pkt->owner_tmp = (uint8_t *)((char *)pkt->question.qname->labels
	                              + PREALLOC_QNAME_LABELS);

	// then answer, authority and additional sections
	pkt->answer = (const dnslib_rrset_t **)
	          ((char *)pkt->question.qname->labels + PREALLOC_QNAME_LABELS);
	pkt->authority = pkt->answer + DEFAULT_ANCOUNT_QUERY;
	pkt->additional = pkt->authority + DEFAULT_NSCOUNT_QUERY;

	debug_dnslib_packet("Answer section: %p (%zu after QNAME)\n",
		pkt->answer,
		(void *)pkt->answer - (void *)pkt->question.qname);
	debug_dnslib_packet("Authority section: %p (%zu after Answer)\n",
		pkt->authority,
		(void *)pkt->authority - (void *)pkt->answer);
	debug_dnslib_packet("Additional section: %p (%zu after Authority)\n",
		pkt->additional,
		(void *)pkt->additional - (void *)pkt->authority);

	pkt->max_an_rrsets = DEFAULT_ANCOUNT_QUERY;
	pkt->max_ns_rrsets = DEFAULT_NSCOUNT_QUERY;
	pkt->max_ar_rrsets = DEFAULT_ARCOUNT_QUERY;

	pkt->tmp_rrsets = (const dnslib_rrset_t **)
	                      (pkt->additional + DEFAULT_ARCOUNT);

	debug_dnslib_packet("Tmp rrsets: %p (%zu after Additional)\n",
		pkt->tmp_rrsets,
		(void *)pkt->tmp_rrsets - (void *)pkt->additional);

	pkt->tmp_rrsets_max = DEFAULT_TMP_RRSETS_QUERY;

	debug_dnslib_packet("End of data: %p (%zu after start of packet)\n",
		pkt->tmp_rrsets + DEFAULT_TMP_RRSETS_QUERY,
		(void *)(pkt->tmp_rrsets + DEFAULT_TMP_RRSETS_QUERY)
		- (void *)pkt);
	debug_dnslib_packet("Allocated total: %u\n", PREALLOC_QUERY);

	assert((char *)(pkt->tmp_rrsets + DEFAULT_TMP_RRSETS_QUERY)
	       == (char *)pkt + PREALLOC_QUERY);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Frees all temporary RRSets stored in the response structure.
 *
 * \param resp Response structure to free the temporary RRSets from.
 */
static void dnslib_packet_free_tmp_rrsets(dnslib_packet_t *pkt)
{
	for (int i = 0; i < pkt->tmp_rrsets_count; ++i) {
		// TODO: this is quite ugly, but better than copying whole
		// function (for reallocating rrset array)
		dnslib_rrset_deep_free(
			&(((dnslib_rrset_t **)(pkt->tmp_rrsets))[i]), 1, 1);
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Deallocates all space which was allocated additionally to the
 *        pre-allocated space of the response structure.
 *
 * \param resp Response structure that holds pointers to the allocated space.
 */
static void dnslib_packet_free_allocated_space(dnslib_packet_t *pkt)
{
	if (pkt->max_an_rrsets > DEFAULT_ANCOUNT) {
		free(pkt->answer);
	}
	if (pkt->max_ns_rrsets > DEFAULT_NSCOUNT) {
		free(pkt->authority);
	}
	if (pkt->max_ar_rrsets > DEFAULT_ARCOUNT) {
		free(pkt->additional);
	}

	if (pkt->compression.max > DEFAULT_DOMAINS_IN_RESPONSE) {
		free(pkt->compression.dnames);
		free(pkt->compression.offsets);
	}

	if (pkt->tmp_rrsets_max > DEFAULT_TMP_RRSETS) {
		free(pkt->tmp_rrsets);
	}
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_packet_t *dnslib_packet_new(dnslib_packet_prealloc_type_t prealloc)
{
	dnslib_packet_t *pkt;
	void (*init_pointers)(dnslib_packet_t *pkt) = NULL;
	size_t size;

	switch (prealloc) {
	case DNSLIB_PACKET_PREALLOC_NONE:
		size = sizeof(dnslib_packet_t);
		break;
	case DNSLIB_PACKET_PREALLOC_QUERY:
		size = PREALLOC_QUERY;
		init_pointers = dnslib_packet_init_pointers_query;
		break;
	case DNSLIB_PACKET_PREALLOC_RESPONSE:
		size = PREALLOC_RESPONSE;
		init_pointers = dnslib_packet_init_pointers_response;
		break;
	}

	pkt = (dnslib_packet_t *)malloc(size);
	CHECK_ALLOC_LOG(pkt, NULL);
	memset(pkt, 0, size);
	if (init_pointers != NULL) {
		init_pointers(pkt);
	}

	return pkt;
}

/*----------------------------------------------------------------------------*/

int dnslib_packet_parse_from_wire(dnslib_packet_t *packet, uint8_t *wireformat,
                                  size_t size, int question_only)
{
	/*! \todo Implement! */
	return DNSLIB_ERROR;
}

/*----------------------------------------------------------------------------*/

uint8_t dnslib_packet_opcode(const dnslib_packet_t *packet)
{
	return dnslib_wire_flags_get_opcode(packet->header.flags1);
}

/*----------------------------------------------------------------------------*/

const dnslib_dname_t *dnslib_packet_qname(const dnslib_packet_t *packet)
{
	return packet->question.qname;
}

/*----------------------------------------------------------------------------*/

uint16_t dnslib_packet_qtype(const dnslib_packet_t *packet)
{
	return packet->question.qtype;
}

/*----------------------------------------------------------------------------*/

uint16_t dnslib_packet_qclass(const dnslib_packet_t *packet)
{
	return packet->question.qclass;
}

/*----------------------------------------------------------------------------*/

short dnslib_packet_answer_rrset_count(const dnslib_packet_t *packet)
{
	return packet->an_rrsets;
}

/*----------------------------------------------------------------------------*/

short dnslib_packet_authority_rrset_count(const dnslib_packet_t *packet)
{
	return packet->ns_rrsets;
}

/*----------------------------------------------------------------------------*/

short dnslib_packet_additional_rrset_count(const dnslib_packet_t *packet)
{
	return packet->ar_rrsets;
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t *dnslib_packet_answer_rrset(
	const dnslib_packet_t *packet, short pos)
{
	if (pos > packet->an_rrsets) {
		return NULL;
	}

	return packet->answer[pos];
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t *dnslib_packet_authority_rrset(
	dnslib_packet_t *packet, short pos)
{
	if (pos > packet->ns_rrsets) {
		return NULL;
	}

	return packet->authority[pos];
}

/*----------------------------------------------------------------------------*/

const dnslib_rrset_t *dnslib_packet_additional_rrset(
	dnslib_packet_t *packet, short pos)
{
	if (pos > packet->ar_rrsets) {
		return NULL;
	}

	return packet->additional[pos];
}

/*----------------------------------------------------------------------------*/

int dnslib_packet_contains(const dnslib_packet_t *packet,
                           const dnslib_rrset_t *rrset)
{
	for (int i = 0; i < packet->header.ancount; ++i) {
		if (packet->answer[i] == rrset) {
			return 1;
		}
	}

	for (int i = 0; i < packet->header.nscount; ++i) {
		if (packet->authority[i] == rrset) {
			return 1;
		}
	}

	for (int i = 0; i < packet->header.arcount; ++i) {
		if (packet->additional[i] == rrset) {
			return 1;
		}
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

void dnslib_packet_free(dnslib_packet_t **packet)
{
	if (packet == NULL || *packet == NULL) {
		return;
	}

	// free temporary domain names
	debug_dnslib_packet("Freeing tmp domains...\n");
	dnslib_packet_free_tmp_rrsets(*packet);

	// check if some additional space was allocated for the packet
	debug_dnslib_packet("Freeing additional allocated space...\n");
	dnslib_packet_free_allocated_space(*packet);

	// free the space for wireformat
	assert((*packet)->wireformat != NULL);
	free((*packet)->wireformat);

	debug_dnslib_packet("Freeing packet structure\n");
	free(*packet);
	*packet = NULL;
}

/*----------------------------------------------------------------------------*/
#ifdef DNSLIB_PACKET_DEBUG
static void dnslib_packet_dump_rrsets(const dnslib_rrset_t **rrsets,
                                      int count)
{
	for (int i = 0; i < count; ++i) {
		debug_dnslib_packet("  RRSet %d:\n", i + 1);
		char *name = dnslib_dname_to_str(rrsets[i]->owner);
		debug_dnslib_packet("    Owner: %s\n", name);
		free(name);
		debug_dnslib_packet("    Type: %s\n",
		                      dnslib_rrtype_to_string(rrsets[i]->type));
		debug_dnslib_packet("    Class: %s\n",
		                   dnslib_rrclass_to_string(rrsets[i]->rclass));
		debug_dnslib_packet("    TTL: %d\n", rrsets[i]->ttl);
		debug_dnslib_packet("    RDATA: ");

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
					debug_dnslib_packet("%s \n",name);
					free(name);
					break;
				case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
					debug_dnslib_packet_hex(
					    (char *)rdata->items[j].raw_data,
					    rdata->items[j].raw_data[0]);
					break;
				default:
					debug_dnslib_packet_hex(
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

void dnslib_packet_dump(const dnslib_packet_t *packet)
{
#ifdef DNSLIB_PACKET_DEBUG
	debug_dnslib_packet("DNS packet:\n-----------------------------\n");

	debug_dnslib_packet("\nHeader:\n");
	debug_dnslib_packet("  ID: %u", packet->header.id);
	debug_dnslib_packet("  FLAGS: %s %s %s %s %s %s %s\n",
	       dnslib_wire_flags_get_qr(packet->header.flags1) ? "qr" : "",
	       dnslib_wire_flags_get_aa(packet->header.flags1) ? "aa" : "",
	       dnslib_wire_flags_get_tc(packet->header.flags1) ? "tc" : "",
	       dnslib_wire_flags_get_rd(packet->header.flags1) ? "rd" : "",
	       dnslib_wire_flags_get_ra(packet->header.flags2) ? "ra" : "",
	       dnslib_wire_flags_get_ad(packet->header.flags2) ? "ad" : "",
	       dnslib_wire_flags_get_cd(packet->header.flags2) ? "cd" : "");
	debug_dnslib_packet("  QDCOUNT: %u\n", packet->header.qdcount);
	debug_dnslib_packet("  ANCOUNT: %u\n", packet->header.ancount);
	debug_dnslib_packet("  NSCOUNT: %u\n", packet->header.nscount);
	debug_dnslib_packet("  ARCOUNT: %u\n", packet->header.arcount);

	debug_dnslib_packet("\nQuestion:\n");
	char *qname = dnslib_dname_to_str(packet->question.qname);
	debug_dnslib_packet("  QNAME: %s\n", qname);
	free(qname);
	debug_dnslib_packet("  QTYPE: %u (%s)\n", packet->question.qtype,
	       dnslib_rrtype_to_string(packet->question.qtype));
	debug_dnslib_packet("  QCLASS: %u (%s)\n", packet->question.qclass,
	       dnslib_rrclass_to_string(packet->question.qclass));

	debug_dnslib_packet("\nAnswer RRSets:\n");
	dnslib_packet_dump_rrsets(packet->answer, packet->an_rrsets);
	debug_dnslib_packet("\nAuthority RRSets:\n");
	dnslib_packet_dump_rrsets(packet->authority, packet->ns_rrsets);
	debug_dnslib_packet("\nAdditional RRSets:\n");
	dnslib_packet_dump_rrsets(packet->additional, packet->ar_rrsets);

	/*! \todo Dumping of Answer, Authority and Additional sections. */

	debug_dnslib_packet("\nEDNS:\n");
	debug_dnslib_packet("  Version: %u\n", packet->opt_rr.version);
	debug_dnslib_packet("  Payload: %u\n", packet->opt_rr.payload);
	debug_dnslib_packet("  Extended RCODE: %u\n",
	                      packet->opt_rr.ext_rcode);

	debug_dnslib_packet("\nPacket size: %d\n", packet->size);
	debug_dnslib_packet("\n-----------------------------\n");
#endif
}

