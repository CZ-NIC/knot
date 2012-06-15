/*!
 * \file packet.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Structure for holding DNS packet data and metadata.
 *
 * \addtogroup libknot
 * @{
 */
/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _KNOT_PACKET_H_
#define _KNOT_PACKET_H_

#include <stdint.h>
#include <string.h>

#include "dname.h"
#include "rrset.h"
#include "edns.h"
#include "zone/node.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure for holding information needed for compressing domain names.
 *
 * It's a simple table of domain names and their offsets in wire format of the
 * packet.
 *
 * \todo Consider using some better lookup structure, such as skip-list.
 */
struct knot_compressed_dnames {
	const knot_dname_t **dnames;  /*!< Domain names present in packet. */
	size_t *offsets;          /*!< Offsets of domain names in the packet. */
	short count;              /*!< Count of items in the previous arrays. */
	short max;                /*!< Capacity of the structure (allocated). */
	short default_count;
};

typedef struct knot_compressed_dnames knot_compressed_dnames_t;

struct knot_wildcard_nodes {
	const knot_node_t **nodes; /*!< Wildcard nodes from CNAME processing. */
	const knot_dname_t **snames;  /*!< SNAMEs related to the nodes. */
	short count;             /*!< Count of items in the previous arrays. */
	short max;               /*!< Capacity of the structure (allocated). */
	short default_count;
};

typedef struct knot_wildcard_nodes knot_wildcard_nodes_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure representing the DNS packet header.
 */
struct knot_header {
	uint16_t id;      /*!< ID stored in host byte order. */
	uint8_t flags1;   /*!< First octet of header flags. */
	uint8_t flags2;   /*!< Second octet of header flags. */
	uint16_t qdcount; /*!< Number of Question RRs, in host byte order. */
	uint16_t ancount; /*!< Number of Answer RRs, in host byte order. */
	uint16_t nscount; /*!< Number of Authority RRs, in host byte order. */
	uint16_t arcount; /*!< Number of Additional RRs, in host byte order. */
};

typedef struct knot_header knot_header_t;

/*!
 * \brief Structure representing one Question entry in the DNS packet.
 */
struct knot_question {
	knot_dname_t *qname;  /*!< Question domain name. */
	uint16_t qtype;         /*!< Question TYPE. */
	uint16_t qclass;        /*!< Question CLASS. */
};

typedef struct knot_question knot_question_t;

enum knot_packet_prealloc_type {
	KNOT_PACKET_PREALLOC_NONE,
	KNOT_PACKET_PREALLOC_QUERY,
	KNOT_PACKET_PREALLOC_RESPONSE
};

typedef enum knot_packet_prealloc_type knot_packet_prealloc_type_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure representing a DNS packet.
 *
 * \note QNAME, Answer, Authority and Additonal sections are by default put to
 *       preallocated space after the structure with default sizes. If the
 *       space is not enough, more space is allocated dynamically.
 */
struct knot_packet {
	/*! \brief DNS header. */
	knot_header_t header;

	/*!
	 * \brief Question section.
	 *
	 * \note Only one Question is supported!
	 */
	knot_question_t question;

	uint8_t *owner_tmp;  /*!< Allocated space for RRSet owner wire format.*/

	const knot_rrset_t **answer;      /*!< Answer RRSets. */
	const knot_rrset_t **authority;   /*!< Authority RRSets. */
	const knot_rrset_t **additional;  /*!< Additional RRSets. */

	short an_rrsets;     /*!< Count of Answer RRSets in the response. */
	short ns_rrsets;     /*!< Count of Authority RRSets in the response. */
	short ar_rrsets;     /*!< Count of Additional RRSets in the response. */

	short max_an_rrsets; /*!< Allocated space for Answer RRsets. */
	short max_ns_rrsets; /*!< Allocated space for Authority RRsets. */
	short max_ar_rrsets; /*!< Allocated space for Additional RRsets. */

	knot_opt_rr_t opt_rr;     /*!< OPT RR included in the packet. */

	uint8_t *wireformat;  /*!< Wire format of the packet. */

	short free_wireformat;
	size_t parsed;
	uint16_t parsed_an;
	uint16_t parsed_ns;
	uint16_t parsed_ar;

	size_t size;      /*!< Current wire size of the packet. */
	size_t max_size;  /*!< Maximum allowed size of the packet. */

	/*! \brief Information needed for compressing domain names in packet. */
	knot_compressed_dnames_t compression;

	/*! \brief Wildcard nodes to be processed for NSEC/NSEC3. */
	knot_wildcard_nodes_t wildcard_nodes;

	/*! \brief RRSets to be destroyed with the packet structure. */
	const knot_rrset_t **tmp_rrsets;
	short tmp_rrsets_count;  /*!< Count of temporary RRSets. */
	short tmp_rrsets_max;    /*!< Allocated space for temporary RRSets. */

	struct knot_packet *query; /*!< Associated query. */

	knot_packet_prealloc_type_t prealloc_type;
	
	size_t tsig_size;	/*!< Space to reserve for the TSIG RR. */
	knot_rrset_t *tsig_rr;  /*!< TSIG RR stored in the packet. */
};

typedef struct knot_packet knot_packet_t;

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

	/*! \brief Default count of wildcard nodes saved for later processing.*/
	DEFAULT_WILDCARD_NODES = 1,

	/*! \brief Default count of temporary RRSets stored in query. */
	DEFAULT_TMP_RRSETS_QUERY = 2,

	STEP_ANCOUNT = 6, /*!< Step for increasing space for Answer RRSets. */
	STEP_NSCOUNT = 8, /*!< Step for increasing space for Authority RRSets.*/
	STEP_ARCOUNT = 8,/*!< Step for increasing space for Additional RRSets.*/
	STEP_DOMAINS = 10,   /*!< Step for resizing compression table. */
	STEP_TMP_RRSETS = 5,  /*!< Step for increasing temorary RRSets count. */
	STEP_WILDCARD_NODES = 2
};

/*----------------------------------------------------------------------------*/
#define PREALLOC_RRSETS(count) (count * sizeof(knot_rrset_t *))

/*! \brief Sizes for preallocated space in the response structure. */
enum {
	/*! \brief Size of the response structure itself. */
	PREALLOC_PACKET = sizeof(knot_packet_t),
	/*! \brief Space for QNAME dname structure. */
	PREALLOC_QNAME_DNAME = sizeof(knot_dname_t),
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

	/*! \brief Space for one part of the compression table (domain names).*/
	PREALLOC_DOMAINS =
		DEFAULT_DOMAINS_IN_RESPONSE * sizeof(knot_dname_t *),
	/*! \brief Space for other part of the compression table (offsets). */
	PREALLOC_OFFSETS =
		DEFAULT_DOMAINS_IN_RESPONSE * sizeof(size_t),
	PREALLOC_COMPRESSION = PREALLOC_DOMAINS + PREALLOC_OFFSETS,

	PREALLOC_WC_NODES =
		DEFAULT_WILDCARD_NODES * sizeof(knot_node_t *),
	PREALLOC_WC_SNAMES =
		DEFAULT_WILDCARD_NODES * sizeof(knot_dname_t *),
	PREALLOC_WC = PREALLOC_WC_NODES + PREALLOC_WC_SNAMES,

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
	                 + PREALLOC_WC
	                 + PREALLOC_RRSETS(DEFAULT_TMP_RRSETS)
};

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates new empty packet structure.
 *
 * \param prealloc What space should be preallocated in the structure.
 *
 * \return New packet structure or NULL if an error occured.
 */
knot_packet_t *knot_packet_new(knot_packet_prealloc_type_t prealloc);

/*!
 * \brief Parses the DNS packet from wire format.
 *
 * \param packet Packet structure to parse into.
 * \param wireformat Wire format of the DNS packet.
 * \param size Size of the wire format in bytes.
 * \param question_only Set to <> 0 if you do not want to parse the whole
 *                      packet. In such case the parsing will end after the
 *                      Question section. Set to 0 to parse the whole packet.
 *
 * \retval KNOT_EOK
 */
int knot_packet_parse_from_wire(knot_packet_t *packet,
                                  const uint8_t *wireformat, size_t size,
                                  int question_only);

int knot_packet_parse_rest(knot_packet_t *packet);

int knot_packet_parse_next_rr_answer(knot_packet_t *packet,
                                       knot_rrset_t **rr);

int knot_packet_parse_next_rr_additional(knot_packet_t *packet,
                                         knot_rrset_t **rr);

size_t knot_packet_size(const knot_packet_t *packet);

/*! \brief Returns size of the wireformat of Header and Question sections. */
size_t knot_packet_question_size(const knot_packet_t *packet);

size_t knot_packet_parsed(const knot_packet_t *packet);

/*!
 * \brief Sets the maximum size of the packet and allocates space for wire
 *        format (if needed).
 *
 * This function also allocates space for the wireformat of the packet, if
 * the given max size is larger than the current maximum size of the packet
 * and copies the current wireformat over to the new space.
 *
 * \warning Do not call this function if you are not completely sure that the
 *          current wire format of the packet fits into the new space.
 *          It does not update the current size of the wire format, so the
 *          produced packet may be larger than the given max size.
 *
 * \param packet Packet to set the maximum size of.
 * \param max_size Maximum size of the packet in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EBADARG
 * \retval KNOT_ENOMEM
 *
 * \todo Needs test.
 */
int knot_packet_set_max_size(knot_packet_t *packet, int max_size);

uint16_t knot_packet_id(const knot_packet_t *packet);

void knot_packet_set_id(knot_packet_t *packet, uint16_t id);

void knot_packet_set_random_id(knot_packet_t *packet);

/*!
 * \brief Returns the OPCODE of the packet.
 *
 * \param packet Packet (with parsed query) to get the OPCODE from.
 *
 * \return OPCODE stored in the packet.
 */
uint8_t knot_packet_opcode(const knot_packet_t *packet);

/*!
 * \brief Returns the QNAME from the packet.
 *
 * \param packet Packet (with parsed query) to get the QNAME from.
 *
 * \return QNAME stored in the packet.
 */
const knot_dname_t *knot_packet_qname(const knot_packet_t *packet);

/*!
 * \brief Returns the QTYPE from the packet.
 *
 * \param packet Packet (with parsed query) to get the QTYPE from.
 *
 * \return QTYPE stored in the packet.
 */
uint16_t knot_packet_qtype(const knot_packet_t *packet);

/*!
 * \brief Set the QTYPE of the packet.
 *
 * \param packet Packet containing question.
 * \param qtype New QTYPE for question.
 */
void knot_packet_set_qtype(knot_packet_t *packet, knot_rr_type_t qtype);


/*!
 * \brief Returns the QCLASS from the packet.
 *
 * \param response Packet (with parsed query) to get the QCLASS from.
 *
 * \return QCLASS stored in the packet.
 */
uint16_t knot_packet_qclass(const knot_packet_t *packet);

int knot_packet_is_query(const knot_packet_t *packet);

const knot_packet_t *knot_packet_query(const knot_packet_t *packet);

int knot_packet_rcode(const knot_packet_t *packet);

int knot_packet_tc(const knot_packet_t *packet);

int knot_packet_qdcount(const knot_packet_t *packet);

int knot_packet_ancount(const knot_packet_t *packet);

int knot_packet_nscount(const knot_packet_t *packet);

int knot_packet_arcount(const knot_packet_t *packet);

void knot_packet_set_tsig_size(knot_packet_t *packet, size_t tsig_size);

const knot_rrset_t *knot_packet_tsig(const knot_packet_t *packet);

void knot_packet_set_tsig(knot_packet_t *packet, const knot_rrset_t *tsig_rr);

/*!
 * \brief Returns number of RRSets in Answer section of the packet.
 *
 * \param response Packet to get the Answer RRSet count from.
 */
short knot_packet_answer_rrset_count(const knot_packet_t *packet);

/*!
 * \brief Returns number of RRSets in Authority section of the packet.
 *
 * \param response Packet to get the Authority RRSet count from.
 */
short knot_packet_authority_rrset_count(const knot_packet_t *packet);

/*!
 * \brief Returns number of RRSets in Additional section of the packet.
 *
 * \param response Packet to get the Additional RRSet count from.
 */
short knot_packet_additional_rrset_count(const knot_packet_t *packet);

/*!
 * \brief Returns the requested Answer RRset.
 *
 * \param packet Packet to get the RRSet from.
 * \param pos Position of the RRSet in the Answer section (RRSets are stored
 *            in the order they were added to the response or parsed from the
 *            query).
 *
 * \return The RRSet on position \a pos in the Answer section of \a packet
 *         or NULL if there is no such RRSet.
 */
const knot_rrset_t *knot_packet_answer_rrset(
	const knot_packet_t *packet, short pos);

/*!
 * \brief Returns the requested Authority RRset.
 *
 * \param packet Packet to get the RRSet from.
 * \param pos Position of the RRSet in the Authority section (RRSets are stored
 *            in the order they were added to the response or parsed from the
 *            query).
 *
 * \return The RRSet on position \a pos in the Authority section of \a packet
 *         or NULL if there is no such RRSet.
 */
const knot_rrset_t *knot_packet_authority_rrset(
	knot_packet_t *packet, short pos);

/*!
 * \brief Returns the requested Additional RRset.
 *
 * \param packet Packet to get the RRSet from.
 * \param pos Position of the RRSet in the Additional section (RRSets are stored
 *            in the order they were added to the response or parsed from the
 *            query).
 *
 * \return The RRSet on position \a pos in the Additional section of \a packet
 *         or NULL if there is no such RRSet.
 */
const knot_rrset_t *knot_packet_additional_rrset(
    knot_packet_t *packet, short pos);

/*!
 * \brief Checks if the packet already contains the given RRSet.
 *
 * It searches for the RRSet in the three lists of RRSets corresponding to
 * Answer, Authority and Additional sections of the packet.
 *
 * \note Only pointers are compared, i.e. two instances of knot_rrset_t with
 * the same data will be considered different.
 *
 * \param packet Packet to look for the RRSet in.
 * \param rrset RRSet to look for.
 *
 * \retval 0 if \a resp does not contain \a rrset.
 * \retval <> 0 if \a resp does contain \a rrset.
 */
int knot_packet_contains(const knot_packet_t *packet,
                           const knot_rrset_t *rrset,
                           knot_rrset_compare_type_t cmp);

/*!
 * \brief Adds RRSet to the list of temporary RRSets.
 *
 * Temporary RRSets are fully freed when the response structure is destroyed.
 *
 * \param response Response to which the temporary RRSet should be added.
 * \param tmp_rrset Temporary RRSet to be stored in the response.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
int knot_packet_add_tmp_rrset(knot_packet_t *response,
                                knot_rrset_t *tmp_rrset);

void knot_packet_free_tmp_rrsets(knot_packet_t *pkt);

/*!
 * \brief Converts the header structure to wire format.
 *
 * \note This function also adjusts the position (\a pos) according to
 *       the size of the converted wire format.
 *
 * \param[in] header DNS header structure to convert.
 * \param[out] pos Position where to put the converted header. The space has
 *                 to be allocated before calling this function.
 * \param[out] size Size of the wire format of the header in bytes.
 */
void knot_packet_header_to_wire(const knot_header_t *header,
                                  uint8_t **pos, size_t *size);

int knot_packet_question_to_wire(knot_packet_t *packet);

/*!
 * \brief Converts the stored response OPT RR to wire format and adds it to
 *        the response wire format.
 *
 * \param resp Response structure.
 */
int knot_packet_edns_to_wire(knot_packet_t *packet);

/*!
 * \brief Converts the packet to wire format.
 *
 * \param packet Packet to be converted to wire format.
 * \param wire Here the wire format of the packet will be stored.
 *             Space for the packet will be allocated. *resp_wire must
 *             be set to NULL (to avoid leaks).
 * \param wire_size The size of the packet in wire format will be stored here.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EBADARG
 */
int knot_packet_to_wire(knot_packet_t *packet, uint8_t **wire,
                          size_t *wire_size);

const uint8_t *knot_packet_wireformat(const knot_packet_t *packet);

/*!
 * \brief Properly destroys the packet structure.
 *
 * \param response Packet to be destroyed.
 */
void knot_packet_free(knot_packet_t **packet);

/*!
 * \brief Dumps the whole packet in human-readable form.
 *
 * \note This function is empty unless KNOT_PACKET_DEBUG is defined.
 *
 * \param resp Packet to dump.
 */
void knot_packet_dump(const knot_packet_t *packet);

#endif /* _KNOT_PACKET_H_ */

/*! @} */
