/*!
 * \file rrset.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief RRSet structure and API for manipulating it.
 *
 * \addtogroup libknot
 * @{
 */
/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifndef _KNOT_RRSET_H_
#define _KNOT_RRSET_H_

#include <stdint.h>
#include <stdbool.h>

#include "common/mempattern.h"

#include "libknot/dname.h"
#include "libknot/rr.h"

struct knot_compr;
struct knot_node;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure for representing an RRSet.
 *
 * For definition of a RRSet see RFC2181, Section 5.
 */
struct knot_rrset {
	knot_dname_t *owner;  /*!< Domain name being the owner of the RRSet. */
	uint16_t type;        /*!< TYPE of the RRset. */
	uint16_t rclass;      /*!< CLASS of the RRSet. */
	knot_rrs_t rrs;       /*!< RRSet's RRs */
	/* Optional fields. */
	struct knot_node **additional; /*!< Additional records. */
};

typedef struct knot_rrset knot_rrset_t;

/*----------------------------------------------------------------------------*/

typedef enum {
	KNOT_RRSET_COMPARE_PTR,
	KNOT_RRSET_COMPARE_HEADER,
	KNOT_RRSET_COMPARE_WHOLE
} knot_rrset_compare_type_t;

typedef enum  {
	KNOT_RRSET_DUPL_MERGE,
	KNOT_RRSET_DUPL_REPLACE,
	KNOT_RRSET_DUPL_SKIP
} knot_rrset_dupl_handling_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Creates a new RRSet with the given properties.
 *
 * The created RRSet contains no RDATAs (i.e. is actually empty).
 *
 * \param owner   OWNER of the RRSet.
 * \param type    TYPE of the RRSet.
 * \param rclass  CLASS of the RRSet.
 *
 * \return New RRSet structure or NULL if an error occured.
 */
knot_rrset_t *knot_rrset_new(knot_dname_t *owner, uint16_t type,
                             uint16_t rclass,
                             mm_ctx_t *mm);

/*!
 * \brief Creates a new RRSet according to given template RRSet.
 *
 * OWNER, TYPE, CLASS, and TTL values from template RRSet are used.
 *
 * \param tmp  RRSet template.
 *
 * \return New RRSet, NULL if an error occured.
 */
knot_rrset_t *knot_rrset_new_from(const knot_rrset_t *tpl, mm_ctx_t *mm);

/*!
 * \brief Adds the given RDATA to the RRSet.
 *
 * \param rrset  RRSet to add the RDATA to.
 * \param rdata  RDATA to add to the RRSet.
 * \param size   Size of RDATA.
 * \param size   TTL for RR.
 * \param mm     Memory context.
 *
 * \return KNOT_E*
 */
int knot_rrset_add_rr(knot_rrset_t *rrset, const uint8_t *rdata,
                      const uint16_t size, const uint32_t ttl,
                      mm_ctx_t *mm);

/*!
 * \brief Creates RDATA memory and returns a pointer to it.
 *        If the RRSet is not empty, function will return a memory
 *        pointing to a beginning of a new RR.
 *
 * \param rrset  RRSet to add the RDATA to.
 * \param size   Size of RR RDATA (Size in internal representation)
 * \param mm     Memory context.
 *
 * \retval  Pointer to memory to be written to.
 * \retval  NULL if arguments are invalid / no memory.
 */
uint8_t* knot_rrset_create_rr(knot_rrset_t *rrset, const uint16_t size,
                              const uint32_t ttl, mm_ctx_t *mm);

/*!
 * \brief Returns the Owner of the RRSet.
 *
 * \param rrset  RRSet to get the Owner of.
 *
 * \return Owner of the given RRSet.
 */
const knot_dname_t *knot_rrset_owner(const knot_rrset_t *rrset);

/*!
 * \brief Returns the Owner of the RRSet.
 *
 * \param rrset  RRSet to get the Owner of.
 *
 * \return Owner of the given RRSet.
 */
knot_dname_t *knot_rrset_get_owner(const knot_rrset_t *rrset);

/*!
 * \brief Set rrset owner to specified dname.
 *
 * Previous owner will be replaced if exist.
 *
 * \param rrset  Specified RRSet.
 * \param owner  New owner dname.
 */
int knot_rrset_set_owner(knot_rrset_t *rrset, const knot_dname_t *owner);

/*!
 * \brief Returns the TYPE of the RRSet.
 *
 * \param rrset  RRSet to get the TYPE of.
 *
 * \return TYPE  of the given RRSet.
 */
uint16_t knot_rrset_type(const knot_rrset_t *rrset);

/*!
 * \brief Returns the CLASS of the RRSet.
 *
 * \param rrset  RRSet to get the CLASS of.
 *
 * \return CLASS of the given RRSet.
 */
uint16_t knot_rrset_class(const knot_rrset_t *rrset);

/*!
 * \brief Returns RDATA of RR on given position.
 *
 * \param rrset  RRSet to get the RDATA from.
 * \param pos    Position of RR to get.
 *
 * \retval  NULL if no RDATA on rdata_pos exist.
 * \retval  Pointer to RDATA on given position if successfull.
 */
uint8_t *knot_rrset_rr_rdata(const knot_rrset_t *rrset, size_t pos);

/*!
 * \brief Returns size of an RR RDATA on a given position.
 *
 * \param rrset  RRSet holding RR RDATA.
 * \param pos    RR position.
 *
 * \return Item size.
 */
uint16_t knot_rrset_rr_size(const knot_rrset_t *rrset, size_t pos);

/*!
 * \brief Returns TTL of an RR on a given position.
 *
 * \param rrset  RRSet holding RR RDATA.
 * \param pos    RR position.
 *
 * \return TTL.
 */
uint32_t knot_rrset_rr_ttl(const knot_rrset_t *rrset, size_t pos);

/*!
 * \brief Sets TTL for RR on a given position.
 *
 * \param rrset  RRSet containing RR.
 * \param pos    RR position.
 * \param ttl    TTL to be set.
 */
void knot_rrset_rr_set_ttl(const knot_rrset_t *rrset, size_t pos, uint32_t ttl);

/*!
 * \brief Returns count of RRs in RRSet.
 *
 * \param rrset  RRSet.
 *
 * \return RR count.
 */
uint16_t knot_rrset_rr_count(const knot_rrset_t *rrset);

/*!
 * \brief Compares two RRSets for equality.
 *
 * \param r1   First RRSet.
 * \param r2   Second RRSet.
 * \param cmp  Type of comparison to perform.
 *
 * \retval True   if RRSets are equal.
 * \retval False  if RRSets are not equal.
 */
bool knot_rrset_equal(const knot_rrset_t *r1,
                      const knot_rrset_t *r2,
                      knot_rrset_compare_type_t cmp);

/*!
 * \brief Complete copy of RRSet structure.
 *
 * \param from  Source data.
 * \param to    Destionation data.
 * \param mm    Memory context.
 *
 * \return KNOT_E*
 */
int knot_rrset_copy(const knot_rrset_t *from, knot_rrset_t **to, mm_ctx_t *mm);

/*!
 * \brief Destroys the RRSet structure and all its substructures.
 )
 * Also sets the given pointer to NULL.
 *
 * \param rrset  RRset to be destroyed.
 * \param mm     Memory context.
 */
void knot_rrset_free(knot_rrset_t **rrset, mm_ctx_t *mm);

/*!
 * \brief Converts RRSet structure to wireformat, compression included.
 *
 * \param rrset     RRSet to be converted.
 * \param wire      Destination wire.
 * \param size      Output size.
 * \param max_size  Wire size.
 * \param rr_count  Output RR count.
 * \param compr     Compression data.
 *
 * \return KNOT_E*
 */
int knot_rrset_to_wire(const knot_rrset_t *rrset, uint8_t *wire, size_t *size,
                       size_t max_size, uint16_t *rr_count, struct knot_compr *compr);

/*!
 * \brief Merges two RRSets, no duplicate check is done, no sorting either.
 *
 * \param r1  Pointer to RRSet to be merged into.
 * \param r2  Pointer to RRSet to be merged.
 * \param mm  Memory context.
 *
 * \return KNOT_E*
 */
int knot_rrset_merge(knot_rrset_t *rrset1, const knot_rrset_t *rrset2,
                     mm_ctx_t *mm);

/*!
 * \brief Merges two RRSets, duplicate check is done, preserves canonical ordering.
 *
 * \param r1           Pointer to RRSet to be merged into.
 * \param r2           Pointer to RRSet to be merged.
 * \param merged       Count of merged RRs.
 * \param deleted_rrs  Count of deleted duplicated RRs.
 * \param mm           Memory context.
 *
 * \return KNOT_E*
 */
int knot_rrset_merge_sort(knot_rrset_t *rrset1, const knot_rrset_t *rrset2,
                          int *merged, int *deleted_rrs, mm_ctx_t *mm);

/*!
 * \brief Sort RDATA in RRSet to be in canonical order.
 * \todo Not optimal, rewrite!
 *
 * \param rrset  RRSet to be sorted.
 * \return Error code, KNOT_EOK when successful.
 */
int knot_rrset_sort_rdata(knot_rrset_t *rrset);

/*!
 * \brief Return true if the RRSet is an NSEC3 related type.
 *
 * \param rr RRSet.
 */
bool knot_rrset_is_nsec3rel(const knot_rrset_t *rr);

/*!
 * \brief Returns binary size of RRSet.
 *
 * \param rrset  RRSet.
 *
 * \return  Binary size.
 */
uint64_t rrset_binary_size(const knot_rrset_t *rrset);

/*!
 * \brief Serializes RRSet into given stream.
 *
 * \param rrset   RRSet to be serialized.
 * \param stream  Output stream
 * \param size    Size written.
 *
 * \return KNOT_E*
 */
int rrset_serialize(const knot_rrset_t *rrset, uint8_t *stream, size_t *size);

/*!
 * \brief Deserializes RRSet structure.
 *
 * \param stream       Input stream.
 * \param stream_size  Input stream size.
 * \param rrset        Output RRSet.
 *
 * \return KNOT_E*
 */
int rrset_deserialize(const uint8_t *stream, size_t *stream_size,
                      knot_rrset_t **rrset);

/*!
 * \brief Adds RR on 'pos' position from 'source' to 'dest'.
 *
 * \param dest       Destination RRSet.
 * \param source     Source RRSet.
 * \param rdata_pos  RR position from 'source' to add to 'dest'.
 * \param mm         Memory context.
 *
 * \return KNOT_E*
 */
int knot_rrset_add_rr_from_rrset(knot_rrset_t *dest, const knot_rrset_t *source,
                                 size_t rdata_pos, mm_ctx_t *mm);

/*!
 * \brief Removes RRs contained in 'what' RRSet from 'from' RRSet.
 *        Deleted RRs are returned in 'rr_deleted'.
 *
 * \param from        Delete from.
 * \param what        Delete what.
 * \param rr_deleted  Deleted RRs stored here.
 * \param mm          Memory context.
 *
 * \return KNOT_E*
 */
int knot_rrset_remove_rr_using_rrset(knot_rrset_t *from,
                                     const knot_rrset_t *what,
                                     knot_rrset_t **rr_deleted, mm_ctx_t *mm);

/*!
 * \brief Finds RR at 'pos' position in 'rr_reference' RRSet in
 *        'rr_search_in' RRSet. Position returned in 'pos_out'.
 *
 * \param rr_search_in  Search in this RRSet.
 * \param rr_reference  Use RR from this RRSet.
 * \param pos           Index for 'rr_reference'.
 * \param pos_out       If found, position returned here.
 *
 * \retval KNOT_EOK     if found, pos_out is set.
 * \retval KNOT_ENOENT  if not found.
 */
int knot_rrset_find_rr_pos(const knot_rrset_t *rr_search_in,
                           const knot_rrset_t *rr_reference, size_t pos,
                           size_t *pos_out);

 /*!
 * \brief Creates one RR from wire, stores it into 'rrset'
 *
 * \param rrset       Destination RRSet.
 * \param wire        Source wire.
 * \param pos         Position in wire.
 * \param total_size  Size of wire.
 * \param ttl         Use this TTL to create RR.
 * \param rdlength    RDLENGTH.
 * \param mm          Memory context.
 *
 * \return KNOT_E*
 */
int knot_rrset_rdata_from_wire_one(knot_rrset_t *rrset,
                                   const uint8_t *wire, size_t *pos,
                                   size_t total_size, uint32_t ttl, size_t rdlength,
                                   mm_ctx_t *mm);

/*!
 * \brief Checks whether the given type requires additional processing.
 *
 * Only MX, NS and SRV types require additional processing.
 *
 * \param rrtype Type to check.
 *
 * \retval <> 0 if additional processing is needed for \a qtype.
 * \retval 0 otherwise.
 */
int rrset_additional_needed(uint16_t rrtype);

/*!
 * \brief Creates RRSIG record from node RRSIGs for given RRSet.
 *
 * \param owner    Owner to use for the RRSIG.
 * \param type     Type to cover.
 * \param rrsigs   Node RRSIGs.
 * \param out_sig  Output RRSIG.
 * \param mm       Memory context.
 *
 * \return KNOT_E*
 */
int knot_rrset_synth_rrsig(const knot_dname_t *owner, uint16_t type,
                           const knot_rrset_t *rrsigs,
                           knot_rrset_t **out_sig, mm_ctx_t *mm);

#endif /* _KNOT_RRSET_H_ */

/*! @} */
