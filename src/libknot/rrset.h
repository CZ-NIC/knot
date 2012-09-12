/*!
 * \file rrset.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief RRSet structure and API for manipulating it.
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

#ifndef _KNOT_RRSET_H_
#define _KNOT_RRSET_H_

#include <stdint.h>

#include "dname.h"
#include "rdata.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure for representing an RRSet.
 *
 * For definition of a RRSet see RFC2181, Section 5.
 *
 * As all RRs within a RRSet share the same OWNER, TYPE, CLASS and TTL (see
 * Section 5.2 of RFC2181), there is no need to duplicate these data in the
 * program. Distinct Resource Records are thus represented only as distinct
 * RDATA sections of corresponding RRs.
 */
struct knot_rrset {
	/*! \brief Domain name being the owner of the RRSet. */
	knot_dname_t *owner;
	uint16_t type; /*!< TYPE of the RRset. */
	uint16_t rclass; /*!< CLASS of the RRSet. */
	uint32_t ttl; /*!< TTL of the RRSet. */
	/*!
	 * \brief First item in an ordered cyclic list of RDATA items.
	 *
	 * \note The fact that the list is cyclic will easily allow for
	 *       possible round-robin rotation of RRSets.
	 */
	knot_rdata_t *rdata;
	struct knot_rrset *rrsigs; /*!< Set of RRSIGs covering this RRSet. */
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
 * \param owner OWNER of the RRSet.
 * \param type TYPE of the RRSet.
 * \param rclass CLASS of the RRSet.
 * \param ttl TTL of the RRset.
 *
 * \return New RRSet structure with the given OWNER, TYPE, CLASS and TTL or NULL
 *         if an error occured.
 */
knot_rrset_t *knot_rrset_new(knot_dname_t *owner, uint16_t type,
                                 uint16_t rclass, uint32_t ttl);

/*!
 * \brief Adds the given RDATA to the RRSet.
 *
 * \param rrset RRSet to add the RDATA to.
 * \param rdata RDATA to add to the RRSet.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 *
 * \todo Provide some function for comparing RDATAs.
 */
int knot_rrset_add_rdata(knot_rrset_t *rrset, knot_rdata_t *rdata);

/*!
 * \brief Adds the given RDATA to the RRSet but will not insert duplicated data.
 *
 * \warning Should be only used to insert one RDATA. (NO lists)
 *
 * \param rrset RRSet to add the RDATA to.
 * \param rdata RDATA to add to the RRSet.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 *
 * \todo Provide some function for comparing RDATAs.
 */
int knot_rrset_add_rdata_order(knot_rrset_t *rrset, knot_rdata_t *rdata);

knot_rdata_t * knot_rrset_remove_rdata(knot_rrset_t *rrset,
                                           const knot_rdata_t *rdata);

/*!
 * \brief Adds RRSIG signatures to this RRSet.
 *
 * \param rrset RRSet to add the signatures into.
 * \param rrsigs Set of RRSIGs covering this RRSet.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int knot_rrset_set_rrsigs(knot_rrset_t *rrset, knot_rrset_t *rrsigs);

int knot_rrset_add_rrsigs(knot_rrset_t *rrset, knot_rrset_t *rrsigs,
                            knot_rrset_dupl_handling_t dupl);

/*!
 * \brief Returns the Owner of the RRSet.
 *
 * \param rrset RRSet to get the Owner of.
 *
 * \return Owner of the given RRSet.
 */
const knot_dname_t *knot_rrset_owner(const knot_rrset_t *rrset);

/*!
 * \todo Document me.
 */
knot_dname_t *knot_rrset_get_owner(const knot_rrset_t *rrset);

/*!
 * \brief Set rrset owner to specified dname.
 *
 * Previous owner will be replaced if exist.
 *
 * \param rrset Specified RRSet.
 * \param owner New owner dname.
 */
void knot_rrset_set_owner(knot_rrset_t *rrset, knot_dname_t* owner);

void knot_rrset_set_ttl(knot_rrset_t *rrset, uint32_t ttl);

/*!
 * \brief Returns the TYPE of the RRSet.
 *
 * \param rrset RRSet to get the TYPE of.
 *
 * \return TYPE of the given RRSet.
 */
uint16_t knot_rrset_type(const knot_rrset_t *rrset);

/*!
 * \brief Returns the CLASS of the RRSet.
 *
 * \param rrset RRSet to get the CLASS of.
 *
 * \return CLASS of the given RRSet.
 */
uint16_t knot_rrset_class(const knot_rrset_t *rrset);

/*!
 * \brief Returns the TTL of the RRSet.
 *
 * \param rrset RRSet to get the TTL of.
 *
 * \return TTL of the given RRSet.
 */
uint32_t knot_rrset_ttl(const knot_rrset_t *rrset);

/*!
 * \brief Returns the first RDATA in the RRSet.
 *
 * RDATAs in a RRSet are stored in a ordered cyclic list.
 *
 * \note If later a round-robin rotation of RRSets is employed, the RDATA
 *       returned by this function may not be the first RDATA in canonical
 *       order.
 *
 * \param rrset RRSet to get the RDATA from.
 *
 * \return First RDATA in the given RRSet.
 */
const knot_rdata_t *knot_rrset_rdata(const knot_rrset_t *rrset);

const knot_rdata_t *knot_rrset_rdata_next(const knot_rrset_t *rrset,
                                              const knot_rdata_t *rdata);

/*!
 * \brief Returns the first RDATA in the RRSet (non-const version).
 *
 * RDATAs in a RRSet are stored in a ordered cyclic list.
 *
 * \note If later a round-robin rotation of RRSets is employed, the RDATA
 *       returned by this function may not be the first RDATA in canonical
 *       order.
 *
 * \param rrset RRSet to get the RDATA from.
 *
 * \return First RDATA in the given RRSet or NULL if there is none or if no
 *         rrset was provided (\a rrset is NULL).
 */
knot_rdata_t *knot_rrset_get_rdata(knot_rrset_t *rrset);

knot_rdata_t *knot_rrset_rdata_get_next(knot_rrset_t *rrset,
                                            knot_rdata_t *rdata);

int knot_rrset_rdata_rr_count(const knot_rrset_t *rrset);

/*!
 * \brief Returns the set of RRSIGs covering the given RRSet.
 *
 * \param rrset RRSet to get the signatures for.
 *
 * \return Set of RRSIGs which cover the given RRSet or NULL if there is none or
 *         if no rrset was provided (\a rrset is NULL).
 */
const knot_rrset_t *knot_rrset_rrsigs(const knot_rrset_t *rrset);

knot_rrset_t *knot_rrset_get_rrsigs(knot_rrset_t *rrset);

int knot_rrset_compare_rdata(const knot_rrset_t *r1, const knot_rrset_t *r2);

int knot_rrset_to_wire(const knot_rrset_t *rrset, uint8_t *wire, size_t *size,
                       int *rr_count);

/*!
 * \brief Compares two RRSets.
 *
 * \note This function does not return 'standard' compare return values, because
 *       there is no way to define which RRSet is 'larger'.
 *
 * \param r1 First RRSet.
 * \param r2 Second RRSet.
 * \param cmp Type of comparison to perform.
 *
 * \retval <> 0 If RRSets are equal.
 * \retval 0 if RRSets are not equal.
 */
int knot_rrset_compare(const knot_rrset_t *r1,
                         const knot_rrset_t *r2,
                         knot_rrset_compare_type_t cmp);

/*! \todo Add unit test. */
int knot_rrset_deep_copy(const knot_rrset_t *from, knot_rrset_t **to,
                         int copy_rdata_dnames);

/*! \todo Add unit test. */
int knot_rrset_shallow_copy(const knot_rrset_t *from, knot_rrset_t **to);

/*! \brief Does round-robin rotation of the RRSet.
 *
 * \note This is not thread-safe. If two threads call this function, the RRSet
 *       may rotate twice, or not rotate at all. This is not a big issue though.
 *       In future we may replace this with some per-thread counter.
 */
void knot_rrset_rotate(knot_rrset_t *rrset);

/*!
 * \brief Destroys the RRSet structure.
 *
 * Does not destroy the OWNER domain name structure, nor the signatures, as
 * these may be used elsewhere.
 *
 * Does not destroy RDATA structures neither, as they need special processing.
 *
 * Also sets the given pointer to NULL.
 *
 * \param rrset RRset to be destroyed.
 */
void knot_rrset_free(knot_rrset_t **rrset);

/*!
 * \brief Destroys the RRSet structure and all its substructures.
 *
 * Also sets the given pointer to NULL.
 *
 * \param rrset RRset to be destroyed.
 * \param free_owner Set to 0 if you do not want the owner domain name to be
 *                   destroyed also. Set to <> 0 otherwise.
 * \param free_rdata ***\todo DOCUMENT ME***
 * \param free_rdata_dnames Set to <> 0 if you want to delete ALL domain names
 *                          present in RDATA. Set to 0 otherwise. (See
 *                          knot_rdata_deep_free().)
 */
void knot_rrset_deep_free(knot_rrset_t **rrset, int free_owner,
                            int free_rdata, int free_rdata_dnames);

/*!
 * \brief Merges two RRSets.
 *
 * Merges \a r1 into \a r2 by concatenating the list of RDATAs in \a r2 after
 * the list of RDATAs in \a r1. You must not
 * destroy the RDATAs in \a r2 as they are now identical to RDATAs in \a r1.
 * (You may use function knot_rrset_free() though, as it does not touch RDATAs).
 *
 * \note Member \a rrsigs is preserved from the first RRSet.
 *
 * \param r1 Pointer to RRSet to be merged into.
 * \param r2 Poitner to RRSet to be merged.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL if the RRSets could not be merged, because their
 *         Owner, Type, Class or TTL does not match.
 */
int knot_rrset_merge(void **r1, void **r2);


/*!
 * \brief Merges two RRSets, but will discard and free any duplicates in \a r2.
 *
 * Merges \a r1 into \a r2 by concatenating the list of RDATAs in \a r2 after
 * the list of RDATAs in \a r1. You must not
 * destroy the RDATAs in \a r2 as they are now identical to RDATAs in \a r1.
 * (You may use function knot_rrset_free() though, as it does not touch RDATAs).
 *
 * \note Member \a rrsigs is preserved from the first RRSet.
 *
 * \param r1 Pointer to RRSet to be merged into.
 * \param r2 Poitner to RRSet to be merged.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL if the RRSets could not be merged, because their
 *         Owner, Type, Class or TTL does not match.
 */
int knot_rrset_merge_no_dupl(void **r1, void **r2);

#endif /* _KNOT_RRSET_H_ */

/*! @} */
