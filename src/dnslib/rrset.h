/*!
 * \file rrset.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief RRSet structure and API for manipulating it.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_RRSET_H_
#define _KNOT_DNSLIB_RRSET_H_

#include <stdint.h>

#include "dnslib/dname.h"
#include "dnslib/rdata.h"

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
struct dnslib_rrset {
	/*! \brief Domain name being the owner of the RRSet. */
	dnslib_dname_t *owner;
	uint16_t type; /*!< TYPE of the RRset. */
	uint16_t rclass; /*!< CLASS of the RRSet. */
	uint32_t ttl; /*!< TTL of the RRSet. */
	/*!
	 * \brief First item in an ordered cyclic list of RDATA items.
	 *
	 * \note The fact that the list is cyclic will easily allow for
	 *       possible round-robin rotation of RRSets.
	 */
	dnslib_rdata_t *rdata;
	struct dnslib_rrset *rrsigs; /*!< Set of RRSIGs covering this RRSet. */
};

typedef struct dnslib_rrset dnslib_rrset_t;

/*----------------------------------------------------------------------------*/

typedef enum {
	DNSLIB_RRSET_COMPARE_PTR,
	DNSLIB_RRSET_COMPARE_HEADER,
	DNSLIB_RRSET_COMPARE_WHOLE
} dnslib_rrset_compare_type_t;

typedef enum  {
	DNSLIB_RRSET_DUPL_MERGE,
	DNSLIB_RRSET_DUPL_REPLACE,
	DNSLIB_RRSET_DUPL_SKIP
} dnslib_rrset_dupl_handling_t;

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
dnslib_rrset_t *dnslib_rrset_new(dnslib_dname_t *owner, uint16_t type,
                                 uint16_t rclass, uint32_t ttl);

/*!
 * \brief Adds the given RDATA to the RRSet.
 *
 * \param rrset RRSet to add the RDATA to.
 * \param rdata RDATA to add to the RRSet.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 *
 * \todo Provide some function for comparing RDATAs.
 */
int dnslib_rrset_add_rdata(dnslib_rrset_t *rrset, dnslib_rdata_t *rdata);

dnslib_rdata_t * dnslib_rrset_remove_rdata(dnslib_rrset_t *rrset,
                                           const dnslib_rdata_t *rdata);

/*!
 * \brief Adds RRSIG signatures to this RRSet.
 *
 * \param rrset RRSet to add the signatures into.
 * \param rrsigs Set of RRSIGs covering this RRSet.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 */
int dnslib_rrset_set_rrsigs(dnslib_rrset_t *rrset, dnslib_rrset_t *rrsigs);

int dnslib_rrset_add_rrsigs(dnslib_rrset_t *rrset, dnslib_rrset_t *rrsigs,
                            dnslib_rrset_dupl_handling_t dupl);

/*!
 * \brief Returns the Owner of the RRSet.
 *
 * \param rrset RRSet to get the Owner of.
 *
 * \return Owner of the given RRSet.
 */
const dnslib_dname_t *dnslib_rrset_owner(const dnslib_rrset_t *rrset);

dnslib_dname_t *dnslib_rrset_get_owner(const dnslib_rrset_t *rrset);

/*!
 * \brief Returns the TYPE of the RRSet.
 *
 * \param rrset RRSet to get the TYPE of.
 *
 * \return TYPE of the given RRSet.
 */
uint16_t dnslib_rrset_type(const dnslib_rrset_t *rrset);

/*!
 * \brief Returns the CLASS of the RRSet.
 *
 * \param rrset RRSet to get the CLASS of.
 *
 * \return CLASS of the given RRSet.
 */
uint16_t dnslib_rrset_class(const dnslib_rrset_t *rrset);

/*!
 * \brief Returns the TTL of the RRSet.
 *
 * \param rrset RRSet to get the TTL of.
 *
 * \return TTL of the given RRSet.
 */
uint32_t dnslib_rrset_ttl(const dnslib_rrset_t *rrset);

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
const dnslib_rdata_t *dnslib_rrset_rdata(const dnslib_rrset_t *rrset);

const dnslib_rdata_t *dnslib_rrset_rdata_next(const dnslib_rrset_t *rrset,
                                              const dnslib_rdata_t *rdata);

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
dnslib_rdata_t *dnslib_rrset_get_rdata(dnslib_rrset_t *rrset);

dnslib_rdata_t *dnslib_rrset_rdata_get_next(dnslib_rrset_t *rrset,
                                            dnslib_rdata_t *rdata);

/*!
 * \brief Returns the set of RRSIGs covering the given RRSet.
 *
 * \param rrset RRSet to get the signatures for.
 *
 * \return Set of RRSIGs which cover the given RRSet or NULL if there is none or
 *         if no rrset was provided (\a rrset is NULL).
 */
const dnslib_rrset_t *dnslib_rrset_rrsigs(const dnslib_rrset_t *rrset);

dnslib_rrset_t *dnslib_rrset_get_rrsigs(dnslib_rrset_t *rrset);

int dnslib_rrset_compare(const dnslib_rrset_t *r1,
                         const dnslib_rrset_t *r2,
                         dnslib_rrset_compare_type_t cmp);

int dnslib_rrset_copy(const dnslib_rrset_t *from, dnslib_rrset_t **to);

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
void dnslib_rrset_free(dnslib_rrset_t **rrset);

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
 *                          dnslib_rdata_deep_free().)
 */
void dnslib_rrset_deep_free(dnslib_rrset_t **rrset, int free_owner,
                            int free_rdata, int free_rdata_dnames);

/*!
 * \brief Merges two RRSets.
 *
 * Merges \a r1 into \a r2 by concatenating the list of RDATAs in \a r2 after
 * the list of RDATAs in \a r1. \a r2 is unaffected by this, though you must not
 * destroy the RDATAs in \a r2 as they are now also in \a r1. (You may use
 * function dnslib_rrset_free() though, as it does not touch RDATAs).
 *
 * \note Member \a rrsigs is preserved from the first RRSet.
 *
 * \param r1 Pointer to RRSet to be merged into.
 * \param r2 Poitner to RRSet to be merged.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG if the RRSets could not be merged, because their
 *         Owner, Type, Class or TTL does not match.
 */
int dnslib_rrset_merge(void **r1, void **r2);

#endif /* _KNOT_DNSLIB_RRSET_H_ */

/*! @} */
