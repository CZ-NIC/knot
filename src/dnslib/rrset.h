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

#ifndef _CUTEDNS_DNSLIB_RRSET_H_
#define _CUTEDNS_DNSLIB_RRSET_H_

#include <stdint.h>

#include "dname.h"
#include "rdata.h"
#include "common.h"

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

	/*! \brief RRSet containing signatures for this RRSet. */
	const struct dnslib_rrset *rrsigs;
	/*! 
	 * \brief First signature for this RRSet 
	 *        (its RDATA portion actually). 
	 */
	const dnslib_rdata_t *first;
	/*!
	 * \brief Number of signatures for this RRSet.
	 *
	 * \note We can do this because the RDATAs withing an RRSet are ordered
	 *       so that RRSIGs for one RRSet are consecutive.
	 */
	uint rrsig_count;
};

typedef struct dnslib_rrset dnslib_rrset_t;

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
 * \retval 0 if successful.
 * \retval -2 if either rrset or rdata was equal to NULL.
 *
 * \todo Provide some function for comparing RDATAs.
 */
int dnslib_rrset_add_rdata(dnslib_rrset_t *rrset, dnslib_rdata_t *rdata);

/*!
 * \brief Stores information about the RRSIG signatures for the RRSet.
 *
 * \param rrset RRSet to store information about signatures for.
 * \param rrsigs RRSet containing the RRSIGs covering this RRset.
 * \param first RDATA of the first RRSIG covering this RRSet in the appropriate
 *              cyclic list of RDATAs.
 * \param count Number of RRISGs covering this RRSet.
 *
 * \retval 0 if successful.
 * \retval <> 0 if an error occured.
 *
 * \todo Modify return values in comment to reflect the implementation.
 * \todo Return value may be unneccessary. Change to void if so.
 */
int dnslib_rrset_set_rrsigs(dnslib_rrset_t *rrset,
                            const dnslib_rrset_t *rrsigs,
                            const dnslib_rdata_t *first, uint count);

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

/*!
 * \brief Returns the RRSet holding RRSIGs covering the given RRSet.
 *
 * \param rrset RRSet to get the signatures for.
 *
 * \return RRSet holding RRSIGs which cover the given RRSet.
 */
const dnslib_rrset_t *dnslib_rrset_rrsigs(const dnslib_rrset_t *rrset);

/*!
 * \brief Returns the RDATA of the first RRSIG covering the given RRSet.
 *
 * \param rrset RRSet to get the first RRSIG for.
 *
 * \return RDATA of the first RRSIG covering the given RRSet.
 */
const dnslib_rdata_t *dnslib_rrset_rrsig_first(const dnslib_rrset_t *rrset);

/*!
 * \brief Returns the count of the RRSIGs covering the given RRSet.
 *
 * \param rrset RRSet to get the count of signatures of.
 *
 * \return Count of the RRSIGs covering the given RRSet.
 */
uint dnslib_rrset_rrsig_count(const dnslib_rrset_t *rrset);

/*!
 * \brief Destroys the RRSet structure.
 *
 * Does not destroy the OWNER domain name structure, nor the signatures, as
 * these may be used elsewhere. This is however a higher-level logic, so maybe
 * a parameter for deciding what to destroy would be better.
 *
 * Does not destroy RDATA structures neither, as they need special processing -
 * their items are not destroyed in dnslib_rdata_free(), so this would be
 * confusing.
 *
 * Also sets the given pointer to NULL.
 *
 * \param rrset RRset to be destroyed.
 */
void dnslib_rrset_free(dnslib_rrset_t **rrset);

/*!
 * \brief Merges two RRSets.
 *
 * Merges \a r1 into \a r2 by concatenating the list of RDATAs in \a r2 after
 * the list of RDATAs in \a r1. \a r2 is unaffected by this, though you must not
 * destroy the RDATAs in \a r2 as they are now also in \a r1. (You may use
 * function dnslib_rrset_free() though, as it does not touch RDATAs).
 *
 * \note Members \a rrsigs, \a first and \a rrsig_count are not checked for
 *       match, members from the first RRSet are preserved.
 *
 * \param r1 Pointer to RRSet to be merged into.
 * \param r2 Poitner to RRSet to be merged.
 *
 * \retval 0 on success.
 * \retval -1 if the RRSets could not be merged, because their Owner, Type,
 *            Class or TTL does not match.
 */
int dnslib_merge_rrsets(void **r1, void **r2);

#endif /* _CUTEDNS_DNSLIB_RRSET_H_ */

/*! @} */
