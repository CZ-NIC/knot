/*!
 * \file rrsig.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Structure for holding RRSIGs and API for manipulating it.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_RRSIG_H_
#define _KNOT_DNSLIB_RRSIG_H_

#include <stdint.h>

#include "dnslib/dname.h"
#include "dnslib/rdata.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure for representing a set of RRSIG records covering one RRSet.
 *
 * RRSIGs covering one RRSet share the same Owner, Type, Class and TTL (TTL must
 * be the same as the TTL of the covered RRSet) and can be thus put in one
 * structure sharing this fields. The structure is similar to dnslib_rrset,
 * but lacks reference.
 */
struct dnslib_rrsig_set {
	/*! \brief Domain name being the owner of this set of RRSIGs. */
	dnslib_dname_t *owner;
	uint16_t type; /*!< TYPE of these RRSIGs. */
	uint16_t rclass; /*!< CLASS of these RRSIGs. */
	/*!
	 * \brief TTL of these RRSIGs. Should be the same as the TTL of the
	 *        covered RRSet.
	 */
	uint32_t ttl;
	/*!
	 * \brief First item in an ordered cyclic list of RRSIG RDATAs.
	 */
	dnslib_rdata_t *rdata;
};

typedef struct dnslib_rrsig_set dnslib_rrsig_set_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates a new set of RRSIGs with the given properties.
 *
 * The created set contains no RDATAs (i.e. is actually empty).
 *
 * \param owner OWNER of the set of RRSIGs.
 * \param type TYPE of the set of RRSIGs.
 * \param rclass CLASS of the set of RRSIGs.
 * \param ttl TTL of the set of RRSIGs.
 *
 * \return New RRSIG set structure with the given OWNER, TYPE, CLASS and TTL or
 *         NULL if an error occured.
 */
dnslib_rrsig_set_t *dnslib_rrsig_set_new(dnslib_dname_t *owner, uint16_t type,
                                         uint16_t rclass, uint32_t ttl);

/*!
 * \brief Adds the given RDATA to the RRSIG set.
 *
 * \param rrsigs RRSIG set to add the RDATA to.
 * \param rdata RDATA to add to the RRSIG set.
 *
 * \retval 0 if successful.
 * \retval -1 if either rrsigs or rdata was equal to NULL.
 *
 * \todo Provide some function for comparing RDATAs.
 */
int dnslib_rrsig_set_add_rdata(dnslib_rrsig_set_t *rrsigs,
                               dnslib_rdata_t *rdata);

/*!
 * \brief Returns the TYPE of the RRSIG set.
 *
 * \param rrset RRSIG set to get the TYPE of.
 *
 * \return TYPE of the given RRSIG set.
 */
uint16_t dnslib_rrsig_set_type(const dnslib_rrsig_set_t *rrsigs);

/*!
 * \brief Returns the CLASS of the RRSIG set.
 *
 * \param rrset RRSIG set to get the CLASS of.
 *
 * \return CLASS of the given RRSIG set.
 */
uint16_t dnslib_rrsig_set_class(const dnslib_rrsig_set_t *rrsigs);

/*!
 * \brief Returns the TTL of the RRSIG set.
 *
 * \param rrset RRSIG set to get the TTL of.
 *
 * \return TTL of the given RRSIG set.
 */
uint32_t dnslib_rrsig_set_ttl(const dnslib_rrsig_set_t *rrsigs);

/*!
 * \brief Returns the first RDATA in the RRSIG set.
 *
 * RDATAs in a RRSIG set are stored in a ordered cyclic list.
 *
 * \param rrset RRSIG set to get the RDATA from.
 *
 * \return First RDATA in the given RRSIG set.
 */
const dnslib_rdata_t *dnslib_rrsig_set_rdata(const dnslib_rrsig_set_t *rrsigs);

/*!
 * \brief Destroys the RRSIG set structure.
 *
 * Does not destroy the OWNER domain name structure.
 *
 * Does not destroy RDATA structures neither, as they need special processing.
 *
 * Also sets the given pointer to NULL.
 *
 * \param rrsigs RRSIG set to be destroyed.
 */
void dnslib_rrsig_set_free(dnslib_rrsig_set_t **rrsigs);

/*!
 * \brief Destroys the RRSIG set structure and all its substructures.
 *
 * Also sets the given pointer to NULL.
 *
 * \param rrsigs RRSIG set to be destroyed.
 * \param free_owner Set to 0 if you do not want the owner domain name to be
 *                   destroyed also. Set to <> 0 otherwise.
 */
void dnslib_rrsig_set_deep_free(dnslib_rrsig_set_t **rrsigs, int free_owner,
                                int free_all_dnames);

/*!
 * \brief Merges two RRSIGs.
 *
 * Merges \a r1 into \a r2 by concatenating the list of RDATAs in \a r2 after
 * the list of RDATAs in \a r1. \a r2 is unaffected by this, though you must not
 * destroy the RDATAs in \a r2 as they are now also in \a r1. (You may use
 * function dnslib_rrset_free() though, as it does not touch RDATAs).
 *
 * \note Member \a rrsigs is preserved from the first RRSet.
 *
 * \param r1 Pointer to RRSIG to be merged into.
 * \param r2 Poitner to RRSIG to be merged.
 *
 * \retval 0 on success.
 * \retval -1 if the RRSIGs could not be merged, because their Owner, Type,
 *         Class or TTL does not match.
 */
int dnslib_rrsig_set_merge(void **r1, void **r2);

#endif /* _KNOT_DNSLIB_RRSIG_H_ */

/*! @} */
