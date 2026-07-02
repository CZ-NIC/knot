/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief RRSet structure and API for manipulating it.
 *
 * \addtogroup rr
 * @{
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "libknot/dname.h"
#include "libknot/descriptor.h"
#include "libknot/mm_ctx.h"
#include "libknot/rdataset.h"

/*!
 * \brief Structure for representing RRSet.
 *
 * For RRSet definition see RFC2181, Section 5.
 */
typedef struct {
	knot_dname_t *owner;  /*!< Domain name being the owner of the RRSet. */
	uint32_t ttl;         /*!< TTL of the RRset. */
	uint16_t type;        /*!< TYPE of the RRset. */
	uint16_t rclass;      /*!< CLASS of the RRSet. */
	knot_rdataset_t rrs;  /*!< RRSet's RRs */
	/* Optional fields. */
	void *additional;     /*!< Additional records. */
} knot_rrset_t;

/*!< \brief Required static rrset buffer size for specified rdata length (reused owner pointer). */
#define KNOT_RRSET_STATIC_BUFSIZE(rdlen)              (KNOT_PTR_ALIGN_MAX + sizeof(knot_rrset_t) + knot_rdata_size(rdlen))
/*!< \brief Required static rrset buffer size for specified rdata length (copied owner). */
#define KNOT_RRSET_STATIC_OWNER_BUFSIZE(owner, rdlen) (knot_dname_size(owner) + KNOT_RRSET_STATIC_BUFSIZE(rdlen))
/*!< \brief Required static rrset buffer size for specified rdata length (maximum possible owner). */
#define KNOT_RRSET_STATIC_OWMAX_BUFSIZE(rdlen)        (KNOT_DNAME_MAXLEN + KNOT_RRSET_STATIC_BUFSIZE(rdlen))

/*!
 * \brief Creates a new RRSet with the given properties.
 *
 * The created RRSet contains no RDATAs (i.e. is actually empty).
 *
 * \param owner   OWNER of the RRSet.
 * \param type    TYPE of the RRSet.
 * \param rclass  CLASS of the RRSet.
 * \param ttl     TTL of the RRSet.
 * \param mm      Memory context.
 *
 * \return New RRSet structure or NULL if an error occurred.
 */
knot_rrset_t *knot_rrset_new(const knot_dname_t *owner, uint16_t type,
                             uint16_t rclass, uint32_t ttl, knot_mm_t *mm);

/*!
 * \brief Initializes RRSet structure with given data.
 *
 * \param rrset   RRSet to init.
 * \param owner   RRSet owner to use.
 * \param type    RR type to use.
 * \param rclass  Class to use.
 * \param ttl     TTL to use.
 */
inline static void knot_rrset_init(knot_rrset_t *rrset, knot_dname_t *owner,
                                   uint16_t type, uint16_t rclass, uint32_t ttl)
{
	if (rrset != NULL) {
		rrset->owner = owner;
		rrset->type = type;
		rrset->rclass = rclass;
		rrset->ttl = ttl;
		knot_rdataset_init(&rrset->rrs);
		rrset->additional = NULL;
	}
}

/*!
 * \brief Initializes given RRSet structure.
 *
 * \param rrset  RRSet to init.
 */
inline static void knot_rrset_init_empty(knot_rrset_t *rrset)
{
	knot_rrset_init(rrset, NULL, 0, KNOT_CLASS_IN, 0);
}

/*!
 * \brief Create a static 1-record RRset structure in a given buffer.
 *
 * \note Class is set to KNOT_CLASS_IN.
 *
 * \param buf         Auxiliary buffer.
 * \param bufsize     Auxiliary buffer size.
 * \param owner       RRset owner name to be used as pointer.
 * \param type        RRset type.
 * \param ttl         RRset TTL.
 * \param rdata       Single RR rdata to be added.
 * \param rdlen       Rdata length.
 * \param copy_owner  Copy owner indication.
 *
 * \return Pointer to resulting RRset inside the buffer or NULL.
 */
knot_rrset_t *knot_rrset_static(uint8_t *buf, size_t bufsize, knot_dname_t *owner,
                                uint16_t type, uint32_t ttl, const uint8_t *rdata,
                                uint16_t rdlen, bool copy_owner);

/*!
 * \brief Creates new RRSet from \a src RRSet.
 *
 * \param src  Source RRSet.
 * \param mm   Memory context.
 *
 * \retval Pointer to new RRSet if all went OK.
 * \retval NULL on error.
 */
knot_rrset_t *knot_rrset_copy(const knot_rrset_t *src, knot_mm_t *mm);

/*!
 * \brief Destroys the RRSet structure and all its substructures.
 *
 * \param rrset  RRset to be destroyed.
 * \param mm     Memory context.
 */
void knot_rrset_free(knot_rrset_t *rrset, knot_mm_t *mm);

/*!
 * \brief Frees structures inside RRSet, but not the RRSet itself.
 *
 * \param rrset  RRSet to be cleared.
 * \param mm     Memory context used for allocations.
 */
void knot_rrset_clear(knot_rrset_t *rrset, knot_mm_t *mm);

/*!
 * \brief Adds the given RDATA to the RRSet.
 *
 * \param rrset  RRSet to add the RDATA to.
 * \param data   RDATA to add to the RRSet.
 * \param len    Length of RDATA.
 * \param mm     Memory context.
 *
 * \return KNOT_E*
 */
int knot_rrset_add_rdata(knot_rrset_t *rrset, const uint8_t *data, uint16_t len,
                         knot_mm_t *mm);

/*!
 * \brief Compares two RRSets for equality.
 *
 * \param r1   First RRSet.
 * \param r2   Second RRSet.
 * \param incl_ttl  Compare also TTLs for equality.
 *
 * \retval True   if RRSets are equal.
 * \retval False  if RRSets are not equal.
 */
bool knot_rrset_equal(const knot_rrset_t *r1, const knot_rrset_t *r2,
                      bool incl_ttl);

/*!
 * \brief Checks whether RRSet is empty.
 *
 * \param rrset  RRSet to check.
 *
 * \retval True if RRSet is empty.
 * \retval False if RRSet is not empty.
 */
inline static bool knot_rrset_empty(const knot_rrset_t *rrset)
{
	return rrset == NULL || rrset->rrs.count == 0;
}

/*!
 * \brief Return whether the RR type is NSEC3 related (NSEC3 or RRSIG).
 */
bool knot_rrset_is_nsec3rel(const knot_rrset_t *rr);

/*!
 * \brief Converts RRSet with one RR into canonical format.
 *
 * The RRSet owner is always converted to lowercase.
 *
 * \note See knot_rdata_to_canonical() for more details.
 *
 * \param rrset  RRSet to convert.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_rrset_rr_to_canonical(knot_rrset_t *rrset);

/*!
 * \brief Size of rrset in wire format (without compression).
 *
 * \retval size in bytes
 */
size_t knot_rrset_size(const knot_rrset_t *rrset);

/*!
 * \brief Fast estimate of knot_rrset_size(); it can return slightly larger values.
 */
inline static size_t knot_rrset_size_estimate(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	/* 8B = TYPE + CLASS + TTL + RDLENGTH - sizeof(knot_rdata_t::len)
	 * We over-estimate by the count of padding bytes (<= rrset->rrs.count) */
	size_t estim = rrset->rrs.size
		+ rrset->rrs.count * (knot_dname_size(rrset->owner) + 8);

	return estim;
}

/*! @} */
