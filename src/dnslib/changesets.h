/*!
 * \file changesets.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Structure for representing IXFR/DDNS changeset and its API.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_CHANGESETS_H_
#define _KNOT_CHANGESETS_H_

#include "dnslib/rrset.h"

/*! \todo Changeset must be serializable/deserializable, so
 *        all data and pointers have to be changeset-exclusive,
 *        or more advanced structure serialization scheme has to be
 *        implemented.
 *
 * \todo Preallocation of space for changeset.
 */
typedef struct {
	knot_rrset_t *soa_from;
	knot_rrset_t **remove;
	size_t remove_count;
	size_t remove_allocated;

	knot_rrset_t *soa_to;
	knot_rrset_t **add;
	size_t add_count;
	size_t add_allocated;

	uint8_t *data;
	size_t size;
	size_t allocated;
	uint32_t serial_from;
	uint32_t serial_to;
} knot_changeset_t;

/*----------------------------------------------------------------------------*/

typedef struct {
	knot_changeset_t *sets;
	size_t count;
	size_t allocated;
} knot_changesets_t;

/*----------------------------------------------------------------------------*/

typedef enum {
	XFRIN_CHANGESET_ADD,
	XFRIN_CHANGESET_REMOVE
} xfrin_changeset_part_t;

/*----------------------------------------------------------------------------*/

int knot_changeset_allocate(knot_changesets_t **changesets);

int knot_changeset_add_rrset(knot_rrset_t ***rrsets,
                               size_t *count, size_t *allocated,
                               knot_rrset_t *rrset);

int knot_changeset_add_rr(knot_rrset_t ***rrsets, size_t *count,
                            size_t *allocated, knot_rrset_t *rr);

int knot_changeset_add_new_rr(knot_changeset_t *changeset,
                                knot_rrset_t *rrset,
                                xfrin_changeset_part_t part);

void knot_changeset_store_soa(knot_rrset_t **chg_soa,
                                uint32_t *chg_serial, knot_rrset_t *soa);

int knot_changeset_add_soa(knot_changeset_t *changeset, knot_rrset_t *soa,
                             xfrin_changeset_part_t part);

int knot_changesets_check_size(knot_changesets_t *changesets);

void knot_free_changesets(knot_changesets_t **changesets);

#endif /* _KNOT_CHANGESETS_H_ */

/*! @} */
