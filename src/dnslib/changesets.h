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

#ifndef _KNOT_DNSLIB_CHANGESETS_H_
#define _KNOT_DNSLIB_CHANGESETS_H_

#include "dnslib/rrset.h"

/*! \todo Changeset must be serializable/deserializable, so
 *        all data and pointers have to be changeset-exclusive,
 *        or more advanced structure serialization scheme has to be
 *        implemented.
 *
 * \todo Preallocation of space for changeset.
 */
typedef struct {
	dnslib_rrset_t *soa_from;
	dnslib_rrset_t **remove;
	size_t remove_count;
	size_t remove_allocated;

	dnslib_rrset_t *soa_to;
	dnslib_rrset_t **add;
	size_t add_count;
	size_t add_allocated;

	uint8_t *data;
	size_t size;
	size_t allocated;
	uint32_t serial_from;
	uint32_t serial_to;
} dnslib_changeset_t;

/*----------------------------------------------------------------------------*/

typedef struct {
	dnslib_changeset_t *sets;
	size_t count;
	size_t allocated;
} dnslib_changesets_t;

/*----------------------------------------------------------------------------*/

typedef enum {
	XFRIN_CHANGESET_ADD,
	XFRIN_CHANGESET_REMOVE
} xfrin_changeset_part_t;

/*----------------------------------------------------------------------------*/

int dnslib_changeset_allocate(dnslib_changesets_t **changesets);

int dnslib_changeset_add_rrset(dnslib_rrset_t ***rrsets,
                               size_t *count, size_t *allocated,
                               dnslib_rrset_t *rrset);

int dnslib_changeset_add_rr(dnslib_rrset_t ***rrsets, size_t *count,
                            size_t *allocated, dnslib_rrset_t *rr);

int dnslib_changeset_add_new_rr(dnslib_changeset_t *changeset,
                                dnslib_rrset_t *rrset,
                                xfrin_changeset_part_t part);

void dnslib_changeset_store_soa(dnslib_rrset_t **chg_soa,
                                uint32_t *chg_serial, dnslib_rrset_t *soa);

int dnslib_changeset_add_soa(dnslib_changeset_t *changeset, dnslib_rrset_t *soa,
                             xfrin_changeset_part_t part);

int dnslib_changesets_check_size(dnslib_changesets_t *changesets);

void dnslib_free_changesets(dnslib_changesets_t **changesets);

#endif /* _KNOT_DNSLIB_CHANGESETS_H_ */

/*! @} */
