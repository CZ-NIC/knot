/*!
 * \file xfr-in.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief XFR client API.
 *
 * \addtogroup query_processing
 * @{
 */

#ifndef _KNOT_XFR_IN_H_
#define _KNOT_XFR_IN_H_

#include <stdint.h>
#include <string.h>

#include "dnslib/dname.h"
#include "dnslib/zone.h"
#include "dnslib/packet.h"
#include "knot/server/name-server.h"

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
} xfrin_changeset_t;

//typedef struct {
//	uint8_t *data;
//	size_t size;
//	uint32_t serial_from;
//	uint32_t serial_to;
//} xfrin_changeset_t;

typedef struct {
	xfrin_changeset_t *sets;
	size_t count;
	size_t allocated;
} xfrin_changesets_t;

/*!
 * \brief Creates normal query for the given zone name and the SOA type.
 *
 * \param zone_name Name of the zone to ask for - the SOA owner.
 * \param buffer Buffer to fill the message in.
 * \param size In: available space in the buffer. Out: actual size of the
 *             message in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int xfrin_create_soa_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                           size_t *size);

/*!
 * \brief Checks if a zone transfer is required by comparing the zone's SOA with
 *        the one received from master server.
 *
 * \param zone Zone to check.
 * \param soa_response Response to SOA query received from master server.
 *
 * \retval < 0 if an error occured.
 * \retval 1 if the transfer is needed.
 * \retval 0 if the transfer is not needed.
 */
int xfrin_transfer_needed(const dnslib_zone_t *zone,
                          dnslib_packet_t *soa_response);

/*!
 * \brief Creates normal query for the given zone name and the AXFR type.
 *
 * \param zone_name Name of the zone to ask for - the SOA owner.
 * \param buffer Buffer to fill the message in.
 * \param size In: available space in the buffer. Out: actual size of the
 *             message in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int xfrin_create_axfr_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                            size_t *size);

/*!
 * \brief Creates normal query for the given zone name and the IXFR type.
 *
 * \param zone_name Name of the zone to ask for - the SOA owner.
 * \param buffer Buffer to fill the message in.
 * \param size In: available space in the buffer. Out: actual size of the
 *             message in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int xfrin_create_ixfr_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                            size_t *size);

/*!
 * \brief Processes the newly created transferred zone.
 *
 * \param nameserver Name server to update.
 * \param zone Zone build from transfer.
 *
 * \retval KNOT_ENOTSUP
 */
int xfrin_zone_transferred(ns_nameserver_t *nameserver, dnslib_zone_t *zone);

/*!
 * \brief Processes one incoming packet of AXFR transfer by updating the given
 *        zone.
 *
 * \param pkt Incoming packet in wire format.
 * \param size Size of the packet in bytes.
 * \param zone Zone being built. If there is no such zone (i.e. this is the
 *             first packet, \a *zone may be set to NULL, in which case a new
 *             zone structure is created).
 *
 * \retval KNOT_EOK
 *
 * \todo Refactor!!!
 */
int xfrin_process_axfr_packet(const uint8_t *pkt, size_t size,
                              dnslib_zone_t **zone);

void xfrin_free_changesets(xfrin_changesets_t **changesets);

int xfrin_process_ixfr_packet(const uint8_t *pkt, size_t size,
                              xfrin_changesets_t **changesets);

/*!
 * \brief Store changesets in journal.
 *
 * Changesets will be stored on a permanent storage.
 * Journal may be compacted, resulting in flattening changeset history.
 *
 * \param zone Zone associated with the changeset.
 * \param src Changesets.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_EAGAIN if journal needs to be synced with zonefile first.
 */
int xfrin_store_changesets(dnslib_zone_t *zone, const xfrin_changesets_t *src);

/*!
 * \brief Load changesets from journal.
 *
 * Changesets will be stored on a permanent storage.
 * Journal may be compacted, resulting in flattening changeset history.
 *
 * In case of KNOT_ERANGE error, whole zone content should be sent instead,
 * as the changeset history cannot be recovered.
 *
 * \param zone Zone containing a changeset journal.
 * \param dst Container to be loaded.
 * \param from Starting SOA serial (oldest).
 * \param to Ending SOA serial (newest).
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ERANGE when changeset history cannot be reconstructed.
 */
int xfr_load_changesets(dnslib_zone_t *zone, xfrin_changesets_t *dst,
			uint32_t from, uint32_t to);

#endif /* _KNOT_XFR_IN_H_ */

/*! @} */
