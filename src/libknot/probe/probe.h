/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief A DNS traffic probe interface.
 *
 * \addtogroup probe
 * @{
 */

#pragma once

#include "libknot/probe/data.h"

/*! A probe context. */
struct knot_probe;
typedef struct knot_probe knot_probe_t;

/*!
 * Allocates a probe context.
 *
 * \return Probe context.
 */
knot_probe_t *knot_probe_alloc(void);

/*!
 * \brief Deallocates a probe.
 *
 * \param probe  Probe context.
 */
void knot_probe_free(knot_probe_t *probe);

/*!
 * \brief Initializes one probe producer.
 *
 * \param probe  Probe context.
 * \param dir    Unix socket directory.
 * \param idx    Probe ID (counted from 1).
 *
 * \retval KNOT_EOK    Success.
 * \retval KNOT_ECONN  Initial connection failed.
 * \return KNOT_E*     If error.
 */
int knot_probe_set_producer(knot_probe_t *probe, const char *dir, uint16_t idx);

/*!
 * \brief Initializes one probe consumer.
 *
 * \note The socket permissions are set to 0222!
 *
 * \param probe  Probe context.
 * \param dir    Unix socket directory.
 * \param idx    Probe ID (counted from 1).
 *
 * \retval KNOT_EOK  Success.
 * \return KNOT_E*   If error.
 */
int knot_probe_set_consumer(knot_probe_t *probe, const char *dir, uint16_t idx);

/*!
 * \brief Returns file descriptor of the probe.
 *
 * \param probe  Probe context.
 */
int knot_probe_fd(knot_probe_t *probe);

/*!
 * \brief Sends data units to a probe.
 *
 * \note Data arrays of length > 1 are not supported yet.
 *
 * If send fails due to unconnected socket anf if not connected for at least
 * 2 seconds, reconnection is attempted and if successful, the send operation
 * is repeated.
 *
 * \param probe  Probe context.
 * \param data   Array of data units.
 * \param count  Length of data unit array.
 *
 * \retval KNOT_EOK  Success.
 * \return KNOT_E*   If error.
 */
int knot_probe_produce(knot_probe_t *probe, const knot_probe_data_t *data, uint8_t count);

/*!
 * \brief Receives data units from a probe.
 *
 * This function blocks on poll until a data unit is received or timeout is hit.
 *
 * \param probe       Probe context.
 * \param data        Array of data units.
 * \param count       Length of data unit array.
 * \param timeout_ms  Poll timeout in milliseconds (-1 means infinity).
 *
 * \retval >= 0    Number of data units received.
 * \return KNOT_E* If error.
 */
int knot_probe_consume(knot_probe_t *probe, knot_probe_data_t *data, uint8_t count,
                       int timeout_ms);

/*! @} */
