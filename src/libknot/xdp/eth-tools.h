/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

/*!
 * \brief Get number of RX queues of a network iface.
 *
 * \param devname   Name of the ethdev (e.g. eth1).
 *
 * \retval < 0   KNOT_E* if error.
 * \retval 1     Default no of queues if the dev does not support.
 * \return > 0   Number of queues.
 */
int knot_eth_get_rx_queues(const char *devname);
