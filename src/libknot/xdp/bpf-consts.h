/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

enum {
	KNOT_XDP_LISTEN_PORT_MASK  = 0xFFFF0000, /*!< Listen port option mask. */
	KNOT_XDP_LISTEN_PORT_TCP   = 1 << 16,    /*!< Apply to TCP. */
	KNOT_XDP_LISTEN_PORT_PASS  = 1 << 17,    /*!< Pass incoming messages to ports >= port value. */
	KNOT_XDP_LISTEN_PORT_DROP  = 1 << 18,    /*!< Drop incoming messages to ports >= port value. */
};
