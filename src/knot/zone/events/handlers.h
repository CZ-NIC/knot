/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "knot/zone/events/events.h"

/*! \brief Loads or reloads potentially changed zone. */
int event_load(zone_t *zone);
/*! \brief Sends a SOA query to master. */
int event_refresh(zone_t *zone);
/*! \brief Initiates transfer with master. */
int event_xfer(zone_t *zone);
/*! \brief Processes DDNS updates in the zone's DDNS queue. */
int event_update(zone_t *zone);
/*! \brief Empties in-memory zone contents. */
int event_expire(zone_t *zone);
/*! \brief Flushes zone contents into text file. */
int event_flush(zone_t *zone);
/*! \brief Sends notify to slaves. */
int event_notify(zone_t *zone);
/*! \brief (re)Signs the zone using its DNSSEC keys. */
int event_dnssec(zone_t *zone);

/*! \brief Progressive bootstrap retry timer. */
uint32_t bootstrap_next(uint32_t timer);
