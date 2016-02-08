/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/conf/conf.h"
#include "knot/zone/zone.h"

/*! \brief Loads or reloads potentially changed zone. */
int event_load(conf_t *conf, zone_t *zone);
/*! \brief Sends a SOA query to master. */
int event_refresh(conf_t *conf, zone_t *zone);
/*! \brief Initiates transfer with master. */
int event_xfer(conf_t *conf, zone_t *zone);
/*! \brief Processes DDNS updates in the zone's DDNS queue. */
int event_update(conf_t *conf, zone_t *zone);
/*! \brief Empties in-memory zone contents. */
int event_expire(conf_t *conf, zone_t *zone);
/*! \brief Flushes zone contents into text file. */
int event_flush(conf_t *conf, zone_t *zone);
/*! \brief Sends notify to slaves. */
int event_notify(conf_t *conf, zone_t *zone);
/*! \brief (re)Signs the zone using its DNSSEC keys. */
int event_dnssec(conf_t *conf, zone_t *zone);

/*! \brief Progressive bootstrap retry timer. */
uint32_t bootstrap_next(uint32_t timer);
