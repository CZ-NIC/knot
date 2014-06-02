/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file log.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Logging facility (configuration file interface).
 *
 * \addtogroup logging
 * @{
 */

#pragma once

struct conf_t;

/*!
 * \brief Setup logging facilities from config.
 *
 * \see syslog.h
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOMEM out of memory error.
 */
int log_reconfigure(const struct conf_t *conf, void *data);

/*! @} */
