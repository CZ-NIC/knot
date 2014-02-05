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
 * \file extra.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief API for managing custom data in the configuration parser.
 *
 * \addtogroup config
 * @{
 */

#ifndef _KNOT_CONF_EXTRA_H_
#define _KNOT_CONF_EXTRA_H_

#include <stdbool.h>

#include "knot/conf/includes.h"

/*!
 * \brief Custom data held within the parser context.
 */
typedef struct {
	bool error;                //!< Indicates that error was set.
	conf_includes_t *includes; //!< Used to handle filenames in includes.
} conf_extra_t;

/*!
 * \brief Init structure with custom data for config parser.
 *
 * \param file                Name of the main configuration file.
 *
 * \return Initialized stucture or NULL.
 */
conf_extra_t *conf_extra_init(const char *file);

/*!
 * \brief Free structure with custom data for config parser.
 *
 * \param extra  Structure to be freed.
 */
void conf_extra_free(conf_extra_t *extra);

#endif /* _KNOT_CONF_EXTRA_H_ */

/*! @} */
