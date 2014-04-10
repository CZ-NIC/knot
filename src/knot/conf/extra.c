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

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "knot/conf/includes.h"
#include "knot/conf/extra.h"


/*!
 * \brief Init structure with custom data for config parser.
 */
conf_extra_t *conf_extra_init(const char *file)
{
	conf_extra_t *extra = calloc(1, sizeof(conf_extra_t));
	if (!extra) {
		return NULL;
	}

	conf_includes_t *includes = conf_includes_init();
	if (!includes) {
		free(extra);
		return NULL;
	}

	if (!conf_includes_push(includes, file)) {
		conf_includes_free(includes);
		free(extra);
		return NULL;
	}

	extra->error = false;
	extra->includes = includes;

	return extra;
}

/*!
 * \brief Free structure with custom data for config parser.
 */
void conf_extra_free(conf_extra_t *extra)
{
	if (!extra)
		return;

	conf_includes_free(extra->includes);
	free(extra);
}
