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

#include <config.h>
#include <stdlib.h>			// EXIT_FAILURE

#include "common/errcode.h"		// KNOT_EOK
#include "utils/host/host_params.h"	// host_parse
#include "utils/dig/dig_exec.h"		// dig_exec

int main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;

	dig_params_t params;
	if (host_parse(&params, argc, argv) == KNOT_EOK) {
		if (!params.stop && dig_exec(&params) != KNOT_EOK) {
			ret = EXIT_FAILURE;
		}
	} else {
		ret = EXIT_FAILURE;
	}

	host_clean(&params);
	return ret;
}
