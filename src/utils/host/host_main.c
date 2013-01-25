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

#include <stdlib.h>			// EXIT_FAILURE

#include "common/errcode.h"		// KNOT_EOK
#include "utils/host/host_params.h"	// params_t
#include "utils/host/host_exec.h"	// host_exec

int main(int argc, char *argv[])
{
	params_t params;

	if (host_params_parse(&params, argc, argv) != KNOT_EOK) {
		return EXIT_FAILURE;
	}

	host_exec(&params);

	host_params_clean(&params);

	return EXIT_SUCCESS;
}

