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

#include <gnutls/gnutls.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <error_code>\n", argv[0]);
		return 1;
	}

	char *end = NULL;
	long error = strtol(argv[1], &end, 10);
	if (*end != '\0' || error < INT_MIN || error > INT_MAX) {
		fprintf(stderr, "Invalid error code.\n");
		return 1;
	}

	printf("%s (%ld): %s\n", gnutls_strerror_name(error), error, gnutls_strerror(error));

	return 0;
}
