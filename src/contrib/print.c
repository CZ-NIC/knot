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

#include <stdio.h>
#include <ctype.h>

#include "contrib/print.h"

typedef int (*printf_t)(const char *fmt, ...);

static void array_printf(const uint8_t *data, const unsigned length,
                         printf_t print_handler, const char type)
{
	for (unsigned i = 0; i < length; i++) {
		uint8_t ch = data[i];

		switch (type) {
		case 't':
			if (isprint(ch) != 0) {
				print_handler("%c  ", ch);
			} else {
				print_handler("   ");
			}
			break;
		case 'x':
			print_handler("%02X ", ch);
			break;
		default:
			print_handler("0x%02X ", ch);
		}
	}
	print_handler("\n");
}

void hex_print(const uint8_t *data, unsigned length)
{
	array_printf(data, length, &printf, 0);
}

void short_hex_print(const uint8_t *data, unsigned length)
{
	array_printf(data, length, &printf, 'x');
}

void txt_print(const uint8_t *data, unsigned length)
{
	array_printf(data, length, &printf, 't');
}
