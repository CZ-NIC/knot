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
#include <stdio.h>

#include "print.h"

void hex_printf(const char *data, int length, printf_t print_handler)
{
	int ptr = 0;
	for (; ptr < length; ptr++) {
		print_handler("0x%02x ", (unsigned char)*(data + ptr));
	}
	print_handler("\n");
}

void hex_print(const char *data, int length)
{
	hex_printf(data, length, &printf);
}

void bit_printf(const char *data, int length, printf_t print_handler)
{
	unsigned char mask = 0x01;
	int ptr = 0;
	int bit = 0;
	for (; ptr < length; ptr++) {
		for (bit = 7; bit >= 0; bit--) {
			if ((mask << bit) & (unsigned char)*(data + ptr)) {
				print_handler("1");
			} else {
				print_handler("0");
			}
		}
		print_handler(" ");
	}
	print_handler("\n");
}

void bit_print(const char *data, int length)
{
	bit_printf(data, length, &printf);
}
