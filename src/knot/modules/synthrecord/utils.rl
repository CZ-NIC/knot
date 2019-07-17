/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "knot/modules/synthrecord/utils_rl.h"

%%{
	machine shorten_ipv6;
	write data;
}%%

size_t shorten_ipv6(char *dst, const char *src)
{
	const char *p = src, *pe = src + strlen( src );
	int cs;

	char *dst_ptr = dst;
	int block = 2;

	%%{
		machine shorten_ipv6;
		
		action printable
		{
			*(dst_ptr++) = fc;
			
			if(block == 1) {
				block = 0;
			}
		}

		action printable_zero
		{
			switch(block) {
			case 0:	
				*(dst_ptr++) = '0';
				*(dst_ptr++) = '-';
				break;
			case 2:
				*(dst_ptr++) = '-';
				block--;
				break;
			}
		}

		action separator
		{
			*(dst_ptr++) = '-';
		}

		begin = ( '0' | (xdigit-'0')$printable ) ( xdigit$printable ){3} ':'$separator
			;
		center_nonzero = ( (xdigit-'0')$printable ) ( xdigit$printable ){3}
			| '0' ( (xdigit-'0')$printable ) ( xdigit$printable ){2}
			| ( '0' ){2} ( (xdigit-'0')$printable ) ( xdigit$printable )
			| ( '0' ){3} ( (xdigit-'0')$printable )
			;
		center_skipable = '0' {4}
			;
		center = ( center_nonzero ':'$separator )
			| ( center_skipable ':')%printable_zero
			;
		end = center_nonzero
			| ( '0' ){3} ( '0'$printable )
			;
		main := begin center{6} end
			;

		write init;
		write exec;

	}%%

	*dst_ptr = '\0';
	if ( cs < shorten_ipv6_first_final ) {
		return 0;
	}
	
	return dst_ptr - dst;
};

