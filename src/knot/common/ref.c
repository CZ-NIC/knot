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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>

#include "knot/common/ref.h"

void ref_init(ref_t *p, ref_destructor_t dtor)
{
	if (p) {
		p->count = 0;
		p->dtor = dtor;
	}
}

void ref_retain(ref_t *p)
{
	if (p) {
		__sync_add_and_fetch(&p->count, 1);
	}
}

void ref_release(ref_t *p)
{
	if (p) {
		int rc = __sync_sub_and_fetch(&p->count, 1);
		if (rc == 0 && p->dtor) {
			p->dtor(p);
		}
	}
}
