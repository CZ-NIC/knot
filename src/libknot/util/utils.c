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

#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>

#include "libknot/util/utils.h"

#include "libknot/util/endian.h"
#include "common/macros.h"

/*----------------------------------------------------------------------------*/
_public_
knot_lookup_table_t *knot_lookup_by_name(knot_lookup_table_t *table,
                                             const char *name)
{
	while (table->name != NULL) {
		if (strcasecmp(name, table->name) == 0) {
			return table;
		}
		table++;
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/
_public_
knot_lookup_table_t *knot_lookup_by_id(knot_lookup_table_t *table,
                                           int id)
{
	while (table->name != NULL) {
		if (table->id == id) {
			return table;
		}
		table++;
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

static int32_t serial_difference(uint32_t s1, uint32_t s2)
{
	return (((int64_t)s1 - s2) % ((int64_t)1 << 32));
}

_public_
int knot_serial_compare(uint32_t s1, uint32_t s2)
{
	int32_t diff = serial_difference(s1, s2);
	return (s1 == s2) /* s1 equal to s2 */
	        ? 0
	        :((diff >= 1 && diff < ((uint32_t)1 << 31))
	           ? 1	/* s1 larger than s2 */
	           : -1); /* s1 less than s2 */
}

_public_
uint16_t knot_wire_read_u16(const uint8_t *pos)
{
	return be16toh(*(uint16_t *)pos);
}

_public_
uint32_t knot_wire_read_u32(const uint8_t *pos)
{
	return be32toh(*(uint32_t *)pos);
}

_public_
uint64_t knot_wire_read_u48(const uint8_t *pos)
{
	uint64_t input = 0;
	memcpy((uint8_t *)&input + 1, pos, 6);
	return be64toh(input) >> 8;
}

_public_
uint64_t knot_wire_read_u64(const uint8_t *pos)
{
	return be64toh(*(uint64_t *)pos);
}

_public_
void knot_wire_write_u16(uint8_t *pos, uint16_t data)
{
	*(uint16_t *)pos = htobe16(data);
}

_public_
void knot_wire_write_u32(uint8_t *pos, uint32_t data)
{
	*(uint32_t *)pos = htobe32(data);
}

_public_
void knot_wire_write_u48(uint8_t *pos, uint64_t data)
{
	uint64_t swapped = htobe64(data << 8);
	memcpy(pos, (uint8_t *)&swapped + 1, 6);
}

_public_
void knot_wire_write_u64(uint8_t *pos, uint64_t data)
{
	*(uint64_t *)pos = htobe64(data);
}
