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

#include "contrib/endian.h"
#include "libknot/internal/utils.h"
#include "libknot/internal/macros.h"

/*----------------------------------------------------------------------------*/
lookup_table_t *lookup_by_name(lookup_table_t *table, const char *name)
{
	if (table == NULL || name == NULL) {
		return NULL;
	}

	while (table->name != NULL) {
		if (strcasecmp(name, table->name) == 0) {
			return table;
		}
		table++;
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/
lookup_table_t *lookup_by_id(lookup_table_t *table, int id)
{
	if (table == NULL) {
		return NULL;
	}

	while (table->name != NULL) {
		if (table->id == id) {
			return table;
		}
		table++;
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

uint16_t wire_read_u16(const uint8_t *pos)
{
	return be16toh(*(uint16_t *)pos);
}

uint32_t wire_read_u32(const uint8_t *pos)
{
	return be32toh(*(uint32_t *)pos);
}

uint64_t wire_read_u48(const uint8_t *pos)
{
	uint64_t input = 0;
	memcpy((uint8_t *)&input + 1, pos, 6);
	return be64toh(input) >> 8;
}

uint64_t wire_read_u64(const uint8_t *pos)
{
	return be64toh(*(uint64_t *)pos);
}

void wire_write_u16(uint8_t *pos, uint16_t data)
{
	*(uint16_t *)pos = htobe16(data);
}

void wire_write_u32(uint8_t *pos, uint32_t data)
{
	*(uint32_t *)pos = htobe32(data);
}

void wire_write_u48(uint8_t *pos, uint64_t data)
{
	uint64_t swapped = htobe64(data << 8);
	memcpy(pos, (uint8_t *)&swapped + 1, 6);
}

void wire_write_u64(uint8_t *pos, uint64_t data)
{
	*(uint64_t *)pos = htobe64(data);
}
