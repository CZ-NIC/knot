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

#include <assert.h>

#include "libknot/internal/macros.h"
#include "libknot/packet/wire.h"
#include "contrib/wire.h"

_public_
uint16_t knot_wire_get_id(const uint8_t *packet)
{
	return wire_read_u16(packet + KNOT_WIRE_OFFSET_ID);
}

_public_
void knot_wire_set_id(uint8_t *packet, uint16_t id)
{
	wire_write_u16(packet + KNOT_WIRE_OFFSET_ID, id);
}

_public_
uint16_t knot_wire_get_qdcount(const uint8_t *packet)
{
	return wire_read_u16(packet + KNOT_WIRE_OFFSET_QDCOUNT);
}

_public_
void knot_wire_set_qdcount(uint8_t *packet, uint16_t qdcount)
{
	wire_write_u16(packet + KNOT_WIRE_OFFSET_QDCOUNT, qdcount);
}

_public_
void knot_wire_add_qdcount(uint8_t *packet, int16_t n)
{
	wire_write_u16(packet + KNOT_WIRE_OFFSET_QDCOUNT,
	                    knot_wire_get_qdcount(packet) + n);
}

_public_
uint16_t knot_wire_get_ancount(const uint8_t *packet)
{
	return wire_read_u16(packet + KNOT_WIRE_OFFSET_ANCOUNT);
}

_public_
void knot_wire_set_ancount(uint8_t *packet, uint16_t ancount)
{
	wire_write_u16(packet + KNOT_WIRE_OFFSET_ANCOUNT, ancount);
}

_public_
void knot_wire_add_ancount(uint8_t *packet, int16_t n)
{
	wire_write_u16(packet + KNOT_WIRE_OFFSET_ANCOUNT,
	                    knot_wire_get_ancount(packet) + n);
}

_public_
uint16_t knot_wire_get_nscount(const uint8_t *packet)
{
	return wire_read_u16(packet + KNOT_WIRE_OFFSET_NSCOUNT);
}

_public_
void knot_wire_set_nscount(uint8_t *packet, uint16_t nscount)
{
	wire_write_u16(packet + KNOT_WIRE_OFFSET_NSCOUNT, nscount);
}

_public_
void knot_wire_add_nscount(uint8_t *packet, int16_t n)
{
	wire_write_u16(packet + KNOT_WIRE_OFFSET_NSCOUNT,
	                    knot_wire_get_nscount(packet) + n);
}

_public_
uint16_t knot_wire_get_arcount(const uint8_t *packet)
{
	return wire_read_u16(packet + KNOT_WIRE_OFFSET_ARCOUNT);
}

_public_
void knot_wire_set_arcount(uint8_t *packet, uint16_t arcount)
{
	wire_write_u16(packet + KNOT_WIRE_OFFSET_ARCOUNT, arcount);
}

_public_
void knot_wire_add_arcount(uint8_t *packet, int16_t n)
{
	wire_write_u16(packet + KNOT_WIRE_OFFSET_ARCOUNT,
	                    knot_wire_get_arcount(packet) + n);
}

_public_
void knot_wire_put_pointer(uint8_t *pos, uint16_t ptr)
{
	wire_write_u16(pos, ptr);		// Write pointer offset.
	assert((pos[0] & KNOT_WIRE_PTR) == 0);	// Check for maximal offset.
	pos[0] |= KNOT_WIRE_PTR;		// Add pointer mark.
}

_public_
uint16_t knot_wire_get_pointer(const uint8_t *pos)
{
	assert((pos[0] & KNOT_WIRE_PTR) == KNOT_WIRE_PTR);	// Check pointer.
	return (wire_read_u16(pos) - KNOT_WIRE_PTR_BASE);	// Return offset.
}

/*! @} */
