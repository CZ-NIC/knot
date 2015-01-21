/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "dnssec/event.h"
#include "shared.h"

_public_
const char *dnssec_event_name(dnssec_event_type_t event)
{
	switch (event) {
	case DNSSEC_EVENT_NONE:
		return "no event";
	case DNSSEC_EVENT_GENERATE_INITIAL_KEY:
		return "generate initial keys";
	case DNSSEC_EVENT_ZSK_ROTATION_INIT:
		return "initialize ZSK rotation";
	case DNSSEC_EVENT_ZSK_ROTATION_FINISH:
		return "finish ZSK rotation";
	default:
		return "unknown event";
	}
}
