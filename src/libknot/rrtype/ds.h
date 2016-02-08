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

#pragma once

#include "libknot/attribute.h"
#include "libknot/rdataset.h"

_pure_
uint16_t knot_ds_key_tag(const knot_rdataset_t *rrs, size_t pos);

_pure_
uint8_t knot_ds_alg(const knot_rdataset_t *rrs, size_t pos);

_pure_
uint8_t knot_ds_digest_type(const knot_rdataset_t *rrs, size_t pos);

void knot_ds_digest(const knot_rdataset_t *rrs, size_t pos,
                    uint8_t **digest, uint16_t *digest_size);
