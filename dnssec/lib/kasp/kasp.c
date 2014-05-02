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

#include "shared.h"
#include "error.h"
#include "kasp.h"
#include "kasp/internal.h"

/* -- internal API --------------------------------------------------------- */

int dnssec_kasp_create(dnssec_kasp_t **kasp_ptr,
                       const dnssec_kasp_store_functions_t *functions,
                       const char *config)
{
	if (!kasp_ptr || !functions || !config) {
		return DNSSEC_EINVAL;
	}

	dnssec_kasp_t *kasp = malloc(sizeof(*kasp));
	if (!kasp) {
		return DNSSEC_ENOMEM;
	}

	clear_struct(kasp);

	kasp->functions = functions;
	int result = functions->open(&kasp->ctx, config);
	if (result != DNSSEC_EOK) {
		free(kasp);
		return result;
	}

	*kasp_ptr = kasp;
	return DNSSEC_EOK;
}

/* -- public API ----------------------------------------------------------- */

_public_
void dnssec_kasp_close(dnssec_kasp_t *kasp)
{
	if (!kasp) {
		return;
	}

	kasp->functions->close(kasp->ctx);
	free(kasp);
}

_public_
int dnssec_kasp_load_zone(dnssec_kasp_t *kasp, const char *zone_name,
			 dnssec_kasp_zone_t **zone_ptr)
{
	if (!kasp || !zone_name || !zone_ptr) {
		return DNSSEC_EINVAL;
	}

	dnssec_kasp_zone_t *zone = dnssec_kasp_zone_new(zone_name);
	if (!zone) {
		return DNSSEC_ENOMEM;
	}

	int result = kasp->functions->load_zone(zone, kasp->ctx);
	if (result != DNSSEC_EOK) {
		dnssec_kasp_zone_free(zone);
		return result;
	}

	*zone_ptr = zone;
	return DNSSEC_EOK;
}

_public_
int dnssec_kasp_save_zone(dnssec_kasp_t *kasp, dnssec_kasp_zone_t *zone)
{
	if (!kasp || !zone) {
		return DNSSEC_EINVAL;
	}

	return kasp->functions->save_zone(zone, kasp->ctx);
}
