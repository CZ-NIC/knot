/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>
#include <string.h>

#include "dnssec/error.h"
#include "dnssec/kasp.h"

static void test_new_policy(void)
{
	diag("%s", __func__);

	dnssec_kasp_policy_t *p = NULL;

	p = dnssec_kasp_policy_new(NULL);
	ok(p != NULL, "create policy without name");
	if (!p) {
		dnssec_kasp_policy_free(p);
	}

	dnssec_kasp_policy_free(p);

	p = dnssec_kasp_policy_new("domestic");
	ok(p != NULL, "create policy with name");
	if (!p) {
		return;
	}

	ok(strcmp(p->name, "domestic") == 0, "policy name is set");
	ok(p->algorithm == DNSSEC_KEY_ALGORITHM_INVALID, "no algorithm set");
	ok(dnssec_kasp_policy_validate(p) != DNSSEC_EOK, "validation fails");

	dnssec_kasp_policy_free(p);
}

static void test_set_parameters(void)
{
	diag("%s", __func__);

	dnssec_kasp_policy_t *p = dnssec_kasp_policy_new("monetary");
	ok(p != NULL, "create policy");
	if (!p) {
		return;
	}

	ok(dnssec_kasp_policy_validate(p) != DNSSEC_EOK, "validation fails with new policy");

	p->algorithm = DNSSEC_KEY_ALGORITHM_RSA_SHA256;
	p->ksk_size = 2048;
	p->zsk_size = 1024;
	p->rrsig_lifetime = 60;
	p->rrsig_refresh_before = 50;
	ok(dnssec_kasp_policy_validate(p) == DNSSEC_EOK, "validation succeeds with valid setting");

	p->algorithm = DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256;
	ok(dnssec_kasp_policy_validate(p) != DNSSEC_EOK, "validation fails with incorrect key size");

	p->manual = true;
	ok(dnssec_kasp_policy_validate(p) == DNSSEC_EOK, "validation succeeds in manual mode");

	dnssec_kasp_policy_free(p);
}

static void test_default_policy(void)
{
	diag("%s", __func__);

	dnssec_kasp_policy_t *p = dnssec_kasp_policy_new("environmental");
	ok(p != NULL, "create policy");
	if (!p) {
		return;
	}

	ok(dnssec_kasp_policy_validate(p) != DNSSEC_EOK, "validation fails with new policy");

	dnssec_kasp_policy_defaults(p);
	ok(dnssec_kasp_policy_validate(p) == DNSSEC_EOK, "validation succeeds with defaults");

	ok(p->manual == false, "manual mode disabled");
	ok(p->algorithm == DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256, "algorithm is ECDSAP256SHA256");
	ok(p->nsec3_enabled == false, "NSEC3 is disabled");
	ok(p->dnskey_ttl == 1200, "DNSKEY TTL is 1200");
	ok(p->zsk_lifetime > 0, "ZSK lifetime is set");
	ok(p->rrsig_lifetime > 0, "RRSIG lifetime is set");
	ok(p->rrsig_lifetime == p->rrsig_refresh_before * 2, "RRSIG lifetime is double the refresh");

	dnssec_kasp_policy_free(p);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	test_new_policy();
	test_set_parameters();
	test_default_policy();

	return 0;
}
