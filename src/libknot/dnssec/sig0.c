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
#include <assert.h>
#include <time.h>
#include "common/errcode.h"
#include "libknot/dnssec/rrset-sign.h"
#include "libknot/dnssec/sig0.h"
#include "libknot/dnssec/sign.h"
#include "libknot/util/wire.h"

/*!
 * \brief Lifetime fudge of the SIG(0) packets in seconds.
 *
 * RFC recommends [now-5min, now+5min] lifetime interval.
 */
#define SIG0_LIFETIME_FUDGE_SECONDS 300

/*- SIG(0) internals ---------------------------------------------------------*/

/*!
 * \brief Create and initialize SIG(0) RR set.
 *
 * \return SIG(0) RR set.
 */
static knot_rrset_t *sig0_create_rrset(void)
{
	knot_dname_t *root = knot_dname_from_str(".");
	uint32_t ttl = 0;

	knot_rrset_t *sig_record = knot_rrset_new(root, KNOT_RRTYPE_SIG,
	                                          KNOT_CLASS_ANY, ttl);

	return sig_record;
}

static void sig0_write_rdata(uint8_t *rdata, const knot_dnssec_key_t *key)
{
	uint32_t incepted = time(NULL) - SIG0_LIFETIME_FUDGE_SECONDS;
	uint32_t expires = incepted + 2 * SIG0_LIFETIME_FUDGE_SECONDS;

	uint16_t type = 0;
	uint8_t labels = 0;
	uint32_t ttl = 0;

	knot_rrsig_write_rdata(rdata, key, type, labels, ttl, incepted, expires);
}

/*!
 * \brief Create and zero SIG(0) RDATA field.
 *
 * \param rrset  SIG(0) RR set.
 * \param key    Signing key.
 *
 * \return SIG(0) RDATA.
 */
static uint8_t *sig0_create_rdata(knot_rrset_t *rrset, knot_dnssec_key_t *key)
{
	assert(rrset);
	assert(key);

	size_t rdata_size = knot_rrsig_rdata_size(key);
	uint8_t *rdata = knot_rrset_create_rdata(rrset, rdata_size);
	if (!rdata) {
		return NULL;
	}

	sig0_write_rdata(rdata, key);

	return rdata;
}

/*!
 * \brief Write SIG(0) signature to a given binary wire.
 *
 * The signature covers SIG(0) RDATA section without signature field. And the
 * whole preceeding request before the SIG(0) record was added (i.e. before the
 * AR count in header was increased).
 *
 * \param wire          Output wire to be signed.
 * \param request_size  Size of the request in the wire.
 * \param sig_rr_size   Size of the SIG(0) RR in the wire.
 * \param key           Signing key.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sig0_write_signature(uint8_t* wire, size_t request_size,
				size_t sig_rr_size, knot_dnssec_key_t *key)
{
	assert(key);
	assert(key->data);

	knot_dnssec_sign_context_t *ctx = knot_dnssec_sign_init(key);
	if (!ctx) {
		return KNOT_ENOMEM;
	}

	size_t signature_size = knot_dnssec_sign_size(key);
	size_t sig_rr_header_size = 11; // owner (== root), type, class, TTL
	size_t sig_rdata_size = sig_rr_size - sig_rr_header_size;

	uint8_t *sig_rdata = wire + request_size + sig_rr_header_size;
	uint8_t *signature = wire + request_size + sig_rr_size - signature_size;

	knot_dnssec_sign_add(ctx, sig_rdata, sig_rdata_size - signature_size);
	knot_dnssec_sign_add(ctx, wire, request_size);
	int result = knot_dnssec_sign_write(ctx, signature, signature_size);

	knot_dnssec_sign_free(ctx);

	return result;
}

/*- SIG(0) public ------------------------------------------------------------*/

/*!
 * \brief Sign a packet using SIG(0) mechanism.
 */
int knot_sig0_sign(uint8_t *wire, size_t *wire_size, size_t wire_max_size,
                   knot_dnssec_key_t *key)
{
	knot_rrset_t *sig_rrset = sig0_create_rrset();
	if (!sig_rrset) {
		return KNOT_ENOMEM;
	}

	// SIG(0) headers without signature

	uint8_t *sig_rdata = sig0_create_rdata(sig_rrset, key);
	if (!sig_rdata) {
		knot_rrset_deep_free(&sig_rrset, 1);
		return KNOT_ENOMEM;
	}

	// convert to wire

	uint8_t *wire_end = wire + *wire_size;
	size_t wire_avail_size = wire_max_size - *wire_size;
	size_t wire_sig_size = 0;
	uint16_t written_rr_count = 0;

	int result = knot_rrset_to_wire(sig_rrset, wire_end, &wire_sig_size,
	                                wire_avail_size, &written_rr_count,
	                                NULL);
	knot_rrset_deep_free(&sig_rrset, 1);
	if (result != KNOT_EOK) {
		return result;
	}

	assert(written_rr_count == 1);

	// create signature

	result = sig0_write_signature(wire, *wire_size, wire_sig_size, key);
	if (result != KNOT_EOK) {
		return result;
	}

	uint16_t wire_arcount = knot_wire_get_arcount(wire);
	knot_wire_set_arcount(wire, wire_arcount + written_rr_count);

	*wire_size += wire_sig_size;

	return KNOT_EOK;
}
