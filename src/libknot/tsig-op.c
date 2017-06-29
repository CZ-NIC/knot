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
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <time.h>
#include <inttypes.h>

#include "libknot/tsig-op.h"

#include "common/debug.h"
#include "common/log.h"
#include "libknot/common.h"
#include "libknot/descriptor.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/packet/wire.h"
#include "libknot/consts.h"
#include "libknot/dnssec/key.h"
#include "libknot/packet/rrset-wire.h"

const int KNOT_TSIG_MAX_DIGEST_SIZE = 64;    // size of HMAC-SHA512 digest
const uint16_t KNOT_TSIG_FUDGE_DEFAULT = 300;  // default Fudge value

static int knot_tsig_check_algorithm(const knot_rrset_t *tsig_rr)
{
	if (tsig_rr == NULL) {
		return KNOT_EINVAL;
	}

	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	if (!alg_name) {
		return KNOT_EMALF;
	}

	knot_tsig_algorithm_t alg = tsig_alg_from_name(alg_name);
	if (alg == 0) {
		/*!< \todo is this error OK? */
		dbg_tsig("TSIG: unknown algorithm.\n");
		return KNOT_TSIG_EBADSIG;
	}

	return KNOT_EOK;
}

static int knot_tsig_check_key(const knot_rrset_t *tsig_rr,
                               const knot_tsig_key_t *tsig_key)
{
	if (tsig_rr == NULL || tsig_key == NULL) {
		return KNOT_EINVAL;
	}

	const knot_dname_t *tsig_name = tsig_rr->owner;
	if (!tsig_name) {
		return KNOT_EMALF;
	}

	char *name = knot_dname_to_str_alloc(tsig_name);
	if (!name) {
		return KNOT_EMALF;
	}

	if (knot_dname_cmp(tsig_name, tsig_key->name) != 0) {
		/*!< \todo which error. */
		dbg_tsig("TSIG: unknown key: %s\n", name);
		free(name);
		return KNOT_TSIG_EBADKEY;
	}

	free(name);
	return KNOT_EOK;
}

static int knot_tsig_compute_digest(const uint8_t *wire, size_t wire_len,
                                    uint8_t *digest, size_t *digest_len,
                                    const knot_tsig_key_t *key)
{
	if (!wire || !digest || !digest_len || !key) {
		dbg_tsig("TSIG: digest: bad args.\n");
		return KNOT_EINVAL;
	}

	if (!key->name) {
		dbg_tsig("TSIG: digest: no algorithm\n");
		return KNOT_EMALF;
	}

	knot_tsig_algorithm_t tsig_alg = key->algorithm;
	if (tsig_alg == 0) {
		dbg_tsig("TSIG: digest: unknown algorithm\n");
		return KNOT_TSIG_EBADSIG;
	}

	dbg_tsig_detail("TSIG: key size: %zu\n", key->secret.size);
	dbg_tsig_detail("TSIG: key:\n");
	dbg_tsig_hex_detail((char *)key->secret.data, key->secret.size);
	dbg_tsig_detail("Wire for signing is %zu bytes long.\n", wire_len);

	/* Compute digest. */
	HMAC_CTX ctx;

	switch (tsig_alg) {
		case KNOT_TSIG_ALG_HMAC_MD5:
			HMAC_Init(&ctx, key->secret.data,
			          key->secret.size, EVP_md5());
			break;
		case KNOT_TSIG_ALG_HMAC_SHA1:
			HMAC_Init(&ctx, key->secret.data,
			          key->secret.size, EVP_sha1());
			break;
		case KNOT_TSIG_ALG_HMAC_SHA224:
			HMAC_Init(&ctx, key->secret.data,
			          key->secret.size, EVP_sha224());
			break;
		case KNOT_TSIG_ALG_HMAC_SHA256:
			HMAC_Init(&ctx, key->secret.data,
			          key->secret.size, EVP_sha256());
			break;
		case KNOT_TSIG_ALG_HMAC_SHA384:
			HMAC_Init(&ctx, key->secret.data,
			          key->secret.size, EVP_sha384());
			break;
		case KNOT_TSIG_ALG_HMAC_SHA512:
			HMAC_Init(&ctx, key->secret.data,
			          key->secret.size, EVP_sha512());
			break;
		default:
			return KNOT_ENOTSUP;
	} /* switch */

	unsigned tmp_dig_len = *digest_len;
	HMAC_Update(&ctx, (const unsigned char *)wire, wire_len);
	HMAC_Final(&ctx, digest, &tmp_dig_len);
	*digest_len = tmp_dig_len;

	HMAC_CTX_cleanup(&ctx);

	return KNOT_EOK;
}

static int knot_tsig_check_time_signed(const knot_rrset_t *tsig_rr,
                                       uint64_t prev_time_signed)
{
	if (!tsig_rr) {
		dbg_tsig("TSIG: check_time_signed: NULL argument.\n");
		return KNOT_EINVAL;
	}

	/* Get the time signed and fudge values. */
	uint64_t time_signed = tsig_rdata_time_signed(tsig_rr);
	if (time_signed == 0) {
		return KNOT_TSIG_EBADTIME;
	}
	uint16_t fudge = tsig_rdata_fudge(tsig_rr);
	if (fudge == 0) {
		return KNOT_TSIG_EBADTIME;
	}

	/* Get the current time. */
	time_t curr_time = time(NULL);

	/*!< \todo bleeding eyes. */
	double diff = difftime(curr_time, (time_t)time_signed);

	if (diff > fudge || diff < -fudge) {
		return KNOT_TSIG_EBADTIME;
	}

	diff = difftime((time_t)time_signed, prev_time_signed);

	if (diff < 0) {
		return KNOT_TSIG_EBADTIME;
	}

	return KNOT_EOK;
}

static int knot_tsig_write_tsig_variables(uint8_t *wire,
                                          const knot_rrset_t *tsig_rr)
{
	if (wire == NULL || tsig_rr == NULL) {
		dbg_tsig("TSIG: write tsig variables: NULL arguments.\n");
		return KNOT_EINVAL;
	}

	/* Copy TSIG variables - starting with key name. */
	const knot_dname_t *tsig_owner = tsig_rr->owner;
	if (!tsig_owner) {
		dbg_tsig("TSIG: write variables: no owner.\n");
		return KNOT_EINVAL;
	}

	int offset = 0;

	offset += knot_dname_to_wire(wire + offset, tsig_owner, KNOT_DNAME_MAXLEN);

	/*!< \todo which order? */

	/* Copy class. */
	knot_wire_write_u16(wire + offset, tsig_rr->rclass);
	dbg_tsig_verb("TSIG: write variables: written CLASS: %u - \n",
	               tsig_rr->rclass);
	dbg_tsig_hex_detail((char *)(wire + offset), sizeof(uint16_t));
	offset += sizeof(uint16_t);

	/* Copy TTL - always 0. */
	knot_wire_write_u32(wire + offset, knot_rdata_ttl(knot_rdataset_at(&tsig_rr->rrs, 0)));
	dbg_tsig_hex_detail((char *)(wire + offset), sizeof(uint32_t));
	offset += sizeof(uint32_t);

	/* Copy alg name. */
	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	if (!alg_name) {
		dbg_tsig("TSIG: write variables: no algorithm name.\n");
		return KNOT_EINVAL;
	}

	/* Te algorithm name must be in canonical form, i.e. in lowercase. */
	uint8_t *alg_name_wire = wire + offset;
	offset += knot_dname_to_wire(alg_name_wire, alg_name, KNOT_DNAME_MAXLEN);
	if (knot_dname_to_lower(alg_name_wire) != KNOT_EOK) {
		dbg_tsig("TSIG: write variables: cannot convert algorithm "
		         "to lowercase.\n");
		return KNOT_EINVAL;
	}

	/* Following data are written in network order. */
	/* Time signed. */
	knot_wire_write_u48(wire + offset, tsig_rdata_time_signed(tsig_rr));
	offset += 6;
	dbg_tsig_verb("TSIG: write variables: time signed: %"PRIu64" \n",
	              tsig_rdata_time_signed(tsig_rr));
	dbg_tsig_hex_detail((char *)(wire + offset - 6), 6);
	/* Fudge. */
	knot_wire_write_u16(wire + offset, tsig_rdata_fudge(tsig_rr));
	offset += sizeof(uint16_t);
	dbg_tsig_verb("TSIG: write variables: fudge: %hu\n",
	              tsig_rdata_fudge(tsig_rr));
	/* TSIG error. */
	knot_wire_write_u16(wire + offset, tsig_rdata_error(tsig_rr));
	offset += sizeof(uint16_t);
	/* Get other data length. */
	uint16_t other_data_length = tsig_rdata_other_data_length(tsig_rr);
	/* Get other data. */
	const uint8_t *other_data = tsig_rdata_other_data(tsig_rr);
	if (!other_data) {
		dbg_tsig("TSIG: write variables: no other data.\n");
		return KNOT_EINVAL;
	}

	/*
	 * We cannot write the whole other_data, as it contains its length in
	 * machine order.
	 */
	knot_wire_write_u16(wire + offset, other_data_length);
	offset += sizeof(uint16_t);

	/* Skip the length. */
	dbg_tsig_verb("Copying other data.\n");
	memcpy(wire + offset, other_data, other_data_length);

	return KNOT_EOK;
}

static int knot_tsig_wire_write_timers(uint8_t *wire,
                                       const knot_rrset_t *tsig_rr)
{
	if (wire == NULL || tsig_rr == NULL) {
		dbg_tsig("TSIG: write timers: NULL arguments.\n");
		return KNOT_EINVAL;
	}

	//write time signed
	knot_wire_write_u48(wire, tsig_rdata_time_signed(tsig_rr));
	//write fudge
	knot_wire_write_u16(wire + 6, tsig_rdata_fudge(tsig_rr));

	return KNOT_EOK;
}

static int knot_tsig_create_sign_wire(const uint8_t *msg, size_t msg_len,
				      const uint8_t *request_mac,
		                      size_t request_mac_len,
		                      uint8_t *digest, size_t *digest_len,
				      const knot_rrset_t *tmp_tsig,
		                      const knot_tsig_key_t *key)
{
	if (!msg || !key || digest_len == NULL) {
		dbg_tsig("TSIG: create wire: bad args.\n");
		return KNOT_EINVAL;
	}

	/* Create tmp TSIG. */
	int ret = KNOT_EOK;

	/*
	 * Create tmp wire, it should contain message
	 * plus request mac plus tsig varibles.
	 */
	dbg_tsig_verb("Counting wire size: %zu, %zu, %zu.\n",
	              msg_len, request_mac_len,
	              tsig_rdata_tsig_variables_length(tmp_tsig));
	size_t wire_len = sizeof(uint8_t) *
			(msg_len + request_mac_len + ((request_mac_len > 0)
			 ? 2 : 0) +
			tsig_rdata_tsig_variables_length(tmp_tsig));
	uint8_t *wire = malloc(wire_len);
	if (!wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	memset(wire, 0, wire_len);

	uint8_t *pos = wire;

	/* Copy the request MAC - should work even if NULL. */
	if (request_mac_len > 0) {
		dbg_tsig_verb("Copying request MAC size\n");
		knot_wire_write_u16(pos, request_mac_len);
		pos += 2;
		dbg_tsig_verb("Copying request mac.\n");
		memcpy(pos, request_mac, sizeof(uint8_t) * request_mac_len);
	}
	dbg_tsig_detail("TSIG: create wire: request mac:\n");
	dbg_tsig_hex_detail((char *)pos, request_mac_len);
	pos += request_mac_len;
	/* Copy the original message. */
	dbg_tsig_verb("Copying original message.\n");
	memcpy(pos, msg, msg_len);
	pos += msg_len;
	/* Copy TSIG variables. */
	dbg_tsig_verb("Writing TSIG variables.\n");
	ret = knot_tsig_write_tsig_variables(pos, tmp_tsig);
	if (ret != KNOT_EOK) {
		dbg_tsig("TSIG: create wire: failed to write TSIG "
		         "variables: %s\n", knot_strerror(ret));
		free(wire);
		return ret;
	}

	/* Compute digest. */
	ret = knot_tsig_compute_digest(wire, wire_len, digest, digest_len, key);
	if (ret != KNOT_EOK) {
		dbg_tsig("TSIG: create wire: failed to compute digest: %s\n",
		         knot_strerror(ret));
		*digest_len = 0;
		free(wire);
		return ret;
	}

	free(wire);

	return KNOT_EOK;
}

static int knot_tsig_create_sign_wire_next(const uint8_t *msg, size_t msg_len,
                                           const uint8_t *prev_mac,
                                           size_t prev_mac_len,
                                           uint8_t *digest, size_t *digest_len,
                                           const knot_rrset_t *tmp_tsig,
                                           const knot_tsig_key_t *key)
{
	if (!msg || !key || digest_len == NULL) {
		dbg_tsig("TSIG: create wire: bad args.\n");
		return KNOT_EINVAL;
	}

	/* Create tmp TSIG. */
	int ret = KNOT_EOK;

	/*
	 * Create tmp wire, it should contain message
	 * plus request mac plus tsig varibles.
	 */
	dbg_tsig_verb("Counting wire size: %zu, %zu, %zu.\n",
	              msg_len, prev_mac_len,
	              tsig_rdata_tsig_timers_length());
	size_t wire_len = sizeof(uint8_t) *
	                (msg_len + prev_mac_len +
			tsig_rdata_tsig_timers_length() + 2);
	uint8_t *wire = malloc(wire_len);
	if (!wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	memset(wire, 0, wire_len);

	/* Copy the request MAC - should work even if NULL. */
	dbg_tsig_verb("Copying request mac size.\n");
	knot_wire_write_u16(wire, prev_mac_len);
	dbg_tsig_verb("Copying request mac.\n");
	memcpy(wire + 2, prev_mac, sizeof(uint8_t) * prev_mac_len);
	dbg_tsig_detail("TSIG: create wire: request mac:\n");
	dbg_tsig_hex_detail((char *)(wire + 2), prev_mac_len);
	/* Copy the original message. */
	dbg_tsig_verb("Copying original message.\n");
	memcpy(wire + prev_mac_len + 2, msg, msg_len);
	/* Copy TSIG variables. */

	dbg_tsig_verb("Writing TSIG timers.\n");
	ret = knot_tsig_wire_write_timers(wire + prev_mac_len + msg_len + 2,
	                                  tmp_tsig);
	if (ret != KNOT_EOK) {
		dbg_tsig("TSIG: create wire: failed to write TSIG "
		         "timers: %s\n", knot_strerror(ret));
		free(wire);
		return ret;
	}

	/* Compute digest. */
	ret = knot_tsig_compute_digest(wire, wire_len,
	                               digest, digest_len, key);
	if (ret != KNOT_EOK) {
		dbg_tsig("TSIG: create wire: failed to compute digest: %s\n",
		         knot_strerror(ret));
		*digest_len = 0;
		free(wire);
		return ret;
	}

	free(wire);

	return KNOT_EOK;
}

int knot_tsig_sign(uint8_t *msg, size_t *msg_len,
                   size_t msg_max_len, const uint8_t *request_mac,
                   size_t request_mac_len,
                   uint8_t *digest, size_t *digest_len,
                   const knot_tsig_key_t *key, uint16_t tsig_rcode,
                   uint64_t request_time_signed)
{
	if (!msg || !msg_len || !key || digest == NULL || digest_len == NULL) {
		return KNOT_EINVAL;
	}

	knot_rrset_t *tmp_tsig =
		knot_rrset_new(key->name, KNOT_RRTYPE_TSIG, KNOT_CLASS_ANY,
		               NULL);
	if (!tmp_tsig) {
		dbg_tsig("TSIG: tmp_tsig = NULL\n");
		return KNOT_ENOMEM;
	}

	/* Create rdata for TSIG RR. */
	uint16_t rdata_rcode = 0;
	if (tsig_rcode == KNOT_TSIG_ERR_BADTIME)
		rdata_rcode = tsig_rcode;
	tsig_create_rdata(tmp_tsig, tsig_alg_to_dname(key->algorithm),
	                  knot_tsig_digest_length(key->algorithm), rdata_rcode);

	/* Distinguish BADTIME response. */
	if (tsig_rcode == KNOT_TSIG_ERR_BADTIME) {
		/* Set client's time signed into the time signed field. */
		tsig_rdata_set_time_signed(tmp_tsig, request_time_signed);

		/* Store current time into Other data. */
		uint8_t time_signed[6];
		time_t curr_time = time(NULL);

		uint64_t time64 = curr_time;
		knot_wire_write_u48(time_signed, time64);

		tsig_rdata_set_other_data(tmp_tsig, 6, time_signed);
	} else {
		tsig_rdata_store_current_time(tmp_tsig);

		/* Set other len. */
		tsig_rdata_set_other_data(tmp_tsig, 0, 0);
	}

	tsig_rdata_set_fudge(tmp_tsig, KNOT_TSIG_FUDGE_DEFAULT);

	/* Set original ID */
	tsig_rdata_set_orig_id(tmp_tsig, knot_wire_get_id(msg));

	uint8_t digest_tmp[KNOT_TSIG_MAX_DIGEST_SIZE];
	size_t digest_tmp_len = 0;

	int ret = KNOT_ERROR;
	ret = knot_tsig_create_sign_wire(msg, *msg_len, /*msg_max_len,*/
	                                     request_mac, request_mac_len,
	                                     digest_tmp, &digest_tmp_len,
					     tmp_tsig, key);
	if (ret != KNOT_EOK) {
		dbg_tsig("TSIG: failed to create wire or sign wire: %s\n",
		         knot_strerror(ret));
		knot_rrset_free(&tmp_tsig, NULL);
		return ret;
	}

	/* Set the digest. */
	tsig_rdata_set_mac(tmp_tsig, digest_tmp_len, digest_tmp);

	/* Write RRSet to wire */

	ret = knot_rrset_to_wire(tmp_tsig, msg + *msg_len,
	                         msg_max_len - *msg_len, NULL);
	if (ret < 0) {
		dbg_tsig("TSIG: rrset_to_wire = %s\n", knot_strerror(ret));
		*digest_len = 0;
		knot_rrset_free(&tmp_tsig, NULL);
		return ret;
	}

	size_t tsig_wire_len = ret;

	knot_rrset_free(&tmp_tsig, NULL);

	dbg_tsig("TSIG: written TSIG RR (wire len %zu)\n", tsig_wire_len);
	*msg_len += tsig_wire_len;

	uint16_t arcount = knot_wire_get_arcount(msg);
	knot_wire_set_arcount(msg, ++arcount);

	// everything went ok, save the digest to the output parameter
	memcpy(digest, digest_tmp, digest_tmp_len);
	*digest_len = digest_tmp_len;

	return KNOT_EOK;
}

int knot_tsig_sign_next(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                        const uint8_t *prev_digest, size_t prev_digest_len,
                        uint8_t *digest, size_t *digest_len,
                        const knot_tsig_key_t *key, uint8_t *to_sign,
                        size_t to_sign_len)
{
	if (!msg || !msg_len || !key || !digest || !digest_len) {
		return KNOT_EINVAL;
	}

	uint8_t digest_tmp[KNOT_TSIG_MAX_DIGEST_SIZE];
	size_t digest_tmp_len = 0;
	knot_rrset_t *tmp_tsig = knot_rrset_new(key->name, KNOT_RRTYPE_TSIG,
	                                        KNOT_CLASS_ANY, NULL);
	if (!tmp_tsig) {
		return KNOT_ENOMEM;
	}

	/* Create rdata for TSIG RR. */
	tsig_create_rdata(tmp_tsig, tsig_alg_to_dname(key->algorithm),
	                  knot_tsig_digest_length(key->algorithm), 0);
	tsig_rdata_store_current_time(tmp_tsig);
	tsig_rdata_set_fudge(tmp_tsig, KNOT_TSIG_FUDGE_DEFAULT);

	/* Create wire to be signed. */
	size_t wire_len = prev_digest_len + to_sign_len
	                  + KNOT_TSIG_TIMERS_LENGTH + 2;
	uint8_t *wire = malloc(wire_len);
	if (!wire) {
		ERR_ALLOC_FAILED;
		knot_rrset_free(&tmp_tsig, NULL);
		return KNOT_ENOMEM;
	}
	memset(wire, 0, wire_len);

	/* Write previous digest length. */
	knot_wire_write_u16(wire, prev_digest_len);
	/* Write previous digest. */
	memcpy(wire + 2, prev_digest, sizeof(uint8_t) * prev_digest_len);
	/* Write original message. */
	memcpy(wire + prev_digest_len + 2, to_sign, to_sign_len);
	/* Write timers. */
	knot_tsig_wire_write_timers(wire + prev_digest_len + to_sign_len + 2,
	                            tmp_tsig);

	dbg_tsig_detail("Previous digest: \n");
	dbg_tsig_hex_detail((char *)prev_digest, prev_digest_len);

	dbg_tsig_detail("Timers: \n");
	dbg_tsig_hex_detail((char *)(wire + prev_digest_len + *msg_len),
			    KNOT_TSIG_TIMERS_LENGTH);

	int ret = KNOT_ERROR;
	ret = knot_tsig_compute_digest(wire, wire_len,
	                               digest_tmp, &digest_tmp_len, key);

	/* No matter how the function did, this data is no longer needed. */
	free(wire);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&tmp_tsig, NULL);
		*digest_len = 0;
		return ret;
	}

	if (digest_tmp_len > *digest_len) {
		knot_rrset_free(&tmp_tsig, NULL);
		*digest_len = 0;
		return KNOT_ESPACE;
	}

	/* Set the MAC. */
	tsig_rdata_set_mac(tmp_tsig, digest_tmp_len, digest_tmp);

	/* Set original id. */
	tsig_rdata_set_orig_id(tmp_tsig, knot_wire_get_id(msg));

	/* Set other data. */
	tsig_rdata_set_other_data(tmp_tsig, 0, NULL);

	dbg_tsig_verb("Message max length: %zu, message length: %zu\n",
	              msg_max_len, *msg_len);

	ret = knot_rrset_to_wire(tmp_tsig, msg + *msg_len,
	                         msg_max_len - *msg_len, NULL);
	if (ret < 0) {
		knot_rrset_free(&tmp_tsig, NULL);
		*digest_len = 0;
		return ret;
	}

	size_t tsig_wire_size = ret;

	knot_rrset_free(&tmp_tsig, NULL);

	*msg_len += tsig_wire_size;
	uint16_t arcount = knot_wire_get_arcount(msg);
	knot_wire_set_arcount(msg, ++arcount);

	memcpy(digest, digest_tmp, digest_tmp_len);
	*digest_len = digest_tmp_len;

	return KNOT_EOK;
}

static int knot_tsig_check_digest(const knot_rrset_t *tsig_rr,
                                  const uint8_t *wire, size_t size,
                                  const uint8_t *request_mac,
                                  size_t request_mac_len,
                                  const knot_tsig_key_t *tsig_key,
                                  uint64_t prev_time_signed,
                                  int use_times)
{
	if (!wire || !tsig_key) {
		return KNOT_EINVAL;
	}

	/* No TSIG record means verification failure. */
	if (tsig_rr == NULL) {
		return KNOT_TSIG_EBADKEY;
	}

	/* Check that libknot knows the algorithm. */
	int ret = knot_tsig_check_algorithm(tsig_rr);
	if (ret != KNOT_EOK) {
		return ret;
	}

	dbg_tsig_verb("TSIG: algorithm checked.\n");

	/* Check that key is valid, ie. the same as given in args. */
	ret = knot_tsig_check_key(tsig_rr, tsig_key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	dbg_tsig_verb("TSIG: key validity checked.\n");

	uint8_t *wire_to_sign = malloc(sizeof(uint8_t) * size);
	if (!wire_to_sign) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	memset(wire_to_sign, 0, sizeof(uint8_t) * size);
	memcpy(wire_to_sign, wire, size);

	uint8_t digest_tmp[KNOT_TSIG_MAX_DIGEST_SIZE];
	size_t digest_tmp_len = 0;
	assert(tsig_rr->rrs.rr_count > 0);

	if (use_times) {
		/* Wire is not a single packet, TSIG RRs must be stripped already. */
		ret = knot_tsig_create_sign_wire_next(wire_to_sign, size,
		                                 request_mac, request_mac_len,
		                                 digest_tmp, &digest_tmp_len,
		                                 tsig_rr, tsig_key);
	} else {
		ret = knot_tsig_create_sign_wire(wire_to_sign, size,
		                                 request_mac, request_mac_len,
		                                 digest_tmp, &digest_tmp_len,
		                                 tsig_rr, tsig_key);
	}

	assert(tsig_rr->rrs.rr_count > 0);
	free(wire_to_sign);

	if (ret != KNOT_EOK) {
		dbg_tsig("Failed to create wire format for checking: %s.\n",
		         knot_strerror(ret));
		return ret;
	}

	dbg_tsig_verb("TSIG: digest calculated\n");

	/* Compare MAC from TSIG RR RDATA with just computed digest. */

	/*!< \todo move to function. */
	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	knot_tsig_algorithm_t alg = tsig_alg_from_name(alg_name);

	/*! \todo [TSIG] TRUNCATION */
	uint16_t mac_length = tsig_rdata_mac_length(tsig_rr);
	const uint8_t *tsig_mac = tsig_rdata_mac(tsig_rr);

	if (mac_length != knot_tsig_digest_length(alg)) {
		dbg_tsig("TSIG: calculated digest length and given length do "
		         "not match!\n");
		return KNOT_TSIG_EBADSIG;
	}

	dbg_tsig_verb("TSIG: calc digest :\n");
	dbg_tsig_hex_verb((char *)digest_tmp, digest_tmp_len);

	dbg_tsig_verb("TSIG: given digest:\n");
	dbg_tsig_hex_verb((char *)tsig_mac, mac_length);

	if (memcmp(tsig_mac, digest_tmp, mac_length) != 0) {
		return KNOT_TSIG_EBADSIG;
	}

	/* Check time signed. */
	ret = knot_tsig_check_time_signed(tsig_rr, prev_time_signed);
	if (ret != KNOT_EOK) {
		return ret;
	}

	dbg_tsig_verb("TSIG: time checked.\n");

	return KNOT_EOK;
}

int knot_tsig_server_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const knot_tsig_key_t *tsig_key)
{
	dbg_tsig("tsig_server_check()\n");
	return knot_tsig_check_digest(tsig_rr, wire, size, NULL, 0, tsig_key,
	                              0, 0);
}

int knot_tsig_client_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const uint8_t *request_mac, size_t request_mac_len,
                           const knot_tsig_key_t *tsig_key,
                           uint64_t prev_time_signed)
{
	dbg_tsig("tsig_client_check()\n");
	return knot_tsig_check_digest(tsig_rr, wire, size, request_mac,
	                              request_mac_len, tsig_key,
	                              prev_time_signed, 0);
}

int knot_tsig_client_check_next(const knot_rrset_t *tsig_rr,
                                const uint8_t *wire, size_t size,
                                const uint8_t *prev_digest,
                                size_t prev_digest_len,
                                const knot_tsig_key_t *tsig_key,
                                uint64_t prev_time_signed)
{
	dbg_tsig("tsig_client_check_next()\n");
	return knot_tsig_check_digest(tsig_rr, wire, size, prev_digest,
	                              prev_digest_len, tsig_key,
	                              prev_time_signed, 1);
}

int knot_tsig_add(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                  uint16_t tsig_rcode, const knot_rrset_t *tsig_rr)
{
	/*! \todo Revise!! */

	if (!msg || !msg_len || !tsig_rr) {
		return KNOT_EINVAL;
	}

	/*! \todo What key to use, when we do not sign? Does this even work? */
	knot_rrset_t *tmp_tsig =
		knot_rrset_new(tsig_rr->owner, KNOT_RRTYPE_TSIG,
		               KNOT_CLASS_ANY, NULL);
	if (!tmp_tsig) {
		dbg_tsig("TSIG: tmp_tsig = NULL\n");
		return KNOT_ENOMEM;
	}

	assert(tsig_rcode != KNOT_TSIG_ERR_BADTIME);
	tsig_create_rdata(tmp_tsig, tsig_rdata_alg_name(tsig_rr), 0, tsig_rcode);
	tsig_rdata_set_time_signed(tmp_tsig, tsig_rdata_time_signed(tsig_rr));

	/* Comparing to BIND it was found out that the Fudge should always be
	 * set to the server's value.
	 */
	tsig_rdata_set_fudge(tmp_tsig, KNOT_TSIG_FUDGE_DEFAULT);

	/* Set original ID */
	tsig_rdata_set_orig_id(tmp_tsig, knot_wire_get_id(msg));

	/* Set other len. */
	tsig_rdata_set_other_data(tmp_tsig, 0, 0);

	/* Append TSIG RR. */
	int ret = knot_tsig_append(msg, msg_len, msg_max_len, tmp_tsig);

	/* key_name already referenced in RRSet, no need to free separately. */
	knot_rrset_free(&tmp_tsig, NULL);

	return ret;
}

int knot_tsig_append(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                     const knot_rrset_t *tsig_rr)
{
	/* Write RRSet to wire */
	int ret = knot_rrset_to_wire(tsig_rr, msg + *msg_len,
	                             msg_max_len - *msg_len, NULL);
	if (ret < 0) {
		dbg_tsig("TSIG: rrset_to_wire = %s\n", knot_strerror(ret));
		return ret;
	}

	*msg_len += ret;

	knot_wire_set_arcount(msg, knot_wire_get_arcount(msg) + 1);

	return KNOT_EOK;
}
