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
#include <ctype.h>

#include "common.h"
#include "tsig.h"
#include "tsig-op.h"
#include "util/wire.h"
#include "util/error.h"
#include "util/debug.h"


static const char Base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char Pad64 = '=';


static int b64rmap_initialized = 0;
static uint8_t b64rmap[256];

static const uint8_t b64rmap_special = 0xf0;
static const uint8_t b64rmap_end = 0xfd;
static const uint8_t b64rmap_space = 0xfe;
static const uint8_t b64rmap_invalid = 0xff;

/**
 * Initializing the reverse map is not thread safe.
 * Which is fine for NSD. For now...
 **/
void b64_initialize_rmap()
{
	int i;
	char ch;

	/* Null: end of string, stop parsing */
	b64rmap[0] = b64rmap_end;

	for (i = 1; i < 256; ++i) {
		ch = (char)i;
		/* Whitespaces */
		if (isspace(ch)) {
			b64rmap[i] = b64rmap_space;
		}
		/* Padding: stop parsing */
		else if (ch == Pad64) {
			b64rmap[i] = b64rmap_end;
		}
		/* Non-base64 char */
		else {
			b64rmap[i] = b64rmap_invalid;
		}
	}

	/* Fill reverse mapping for base64 chars */
	for (i = 0; Base64[i] != '\0'; ++i) {
		b64rmap[(uint8_t)Base64[i]] = i;
	}

	b64rmap_initialized = 1;
}

int b64_pton_do(char const *src, uint8_t *target, size_t targsize)
{
	int tarindex, state, ch;
	uint8_t ofs;

	state = 0;
	tarindex = 0;

	while (1) {
		ch = *src++;
		ofs = b64rmap[ch];

		if (ofs >= b64rmap_special) {
			/* Ignore whitespaces */
			if (ofs == b64rmap_space) {
				continue;
			}
			/* End of base64 characters */
			if (ofs == b64rmap_end) {
				break;
			}
			/* A non-base64 character. */
			return (-1);
		}

		switch (state) {
		case 0:
			if ((size_t)tarindex >= targsize) {
				return (-1);
			}
			target[tarindex] = ofs << 2;
			state = 1;
			break;
		case 1:
			if ((size_t)tarindex + 1 >= targsize) {
				return (-1);
			}
			target[tarindex]   |=  ofs >> 4;
			target[tarindex+1]  = (ofs & 0x0f)
					      << 4 ;
			tarindex++;
			state = 2;
			break;
		case 2:
			if ((size_t)tarindex + 1 >= targsize) {
				return (-1);
			}
			target[tarindex]   |=  ofs >> 2;
			target[tarindex+1]  = (ofs & 0x03)
					      << 6;
			tarindex++;
			state = 3;
			break;
		case 3:
			if ((size_t)tarindex >= targsize) {
				return (-1);
			}
			target[tarindex] |= ofs;
			tarindex++;
			state = 0;
			break;
		default:
			abort();
		}
	}

	/*
	 * We are done decoding Base-64 chars.  Let's see if we ended
	 * on a byte boundary, and/or with erroneous trailing characters.
	 */

	if (ch == Pad64) {		/* We got a pad char. */
		ch = *src++;		/* Skip it, get next. */
		switch (state) {
		case 0:		/* Invalid = in first position */
		case 1:		/* Invalid = in second position */
			return (-1);

		case 2:		/* Valid, means one byte of info */
			/* Skip any number of spaces. */
			for ((void)NULL; ch != '\0'; ch = *src++)
				if (b64rmap[ch] != b64rmap_space) {
					break;
				}
			/* Make sure there is another trailing = sign. */
			if (ch != Pad64) {
				return (-1);
			}
			ch = *src++;		/* Skip the = */
			/* Fall through to "single trailing =" case. */
			/* FALLTHROUGH */

		case 3:		/* Valid, means two bytes of info */
			/*
			 * We know this char is an =.  Is there anything but
			 * whitespace after it?
			 */
			for ((void)NULL; ch != '\0'; ch = *src++)
				if (b64rmap[ch] != b64rmap_space) {
					return (-1);
				}

			/*
			 * Now make sure for cases 2 and 3 that the "extra"
			 * bits that slopped past the last full byte were
			 * zeros.  If we don't check them, they become a
			 * subliminal channel.
			 */
			if (target[tarindex] != 0) {
				return (-1);
			}
		}
	} else {
		/*
		 * We ended by seeing the end of the string.  Make sure we
		 * have no partial bytes lying around.
		 */
		if (state != 0) {
			return (-1);
		}
	}

	return (tarindex);
}


int b64_pton_len(char const *src)
{
	int tarindex, state, ch;
	uint8_t ofs;

	state = 0;
	tarindex = 0;

	while (1) {
		ch = *src++;
		ofs = b64rmap[ch];

		if (ofs >= b64rmap_special) {
			/* Ignore whitespaces */
			if (ofs == b64rmap_space) {
				continue;
			}
			/* End of base64 characters */
			if (ofs == b64rmap_end) {
				break;
			}
			/* A non-base64 character. */
			return (-1);
		}

		switch (state) {
		case 0:
			state = 1;
			break;
		case 1:
			tarindex++;
			state = 2;
			break;
		case 2:
			tarindex++;
			state = 3;
			break;
		case 3:
			tarindex++;
			state = 0;
			break;
		default:
			abort();
		}
	}

	/*
	 * We are done decoding Base-64 chars.  Let's see if we ended
	 * on a byte boundary, and/or with erroneous trailing characters.
	 */

	if (ch == Pad64) {		/* We got a pad char. */
		ch = *src++;		/* Skip it, get next. */
		switch (state) {
		case 0:		/* Invalid = in first position */
		case 1:		/* Invalid = in second position */
			return (-1);

		case 2:		/* Valid, means one byte of info */
			/* Skip any number of spaces. */
			for ((void)NULL; ch != '\0'; ch = *src++)
				if (b64rmap[ch] != b64rmap_space) {
					break;
				}
			/* Make sure there is another trailing = sign. */
			if (ch != Pad64) {
				return (-1);
			}
			ch = *src++;		/* Skip the = */
			/* Fall through to "single trailing =" case. */
			/* FALLTHROUGH */

		case 3:		/* Valid, means two bytes of info */
			/*
			 * We know this char is an =.  Is there anything but
			 * whitespace after it?
			 */
			for ((void)NULL; ch != '\0'; ch = *src++)
				if (b64rmap[ch] != b64rmap_space) {
					return (-1);
				}

		}
	} else {
		/*
		 * We ended by seeing the end of the string.  Make sure we
		 * have no partial bytes lying around.
		 */
		if (state != 0) {
			return (-1);
		}
	}

	return (tarindex);
}

int b64_pton(char const *src, uint8_t *target, size_t targsize)
{
	if (!b64rmap_initialized) {
		b64_initialize_rmap();
	}

	if (target) {
		return b64_pton_do(src, target, targsize);
	} else {
		return b64_pton_len(src);
	}
}

#define	B64BUFSIZE	65535	/*!< Buffer size for b64 conversion. */












const int KNOT_TSIG_MAX_DIGEST_SIZE = 64;    // size of HMAC-SHA512 digest


static int knot_tsig_check_algorithm(const knot_rrset_t *tsig_rr)
{
	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	if (!alg_name) {
		return KNOT_EMALF;
	}

	tsig_algorithm_t alg = tsig_alg_from_name(alg_name);
	if (alg == 0) {
		/*!< \todo is this error OK? */
		dbg_tsig("TSIG: unknown algorithm.\n");
		return KNOT_TSIG_EBADSIG;
	}

	return KNOT_EOK;
}

static int knot_tsig_check_key(const knot_rrset_t *tsig_rr,
                               const knot_key_t *tsig_key)
{
	const knot_dname_t *tsig_name = knot_rrset_owner(tsig_rr);
	if (!tsig_name) {
		return KNOT_EMALF;
	}

	const char *name = knot_dname_to_str(tsig_name);
	if (!name) {
		return KNOT_EMALF;
	}

	if (knot_dname_compare(tsig_name, tsig_key->name) != 0) {
		/*!< \todo which error. */
		dbg_tsig("TSIG: unknown key: %s\n", name);
		return KNOT_TSIG_EBADKEY;
	}

	return KNOT_EOK;
}

static int knot_tsig_compute_digest(const uint8_t *wire, size_t wire_len,
                                    uint8_t *digest, size_t *digest_len,
                                    const knot_key_t *key)
{
	if (!wire || !digest || !digest_len || !key) {
		dbg_tsig("TSIG: digest: bad args.\n");
		return KNOT_EBADARG;
	}

	if (!key->name) {
		dbg_tsig("TSIG: digest: no algorithm\n");
		return KNOT_EMALF;
	}

	tsig_algorithm_t tsig_alg = key->algorithm;
	if (tsig_alg == 0) {
		dbg_tsig("TSIG: digest: unknown algorithm\n");
		return KNOT_TSIG_EBADSIG;
	}

	/* Create digest, using length of the algorithm. */
//	*digest = malloc(sizeof(uint8_t) * tsig_alg_digest_length(tsig_alg));
//	if (!digest) {
//		ERR_ALLOC_FAILED;
//		return KNOT_ENOMEM;
//	}

	/* Decode key from Base64. */
	char decoded_key[B64BUFSIZE];

	int decoded_key_size = b64_pton(key->secret, (uint8_t *)decoded_key,
					B64BUFSIZE);
	if (decoded_key_size < 0) {
		dbg_tsig("TSIG: Could not decode Base64\n");
		return KNOT_EMALF;
	}

	dbg_tsig("TSIG: decoded key size: %d\n", decoded_key_size);
	dbg_tsig("TSIG: decoded key: '%*s'\n", decoded_key_size, decoded_key);

	dbg_tsig("TSIG: using this wire for digest calculation\n");

	//dbg_tsig_hex(wire, wire_len);

	/* Compute digest. */
	HMAC_CTX ctx;

	switch (tsig_alg) {
		case KNOT_TSIG_ALG_HMAC_MD5:
			HMAC_Init(&ctx, decoded_key,
			          decoded_key_size, EVP_md5());
			break;
		default:
			return KNOT_ENOTSUP;
	} /* switch */

	unsigned tmp_dig_len = *digest_len;
	HMAC_Update(&ctx, (const unsigned char *)wire, wire_len);
	HMAC_Final(&ctx, digest, &tmp_dig_len);
	*digest_len = tmp_dig_len;

	return KNOT_EOK;
}

static int knot_tsig_check_time_signed(const knot_rrset_t *tsig_rr)
{
	if (!tsig_rr) {
		return KNOT_EBADARG;
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
	if (difftime(curr_time, (time_t)time_signed) > fudge) {
		return KNOT_TSIG_EBADTIME;
	}

	return KNOT_EOK;
}

static int knot_tsig_write_tsig_timers(uint8_t *wire, 
                                       const knot_rrset_t *tsig_rr)
{
	// put time signed
	knot_wire_write_u48(wire, tsig_rdata_time_signed(tsig_rr));
	
	// put fudge
	knot_wire_write_u16(wire + 6, tsig_rdata_fudge(tsig_rr));
	
	return KNOT_EOK;
}

static int knot_tsig_write_tsig_variables(uint8_t *wire,
                                         const knot_rrset_t *tsig_rr)
{
	/* Copy TSIG variables - starting with key name. */
	const knot_dname_t *tsig_owner = knot_rrset_owner(tsig_rr);
	if (!tsig_owner) {
		dbg_tsig("TSIG: write variables: no owner.\n");
		return KNOT_EBADARG;
	}

	int offset = 0;

	memcpy(wire + offset, knot_dname_name(tsig_owner),
	       sizeof(uint8_t) * knot_dname_size(tsig_owner));
	dbg_tsig("TSIG: write variables: written owner (tsig alg): \n");
	         /*knot_rrset_class(tsig_rr));*/
	dbg_tsig_hex_detail(wire + offset, knot_dname_size(tsig_owner));
	offset += knot_dname_size(tsig_owner);

	/*!< \todo which order? */

	/* Copy class. */
	knot_wire_write_u16(wire + offset, knot_rrset_class(tsig_rr));
	dbg_tsig("TSIG: write variables: written CLASS: %u - ",
	         knot_rrset_class(tsig_rr));
	dbg_tsig_hex_detail(wire + offset, sizeof(uint16_t));
	offset += sizeof(uint16_t);

	/* Copy TTL - always 0. */
	knot_wire_write_u32(wire + offset, knot_rrset_ttl(tsig_rr));
	dbg_tsig("TSIG: write variables: written TTL: %u - ",
	         knot_rrset_ttl(tsig_rr));
	dbg_tsig_hex_detail(wire + offset, sizeof(uint32_t));
	offset += sizeof(uint32_t);

	/* Copy alg name. */
	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	if (!alg_name) {
		dbg_tsig("TSIG: write variables: no algorithm name.\n");
		return KNOT_EBADARG;
	}
//	alg_name = knot_dname_new_from_str("HMAC-MD5.SIG-ALG.REG.INT.",
					   //strlen("HMAC-MD5.SIG-ALG.REG.INT."),
					   //NULL);

	memcpy(wire + offset, knot_dname_name(alg_name),
	       sizeof(uint8_t) * knot_dname_size(alg_name));
	offset += knot_dname_size(alg_name);
	dbg_tsig_detail("TSIG: write variables: written alg name: %s\n",
		 knot_dname_to_str(alg_name));

	/* Following data are written in network order. */
	/* Time signed. */
	knot_wire_write_u48(wire + offset, tsig_rdata_time_signed(tsig_rr));
	offset += 6;
	dbg_tsig_detail("TSIG: write variables: time signed: %llu - ",
		        tsig_rdata_time_signed(tsig_rr));
	dbg_tsig_hex_detail(wire + offset - 6, 6);
	/* Fudge. */
	knot_wire_write_u16(wire + offset, tsig_rdata_fudge(tsig_rr));
	offset += sizeof(uint16_t);
	dbg_tsig_detail("TSIG: write variables: fudge: %hu\n",
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
		return KNOT_EBADARG;
	}

	/*
	 * We cannot write the whole other_data, as it contains its length in
	 * machine order.
	 */
	knot_wire_write_u16(wire + offset, other_data_length);
	offset += sizeof(uint16_t);

	/* Skip the length. */
	dbg_tsig_detail("Copying other data.\n");
	memcpy(wire + offset, other_data, other_data_length);

	return KNOT_EOK;
}

static int knot_tsig_wire_write_timers(uint8_t *wire,
                                       const knot_rrset_t *tsig_rr)
{
	knot_wire_write_u48(wire, tsig_rdata_time_signed(tsig_rr));
	knot_wire_write_u16(wire + 6, tsig_rdata_fudge(tsig_rr));

	return KNOT_EOK;
}

int knot_tsig_create_sign_wire(const uint8_t *msg, size_t msg_len,
				      /*size_t msg_max_len, */const uint8_t *request_mac,
		                      size_t request_mac_len,
		                      uint8_t *digest, size_t *digest_len,
				      const knot_rrset_t *tmp_tsig,
		                      const knot_key_t *key)
{
	if (!msg || !key || digest_len == NULL) {
		dbg_tsig("TSIG: create wire: bad args.\n");
		return KNOT_EBADARG;
	}

	/* Create tmp TSIG. */
	int ret = KNOT_EOK;
//	knot_rrset_t *tmp_tsig =
//		knot_rrset_new(key->name, KNOT_RRTYPE_TSIG, KNOT_CLASS_ANY, 0);
//	if (!tmp_tsig) {
//		return KNOT_ENOMEM;
//	}

//	tsig_rdata_store_current_time(tmp_tsig);

	/*
	 * Create tmp wire, it should contain message
	 * plus request mac plus tsig varibles.
	 */
	dbg_tsig("Counting wire size: %zu, %zu, %zu.\n",
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
		dbg_tsig_detail("Copying request MAC size\n");
		knot_wire_write_u16(pos, request_mac_len);
		pos += 2;
	}
	dbg_tsig("Copying request mac.\n");
	memcpy(pos, request_mac, sizeof(uint8_t) * request_mac_len);
	dbg_tsig_detail("TSIG: create wire: request mac: ");
	dbg_tsig_hex_detail(pos, request_mac_len);
	pos += request_mac_len;
	/* Copy the original message. */
	dbg_tsig("Copying original message.\n");
	memcpy(pos, msg, msg_len);
	dbg_tsig_detail("TSIG: create wire: original message: \n");
	//dbg_tsig_hex_detail(pos, msg_len);
	pos += msg_len;
	/* Copy TSIG variables. */
	dbg_tsig("Writing TSIG variables.\n");
	ret = knot_tsig_write_tsig_variables(pos, tmp_tsig);
	if (ret != KNOT_EOK) {
		dbg_tsig("TSIG: create wire: failed to write TSIG "
		         "variables: %s\n", knot_strerror(ret));
		return ret;
	}

	/* Compute digest. */
	ret = knot_tsig_compute_digest(wire, wire_len,
	                               digest, digest_len, key);
	if (ret != KNOT_EOK) {
		dbg_tsig("TSIG: create wire: failed to compute digest: %s\n",
		         knot_strerror(ret));
		*digest_len = 0;
		return ret;
	}

//	assert(digest_tmp_len > 0);
	free(wire);

//	if (digest_tmp_len > *digest_len) {
//		*digest_len = 0;
//		return KNOT_ESPACE;
//	}

//	knot_rrset_deep_free(&tmp_tsig, 1, 1, 1);

	// everything went ok, save the digest to the output parameter
//	memcpy(digest, digest_tmp, digest_tmp_len);
//	*digest_len = digest_tmp_len;

	return KNOT_EOK;
}

static int knot_tsig_create_sign_wire_next(const uint8_t *msg, size_t msg_len,
				      const uint8_t *prev_mac,
		                      size_t prev_mac_len,
		                      uint8_t *digest, size_t *digest_len,
				      const knot_rrset_t *tmp_tsig,
		                      const knot_key_t *key)
{
	if (!msg || !key || digest_len == NULL) {
		dbg_tsig("TSIG: create wire: bad args.\n");
		return KNOT_EBADARG;
	}

	/* Create tmp TSIG. */
	int ret = KNOT_EOK;

	/*
	 * Create tmp wire, it should contain message
	 * plus request mac plus tsig varibles.
	 */
	dbg_tsig("Counting wire size: %zu, %zu, %zu.\n",
	         msg_len, prev_mac_len,
	         tsig_rdata_tsig_timers_length());
	size_t wire_len = sizeof(uint8_t) *
	                (msg_len + prev_mac_len +
			tsig_rdata_tsig_timers_length());
	uint8_t *wire = malloc(wire_len);
	if (!wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	memset(wire, 0, wire_len);

	/* Copy the request MAC - should work even if NULL. */
	dbg_tsig("Copying request mac.\n");
	memcpy(wire, prev_mac, sizeof(uint8_t) * prev_mac_len);
	dbg_tsig_detail("TSIG: create wire: request mac: ");
	dbg_tsig_hex_detail(wire, prev_mac_len);
	/* Copy the original message. */
	dbg_tsig("Copying original message.\n");
	memcpy(wire + prev_mac_len, msg, msg_len);
	dbg_tsig_detail("TSIG: create wire: original message: \n");
	//dbg_tsig_hex_detail(wire + prev_mac_len, msg_len);
	/* Copy TSIG variables. */
	
	dbg_tsig("Writing TSIG timers.\n");
	ret = knot_tsig_write_tsig_timers(wire + prev_mac_len + msg_len, 
	                                  tmp_tsig);
//	ret = knot_tsig_write_tsig_variables(wire + prev_mac_len + msg_len,
//	                                     tmp_tsig);
	if (ret != KNOT_EOK) {
		dbg_tsig("TSIG: create wire: failed to write TSIG "
		         "timers: %s\n", knot_strerror(ret));
		return ret;
	}

	/* Compute digest. */
	ret = knot_tsig_compute_digest(wire, wire_len,
	                               digest, digest_len, key);
	if (ret != KNOT_EOK) {
		dbg_tsig("TSIG: create wire: failed to compute digest: %s\n",
		         knot_strerror(ret));
		*digest_len = 0;
		return ret;
	}

	free(wire);

	return KNOT_EOK;
}

int knot_tsig_sign(uint8_t *msg, size_t *msg_len,
                   size_t msg_max_len, const uint8_t *request_mac,
                   size_t request_mac_len,
                   uint8_t *digest, size_t *digest_len,
                   const knot_key_t *key)
{
	if (!msg || !msg_len || !key || digest == NULL || digest_len == NULL) {
		return KNOT_EBADARG;
	}

	knot_dname_t *key_name_copy = knot_dname_deep_copy(key->name);
	if (!key_name_copy) {
		dbg_tsig_detail("TSIG: key_name_copy = NULL\n");
		return KNOT_ENOMEM;
	}

	knot_rrset_t *tmp_tsig =
		knot_rrset_new(key_name_copy,
			       KNOT_RRTYPE_TSIG, KNOT_CLASS_ANY, 0);
	if (!tmp_tsig) {
		dbg_tsig_detail("TSIG: tmp_tsig = NULL\n");
		return KNOT_ENOMEM;
	}

	/* Create rdata for TSIG RR. */
	knot_rdata_t *rdata = knot_rdata_new();
	if (!rdata) {
		dbg_tsig_detail("TSIG: rdata = NULL\n");
		return KNOT_ENOMEM;
	}

	knot_rrset_add_rdata(tmp_tsig, rdata);

	/* Create items for TSIG RR. */
	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(KNOT_RRTYPE_TSIG);
	assert(desc);

	knot_rdata_item_t *items =
		malloc(sizeof(knot_rdata_item_t) * desc->length);
	if (!items) {
		dbg_tsig_detail("TSIG: items = NULL\n");
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	memset(items, 0, sizeof(knot_rdata_item_t) * desc->length);

	int ret = knot_rdata_set_items(rdata, items, desc->length);
	if (ret != KNOT_EOK) {
		dbg_tsig_detail("TSIG: rdata_set_items returned %s\n", knot_strerror(ret));
		return ret;
	}
	free(items);

	tsig_rdata_set_alg(tmp_tsig, key->algorithm);
	tsig_rdata_store_current_time(tmp_tsig);
	tsig_rdata_set_fudge(tmp_tsig, 300);

	/* Set original ID */
	tsig_rdata_set_orig_id(tmp_tsig, knot_wire_get_id(msg));

	/* Set error */
	/*! \todo [TSIG] Set error and other data if appropriate. */
	tsig_rdata_set_tsig_error(tmp_tsig, 0);

	/* Set other len. */
	tsig_rdata_set_other_data(tmp_tsig, 0, 0);

	uint8_t digest_tmp[KNOT_TSIG_MAX_DIGEST_SIZE];
	size_t digest_tmp_len = 0;

	dbg_tsig_detail("tmp_tsig before sign_wire():\n");
	knot_rrset_dump(tmp_tsig, 0);

	ret = knot_tsig_create_sign_wire(msg, *msg_len, /*msg_max_len,*/
	                                     request_mac, request_mac_len,
	                                     digest_tmp, &digest_tmp_len,
					     tmp_tsig, key);
	if (ret != KNOT_EOK) {
		dbg_tsig("TSIG: could not create wire or sign wire: %s\n",
		         knot_strerror(ret));
		return ret;
	}

	/* Set the digest. */
	size_t tsig_wire_len = msg_max_len - *msg_len;
	int rr_count = 0;
	tsig_rdata_set_mac(tmp_tsig, digest_tmp_len, digest_tmp);

	//knot_rrset_dump(tmp_tsig, 1);

	/* Write RRSet to wire */
	ret = knot_rrset_to_wire(tmp_tsig, msg + *msg_len,
	                         &tsig_wire_len, &rr_count);
	if (ret != KNOT_EOK) {
		dbg_tsig_detail("TSIG: rrset_to_wire = %s\n", knot_strerror(ret));
		*digest_len = 0;
		return ret;
	}

	knot_rrset_deep_free(&tmp_tsig, 1, 1, 1);

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
                        const knot_key_t *key)
{
	if (!msg || !msg_len || !key || !key || !digest || !digest_len) {
		return KNOT_EBADARG;
	}
	
	uint8_t digest_tmp[KNOT_TSIG_MAX_DIGEST_SIZE];
	size_t digest_tmp_len = 0;

	/* Create tmp TSIG. */
	knot_rrset_t *tmp_tsig =
		knot_rrset_new(key->name, KNOT_RRTYPE_TSIG, KNOT_CLASS_ANY, 0);
	if (!tmp_tsig) {
		return KNOT_ENOMEM;
	}

	tsig_rdata_store_current_time(tmp_tsig);

	/* Create wire to be signed. */
	size_t wire_len = prev_digest_len + *msg_len + KNOT_TSIG_TIMERS_LENGTH;
	uint8_t *wire = malloc(wire_len);
	if (!wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}
	memset(wire, 0, wire_len);

	/* Write previous digest. */
	memcpy(wire, prev_digest, sizeof(uint8_t) * prev_digest_len);
	/* Write original message. */
	memcpy(msg + prev_digest_len, msg, *msg_len);
	/* Write timers. */
	knot_tsig_wire_write_timers(msg + prev_digest_len + *msg_len, tmp_tsig);

	int ret = 0;
	ret = knot_tsig_compute_digest(wire, wire_len,
	                               digest_tmp, &digest_tmp_len, key);
	if (ret != KNOT_EOK) {
		*digest_len = 0;
		return ret;
	}
	
	if (digest_tmp_len > *digest_len) {
		*digest_len = 0;
		return KNOT_ESPACE;
	}

	free(wire);

	/* Set the MAC. */
	tsig_rdata_set_mac(tmp_tsig, *digest_len, digest);

	size_t tsig_wire_size = msg_max_len - *msg_len;
	int rr_count = 0;
	ret = knot_rrset_to_wire(tmp_tsig, msg + *msg_len,
	                         &tsig_wire_size, &rr_count);
	if (ret != KNOT_EOK) {
		*digest_len = 0;
		return ret;
	}

	knot_rrset_deep_free(&tmp_tsig, 1, 1, 1);

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
                                  const knot_key_t *tsig_key,
                                  int use_times)
{
	if (!tsig_rr || !wire || !tsig_key) {
		return KNOT_EBADARG;
	}

	/* Check time signed. */
	int ret = knot_tsig_check_time_signed(tsig_rr);
	if (ret != KNOT_EOK) {
		return ret;
	}

	dbg_tsig("TSIG: time checked.\n");

	/* Check that libknot knows the algorithm. */
	ret = knot_tsig_check_algorithm(tsig_rr);
	if (ret != KNOT_EOK) {
		return ret;
	}

	dbg_tsig("TSIG: algorithm checked.\n");

	/* Check that key is valid, ie. the same as given in args. */
	ret = knot_tsig_check_key(tsig_rr, tsig_key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	dbg_tsig("TSIG: key validity checked.\n");

	/* Time OK algorithm OK, key name OK - do digest. */
	/* Calculate the size of TSIG RR. */
	size_t tsig_len = tsig_wire_actsize(tsig_rr);

	dbg_tsig_detail("TSIG: check digest: wire before strip: \n");
	//dbg_tsig_hex_detail(wire, size);

	/* Strip the TSIG. */
	size -= tsig_len;

	dbg_tsig_detail("TSIG: check digest: wire after strip (stripped %zu):\n",
	                tsig_len);
	//dbg_tsig_hex_detail(wire, size);

	uint8_t *wire_to_sign = malloc(sizeof(uint8_t) * size);
	if (!wire_to_sign) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	memset(wire_to_sign, 0, sizeof(uint8_t) * size);
	memcpy(wire_to_sign, wire, size);

	/* Decrease arcount. */
	knot_wire_set_arcount(wire_to_sign,
	                      knot_wire_get_arcount(wire_to_sign) - 1);

	uint8_t digest_tmp[KNOT_TSIG_MAX_DIGEST_SIZE];
	size_t digest_tmp_len = 0;
	assert(tsig_rr->rdata);
	
	if (use_times) {
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

	assert(tsig_rr->rdata);
	free(wire_to_sign);

	if (ret != KNOT_EOK) {
		dbg_tsig("Failed to create wire format for checking: %s.\n",
		         knot_strerror(ret));
		return ret;
	}

//	uint8_t digest_tmp[KNOT_TSIG_MAX_DIGEST_SIZE];
//	size_t digest_tmp_len = 0;
//	ret = knot_tsig_compute_digest(wire, size, digest_tmp,
//	                               &digest_tmp_len, tsig_key);
//	if (ret != KNOT_EOK) {
//		dbg_tsig("TSIG: digest could not be calculated\n");
//		return ret;
//	}

	dbg_tsig("TSIG: digest calculated\n");

	/* Compare MAC from TSIG RR RDATA with just computed digest. */

	/*!< \todo move to function. */
	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	tsig_algorithm_t alg = tsig_alg_from_name(alg_name);

	/*! \todo [TSIG] TRUNCATION */
	uint16_t mac_length = tsig_rdata_mac_length(tsig_rr);
	const uint8_t *tsig_mac = tsig_rdata_mac(tsig_rr);

	if (mac_length != tsig_alg_digest_length(alg)) {
		dbg_tsig("TSIG: calculated digest length and given length do not match!\n");
		return KNOT_TSIG_EBADSIG;
	}

//	assert(tsig_alg_digest_length(alg) == mac_length);

	dbg_tsig("TSIG: calc digest : ");
	dbg_tsig_hex(digest_tmp, digest_tmp_len);

	dbg_tsig("TSIG: given digest: ");
	dbg_tsig_hex(tsig_mac, mac_length);

	if (strncasecmp((char *)(tsig_mac), (char *)digest_tmp,
	                mac_length) != 0) {
		return KNOT_TSIG_EBADSIG;
	}

	return KNOT_EOK;
}

int knot_tsig_server_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const knot_key_t *tsig_key)
{
	dbg_tsig_verb("tsig_server_check()\n");
	return knot_tsig_check_digest(tsig_rr, wire, size, NULL, 0, tsig_key, 0);
}

int knot_tsig_client_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const uint8_t *request_mac, size_t request_mac_len,
                           const knot_key_t *tsig_key)
{
	dbg_tsig_verb("tsig_client_check()\n");
	return knot_tsig_check_digest(tsig_rr, wire, size, request_mac,
	                              request_mac_len, tsig_key, 0);
}

int knot_tsig_client_check_next(const knot_rrset_t *tsig_rr,
                                const uint8_t *wire, size_t size,
                                const uint8_t *prev_digest,
                                size_t prev_digest_len,
                                const knot_key_t *tsig_key)
{
//	return knot_tsig_client_check(tsig_rr, wire, size, prev_digest,
//	                              prev_digest_len, tsig_key);
	dbg_tsig_verb("tsig_client_check_next()\n");
	return knot_tsig_check_digest(tsig_rr, wire, size, prev_digest,
	                              prev_digest_len, tsig_key, 1);
	return KNOT_ENOTSUP;
}
