/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "utils/kkeymgr/functions.h"

#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "dnssec/lib/dnssec/dnssec.h"
#include "dnssec/shared/shared.h"
#include "knot/dnssec/zone-keys.h"
#include "utils/kkeymgr/bind_privkey.h"
#include "zscanner/scanner.h"

static time_t arg_timestamp(const char *arg)
{
	if (isdigit(arg[0]) && strlen(arg) < 12) {
		return atol(arg); // unixtime
	}
	if (isdigit(arg[0]) && strlen(arg) == 14) {
		struct tm tm = { 0 };
		char *end = strptime(arg, "%Y%m%d%H%M%S", &tm);
		if (end == NULL || *end != '\0') {
			return -1;
		}
		return mktime(&tm); // time format
	}
	long amount;
	if (strncasecmp(arg, "now+", 4) == 0) {
		amount = atol(arg + 4);
	} else if (strncasecmp(arg, "now-", 4) == 0) {
		amount = 0 - atol(arg + 4);
	} else if (strncasecmp(arg, "t+", 2) == 0) {
		amount = atol(arg + 2);
	} else if (strncasecmp(arg, "t-", 2) == 0) {
		amount = 0 - atol(arg + 2);
	} else if (arg[0] == '+' || arg[0] == '-') {
		amount = atol(arg);
	} else {
		return -1;
	}
	char *unit = strrchr(arg, '0' + (labs(amount) % 10));
	if (unit++ == NULL) {
		return -1;
	}
	time_t now = time(NULL);
	switch ((*unit == 'm') ? *(unit + 1) : *unit) {
	case 'i':
		return now + amount * 60;
	case 'h':
		return now + amount * 3600;
	case 'd':
		return now + amount * 3600 * 24;
	case 'w':
		return now + amount * 3600 * 24 * 7;
	case 'o':
		return now + amount * 3600 * 24 * 30; // this is lame but same as keymgr
	case 'y':
		return now + amount * 3600 * 24 * 365;
	case '\0':
		return now + amount;
	}
	return -1;
}

static bool genkeyargs(int argc, char *argv[], bool *isksk, dnssec_key_algorithm_t *algorithm,
		       uint16_t *keysize, dnssec_kasp_key_timing_t *timing)
{
	// generate algorithms field
	char *algnames[256] = { 0 };
	algnames[DNSSEC_KEY_ALGORITHM_DSA_SHA1] = "dsa";
	algnames[DNSSEC_KEY_ALGORITHM_RSA_SHA1] = "rsasha1";
	algnames[DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3] = "dsansec3sha1";
	algnames[DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3] = "rsasha1nsec3sha1";
	algnames[DNSSEC_KEY_ALGORITHM_RSA_SHA256] = "rsasha256";
	algnames[DNSSEC_KEY_ALGORITHM_RSA_SHA512] = "rsasha512";
	algnames[DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256] = "ecdsap256sha256";
	algnames[DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384] = "ecdsap384sha384";

	// parse args
	for (int i = 0; i < argc; i++) {
		if (strncasecmp(argv[i], "algorithm=", 10) == 0) {
			if (isdigit(argv[i][10]) && atol(argv[i] + 10) < 256) {
				*algorithm = atol(argv[i] + 10);
				continue;
			}
			int al;
			for (al = 0; al < 256; al++) {
				if (algnames[al] != NULL &&
				    strcasecmp(argv[i] + 10, algnames[al]) == 0) {
					*algorithm = al;
					break;
				}
			}
			if (al == 256) {
				printf("Unknown algorithm: %s\n", argv[i] + 10);
				return false;
			}
		} else if (strncasecmp(argv[i], "ksk=", 4) == 0) {
			switch (tolower(argv[i][4])) {
			case '1':
			case 'y':
			case 't':
				*isksk = true;
				break;
			default:
				*isksk = false;
			}
		} else if (strncasecmp(argv[i], "size=", 5) == 0) {
			*keysize = atol(argv[i] + 5);
		} else if (strncasecmp(argv[i], "created=", 8) == 0 ||
			   strncasecmp(argv[i], "publish=", 8) == 0 ||
			   strncasecmp(argv[i], "active=", 7) == 0 ||
			   strncasecmp(argv[i], "retire=", 7) == 0 ||
			   strncasecmp(argv[i], "remove=", 7) == 0) {
			time_t stamp = arg_timestamp(strchr(argv[i], '=') + 1);
			if (stamp < 0) {
				printf("Invalid timestamp: %s\n", argv[i]);
				return false;
			}
			switch ((argv[i][0] == 'r') ? argv[i][2] : argv[i][0]) {
			case 'c':
				timing->created = stamp;
				break;
			case 'a':
				timing->active = stamp;
				break;
			case 'p':
				timing->publish = stamp;
				break;
			case 't':
				timing->retire = stamp;
				break;
			case 'm':
				timing->remove = stamp;
				break;
			}
		} else {
			printf("Invalid parameter: %s\n", argv[i]);
			return false;
		}
	}
	return true;
}

// modifies ctx->policy options, so don't do anything afterwards !
int kkeymgr_generate_key(kdnssec_ctx_t *ctx, int argc, char *argv[]) {
	time_t now = time(NULL), infty = 0x0fffffffffffff00LLU;
	dnssec_kasp_key_timing_t gen_timing = { now, now, now, infty, infty };
	bool isksk = false;
	uint16_t keysize = 0;
	if (!genkeyargs(argc, argv, &isksk, &ctx->policy->algorithm,
			&keysize, &gen_timing)) {
		return KNOT_EINVAL;
	}
	if (keysize > 0) {
		if (isksk) {
			ctx->policy->ksk_size = keysize;
		} else {
			ctx->policy->zsk_size = keysize;
		}
	}
	printf("alg %d\n", (int)ctx->policy->algorithm);

	dnssec_kasp_key_t *key = NULL;
	int ret = kdnssec_generate_key(ctx, isksk, &key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	key->timing = gen_timing;

	ret = kdnssec_ctx_commit(ctx);

	if (ret == KNOT_EOK) {
		printf("%s\n", key->id);
	}

	return ret;
}

static void parse_record(zs_scanner_t *scanner)
{
	dnssec_key_t *key = scanner->process.data;

	if (dnssec_key_get_dname(key) != NULL ||
	    scanner->r_type != KNOT_RRTYPE_DNSKEY) {
		scanner->state = ZS_STATE_STOP;
		return;
	}

	dnssec_binary_t rdata = {
		.data = scanner->r_data,
		.size = scanner->r_data_length
	};
	dnssec_key_set_dname(key, scanner->dname);
	dnssec_key_set_rdata(key, &rdata);
}

int bind_pubkey_parse(const char *filename, dnssec_key_t **key_ptr)
{
	dnssec_key_t *key = NULL;
	int result = dnssec_key_new(&key);
	if (result != DNSSEC_EOK) {
		return KNOT_ENOMEM;
	}

	uint16_t cls = KNOT_CLASS_IN;
	uint32_t ttl = 0;
	zs_scanner_t *scanner = malloc(sizeof(zs_scanner_t));
	if (scanner == NULL) {
		dnssec_key_free(key);
		return KNOT_ENOMEM;
	}

	if (zs_init(scanner, ".", cls, ttl) != 0 ||
	    zs_set_input_file(scanner, filename) != 0 ||
	    zs_set_processing(scanner, parse_record, NULL, key) != 0 ||
	    zs_parse_all(scanner) != 0) {
		zs_deinit(scanner);
		free(scanner);
		dnssec_key_free(key);
		return KNOT_ENOENT;
	}
	zs_deinit(scanner);
	free(scanner);

	if (dnssec_key_get_dname(key) == NULL) {
		dnssec_key_free(key);
		return KNOT_INVALID_PUBLIC_KEY;
	}

	*key_ptr = key;
	return KNOT_EOK;
}

static char *genname(const char *orig, const char *wantsuff, const char *altsuff)
{
	char *res;
	if (orig == NULL || wantsuff == NULL || altsuff == NULL ||
	    (res = malloc(strlen(orig) + strlen(wantsuff) + 1)) == NULL) {
		return NULL;
	}
	strcpy(res, orig);
	char *dot = strrchr(res, '.');
	if (dot != NULL && strcmp(dot, wantsuff) == 0) {
		;
	} else if (dot != NULL && strcmp(dot, altsuff) == 0) {
		strcpy(dot, wantsuff);
	} else {
		strcat(res, wantsuff);
	}
	return res;
}

int kkeymgr_import_bind(kdnssec_ctx_t *ctx, const char *import_file)
{
	char *pubname = genname(import_file, ".key", ".private");
	char *privname = genname(import_file, ".private", ".key");
	if (ctx == NULL || import_file == NULL || pubname == NULL || privname == NULL) {
		free(pubname);
		free(privname);
		return KNOT_EINVAL;
	}

	char *keyid = NULL;
	dnssec_key_t *key = NULL;
	int ret = KNOT_EOK;
	printf("kkib %s %s\n", pubname, privname);

	ret = bind_pubkey_parse(pubname, &key);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	bind_privkey_t bpriv = { 0 };
	ret = bind_privkey_parse(privname, &bpriv);
	if (ret != DNSSEC_EOK) {
		goto fail;
	}

	dnssec_binary_t pem = { 0 };
	ret = bind_privkey_to_pem(key, &bpriv, &pem);
	if (ret != DNSSEC_EOK) {
		bind_privkey_free(&bpriv);
		goto fail;
	}

	dnssec_kasp_key_timing_t timing = { 0 };
	bind_privkey_to_timing(&bpriv, &timing); // time created remains always zero

	bind_privkey_free(&bpriv);

	ret = dnssec_keystore_import(ctx->keystore, &pem, &keyid);
	if (ret != DNSSEC_EOK) {
		goto fail;
	}

	dnssec_kasp_key_t *kkey = calloc(1, sizeof(*kkey));
	if (!kkey) {
		ret = KNOT_ENOMEM;
		goto fail;
	}

	kkey->id = keyid;
	kkey->key = key;
	kkey->timing = timing;

	ret = kasp_zone_append(ctx->zone, kkey);
	free(kkey);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	ret = kdnssec_ctx_commit(ctx);
	// ret fallthrough

	if (ret == KNOT_EOK) {
		printf("%s\n", keyid);
	}

	goto cleanup;

fail:
	dnssec_key_free(key);
	free(keyid);
cleanup:
	free(pubname);
	free(privname);
	return knot_error_from_libdnssec(ret);
}

static void print_tsig(dnssec_tsig_algorithm_t mac, const char *name,
		       const dnssec_binary_t *secret)
{
	assert(name);
	assert(secret);

	const char *mac_name = dnssec_tsig_algorithm_to_name(mac);
	assert(mac_name);

	// client format (as a comment)
	printf("# %s:%s:%.*s\n", mac_name, name, (int)secret->size, secret->data);

	// server format
	printf("key:\n");
	printf("  - id: %s\n", name);
	printf("    algorithm: %s\n", mac_name);
	printf("    secret: %.*s\n", (int)secret->size, secret->data);
}

int kkeymgr_generate_tsig(const char *tsig_name, const char *alg_name, int bits)
{
	dnssec_tsig_algorithm_t alg = dnssec_tsig_algorithm_from_name(alg_name);
	if (alg == DNSSEC_TSIG_UNKNOWN) {
		return KNOT_INVALID_KEY_ALGORITHM;
	}

	int optimal_bits = dnssec_tsig_optimal_key_size(alg);
	if (bits == 0) {
		bits = optimal_bits; // TODO review
	}

	// round up bits to bytes
	bits = (bits + CHAR_BIT - 1) / CHAR_BIT * CHAR_BIT;

	if (bits != optimal_bits) {
		printf("Notice: Optimal key size for %s is %d bits.",
		       dnssec_tsig_algorithm_to_name(alg), optimal_bits);
	}
	assert(bits % CHAR_BIT == 0);

	_cleanup_binary_ dnssec_binary_t key = { 0 };
	int r = dnssec_binary_alloc(&key, bits / CHAR_BIT);
	if (r != DNSSEC_EOK) {
		printf("Failed to allocate memory.");
		return knot_error_from_libdnssec(r);
	}

	r = gnutls_rnd(GNUTLS_RND_KEY, key.data, key.size);
	if (r != 0) {
		printf("Failed to generate secret the key.");
		return knot_error_from_libdnssec(r);
	}

	_cleanup_binary_ dnssec_binary_t key_b64 = { 0 };
	r = dnssec_binary_to_base64(&key, &key_b64);
	if (r != DNSSEC_EOK) {
		printf("Failed to convert the key to Base64.");
		return knot_error_from_libdnssec(r);
	}

	print_tsig(alg, tsig_name, &key_b64);

	return KNOT_EOK;
}
