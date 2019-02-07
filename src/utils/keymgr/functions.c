/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <limits.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <fcntl.h>

#include "utils/keymgr/functions.h"
#include "utils/keymgr/bind_privkey.h"
#include "contrib/base64.h"
#include "contrib/ctype.h"
#include "contrib/string.h"
#include "contrib/strtonum.h"
#include "contrib/tolower.h"
#include "contrib/wire_ctx.h"
#include "libdnssec/error.h"
#include "libdnssec/keyid.h"
#include "libdnssec/shared/shared.h"
#include "knot/dnssec/kasp/policy.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-sign.h"
#include "libzscanner/scanner.h"

int parse_timestamp(char *arg, knot_time_t *stamp)
{
	int ret = knot_time_parse("YMDhms|'now'+-#u|'t'+-#u|+-#u|'t'+-#|+-#|#",
	                          arg, stamp);
	if (ret < 0) {
		printf("Invalid timestamp: %s\n", arg);
		return KNOT_EINVAL;
	}
	return KNOT_EOK;
}

static bool init_timestamps(char *arg, knot_kasp_key_timing_t *timing)
{
	knot_time_t *dst = NULL;

	if (strncasecmp(arg, "created=", 8) == 0) {
		dst = &timing->created;
	} else if (strncasecmp(arg, "publish=", 8) == 0) {
		dst = &timing->publish;
	} else if (strncasecmp(arg, "ready=", 6) == 0) {
		dst = &timing->ready;
	} else if (strncasecmp(arg, "active=", 7) == 0) {
		dst = &timing->active;
	} else if (strncasecmp(arg, "retire=", 7) == 0) {
		dst = &timing->retire;
	} else if (strncasecmp(arg, "remove=", 7) == 0) {
		dst = &timing->remove;
	} else if (strncasecmp(arg, "pre_active=", 11) == 0) {
		dst = &timing->pre_active;
	} else if (strncasecmp(arg, "post_active=", 12) == 0) {
		dst = &timing->post_active;
	} else if (strncasecmp(arg, "retire_active=", 14) == 0) {
		dst = &timing->retire_active;
	} else {
		return false;
	}

	knot_time_t stamp;
	int ret = parse_timestamp(strchr(arg, '=') + 1, &stamp);
	if (ret != KNOT_EOK) {
		return true;
	}

	*dst = stamp;

	return true;
}

static bool str2bool(const char *s)
{
	switch (knot_tolower(s[0])) {
	case '1':
	case 'y':
	case 't':
		return true;
	default:
		return false;
	}
}

static void bitmap_set(kdnssec_generate_flags_t *bitmap, int flag, bool onoff)
{
        if (onoff) {
                *bitmap |= flag;
        } else {
                *bitmap &= ~flag;
        }
}

static bool genkeyargs(int argc, char *argv[], bool just_timing,
                       kdnssec_generate_flags_t *flags, dnssec_key_algorithm_t *algorithm,
                       uint16_t *keysize, knot_kasp_key_timing_t *timing,
                       const char **addtopolicy)
{
	// generate algorithms field
	char *algnames[256] = { 0 };
	algnames[DNSSEC_KEY_ALGORITHM_RSA_SHA1] = "rsasha1";
	algnames[DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3] = "rsasha1nsec3sha1";
	algnames[DNSSEC_KEY_ALGORITHM_RSA_SHA256] = "rsasha256";
	algnames[DNSSEC_KEY_ALGORITHM_RSA_SHA512] = "rsasha512";
	algnames[DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256] = "ecdsap256sha256";
	algnames[DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384] = "ecdsap384sha384";
	algnames[DNSSEC_KEY_ALGORITHM_ED25519] = "ed25519";

	// parse args
	for (int i = 0; i < argc; i++) {
		if (!just_timing && strncasecmp(argv[i], "algorithm=", 10) == 0) {
			int alg = 256; // invalid value
			(void)str_to_int(argv[i] + 10, &alg, 0, 255);
			for (int al = 0; al < 256 && alg > 255; al++) {
				if (algnames[al] != NULL &&
				    strcasecmp(argv[i] + 10, algnames[al]) == 0) {
					alg = al;
				}
			}
			if (alg > 255) {
				printf("Unknown algorithm: %s\n", argv[i] + 10);
				return false;
			}
			*algorithm = alg;
		} else if (strncasecmp(argv[i], "ksk=", 4) == 0) {
			bitmap_set(flags, DNSKEY_GENERATE_KSK, str2bool(argv[i] + 4));
		} else if (strncasecmp(argv[i], "zsk=", 4) == 0) {
			bitmap_set(flags, DNSKEY_GENERATE_ZSK, str2bool(argv[i] + 4));
		} else if (!just_timing && strncasecmp(argv[i], "sep=", 4) == 0) {
			bitmap_set(flags, DNSKEY_GENERATE_SEP_SPEC, true);
			bitmap_set(flags, DNSKEY_GENERATE_SEP_ON, str2bool(argv[i] + 4));
		} else if (!just_timing && strncasecmp(argv[i], "size=", 5) == 0) {
			if (str_to_u16(argv[i] + 5, keysize) != KNOT_EOK) {
				printf("Invalid size: '%s'\n", argv[i] + 5);
				return false;
			}
		} else if (!just_timing && strncasecmp(argv[i], "addtopolicy=", 12) == 0) {
			*addtopolicy = argv[i] + 12;
		} else if (!init_timestamps(argv[i], timing)) {
			printf("Invalid parameter: %s\n", argv[i]);
			return false;
		}
	}

	return true;
}

static bool _check_lower(knot_time_t a, knot_time_t b,
			 const char *a_name, const char *b_name)
{
	if (knot_time_cmp(a, b) > 0) {
		fprintf(stderr, "Semantic error: expected '%s' before '%s'.\n", a_name, b_name);
		return false;
	}
	return true;
}

#define check_lower(t, a, b) if (!_check_lower(t->a, t->b, #a, #b)) return KNOT_ESEMCHECK

static int check_timers(const knot_kasp_key_timing_t *t)
{
	if (t->pre_active != 0) {
		check_lower(t, pre_active, publish);
	}
	check_lower(t, publish, active);
	check_lower(t, active, retire_active);
	check_lower(t, active, retire);
	check_lower(t, active, post_active);
	if (t->post_active == 0) {
		check_lower(t, retire, remove);
	}
	return KNOT_EOK;
}

#undef check_lower

// modifies ctx->policy options, so don't do anything afterwards !
int keymgr_generate_key(kdnssec_ctx_t *ctx, int argc, char *argv[])
{
	knot_time_t now = knot_time(), infty = 0;
	knot_kasp_key_timing_t gen_timing = { now, infty, now, infty, now, infty, infty, infty, infty };
	kdnssec_generate_flags_t flags = 0;
	uint16_t keysize = 0;
	const char *addtopolicy = NULL;
	if (!genkeyargs(argc, argv, false, &flags, &ctx->policy->algorithm,
			&keysize, &gen_timing, &addtopolicy)) {
		return KNOT_EINVAL;
	}

	int ret = check_timers(&gen_timing);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if ((flags & DNSKEY_GENERATE_KSK) && gen_timing.ready == infty) {
		gen_timing.ready = gen_timing.active;
	}

	if (keysize > 0) {
		if ((flags & DNSKEY_GENERATE_KSK)) {
			ctx->policy->ksk_size = keysize;
		} else {
			ctx->policy->zsk_size = keysize;
		}
	}

	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *kasp_key = &ctx->zone->keys[i];
		if ((kasp_key->is_ksk && (flags & DNSKEY_GENERATE_KSK)) &&
		    dnssec_key_get_algorithm(kasp_key->key) != ctx->policy->algorithm) {
			printf("warning: creating key with different algorithm than "
			       "configured in the policy\n");
			break;
		}
	}

	knot_kasp_key_t *key = NULL;
	ret = kdnssec_generate_key(ctx, flags, &key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	key->timing = gen_timing;

	if (addtopolicy != NULL) {
		char *last_policy_last = NULL;

		knot_dname_t *unused = NULL;
		ret = kasp_db_get_policy_last(ctx->kasp_db, addtopolicy, &unused,
		                              &last_policy_last);
		knot_dname_free(unused, NULL);
		if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
			return ret;
		}

		ret = kasp_db_set_policy_last(ctx->kasp_db, addtopolicy, last_policy_last,
		                              ctx->zone->dname, key->id);
		free(last_policy_last);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

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

int keymgr_import_bind(kdnssec_ctx_t *ctx, const char *import_file, bool pub_only)
{
	if (ctx == NULL || import_file == NULL) {
		return KNOT_EINVAL;
	}

	knot_kasp_key_timing_t timing = { 0 };
	dnssec_key_t *key = NULL;
	char *keyid = NULL;

	char *pubname = genname(import_file, ".key", ".private");
	if (pubname == NULL) {
		return KNOT_EINVAL;
	}

	int ret = bind_pubkey_parse(pubname, &key);
	free(pubname);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	if (!pub_only) {
		bind_privkey_t bpriv = { 0 };

		char *privname = genname(import_file, ".private", ".key");
		if (privname == NULL) {
			goto fail;
		}

		ret = bind_privkey_parse(privname, &bpriv);
		free(privname);
		if (ret != DNSSEC_EOK) {
			goto fail;
		}

		dnssec_binary_t pem = { 0 };
		ret = bind_privkey_to_pem(key, &bpriv, &pem);
		if (ret != DNSSEC_EOK) {
			bind_privkey_free(&bpriv);
			goto fail;
		}

		bind_privkey_to_timing(&bpriv, &timing); // time created remains always zero

		bind_privkey_free(&bpriv);

		ret = dnssec_keystore_import(ctx->keystore, &pem, &keyid);
		dnssec_binary_free(&pem);
		if (ret != DNSSEC_EOK) {
			goto fail;
		}
	} else {
		timing.publish = ctx->now;

		ret = dnssec_key_get_keyid(key, &keyid);
		if (ret != DNSSEC_EOK) {
			goto fail;
		}
	}

	// allocate kasp key
	knot_kasp_key_t *kkey = calloc(1, sizeof(*kkey));
	if (!kkey) {
		ret = KNOT_ENOMEM;
		goto fail;
	}

	kkey->id = keyid;
	kkey->key = key;
	kkey->timing = timing;
	kkey->is_pub_only = pub_only;
	kkey->is_ksk = (dnssec_key_get_flags(kkey->key) == DNSKEY_FLAGS_KSK);
	kkey->is_zsk = !kkey->is_ksk;

	// append to zone
	ret = kasp_zone_append(ctx->zone, kkey);
	free(kkey);
	if (ret != KNOT_EOK) {
		goto fail;
	}
	ret = kdnssec_ctx_commit(ctx);
	if (ret == KNOT_EOK) {
		printf("%s\n", keyid);
		return KNOT_EOK;
	}
fail:
	dnssec_key_free(key);
	free(keyid);
	return knot_error_from_libdnssec(ret);
}

static int import_key(kdnssec_ctx_t *ctx, unsigned backend, const char *param,
                      int argc, char *argv[])
{
	if (ctx == NULL || param == NULL) {
		return KNOT_EINVAL;
	}

	// parse params
	knot_time_t now = knot_time();
	knot_kasp_key_timing_t timing = { .publish = now, .active = now };
	kdnssec_generate_flags_t flags = 0;
	uint16_t keysize = 0;
	if (!genkeyargs(argc, argv, false, &flags, &ctx->policy->algorithm,
	                &keysize, &timing, NULL)) {
		return KNOT_EINVAL;
	}

	int ret = check_timers(&timing);
	if (ret != KNOT_EOK) {
		return ret;
	}

	normalize_generate_flags(&flags);

	dnssec_key_t *key = NULL;
	char *keyid = NULL;

	if (backend == KEYSTORE_BACKEND_PEM) {
		// open file
		int fd = open(param, O_RDONLY, 0);
		if (fd == -1) {
			return knot_map_errno();
		}

		// determine size
		off_t fsize = lseek(fd, 0, SEEK_END);
		if (fsize == -1) {
			close(fd);
			return knot_map_errno();
		}
		if (lseek(fd, 0, SEEK_SET) == -1) {
			close(fd);
			return knot_map_errno();
		}

		// alloc memory
		dnssec_binary_t pem = { 0 };
		ret = dnssec_binary_alloc(&pem, fsize);
		if (ret != DNSSEC_EOK) {
			close(fd);
			goto fail;
		}

		// read pem
		ssize_t read_count = read(fd, pem.data, pem.size);
		close(fd);
		if (read_count == -1) {
			dnssec_binary_free(&pem);
			ret = knot_map_errno();
			goto fail;
		}

		// put pem to kesytore
		ret = dnssec_keystore_import(ctx->keystore, &pem, &keyid);
		dnssec_binary_free(&pem);
		if (ret != DNSSEC_EOK) {
			goto fail;
		}
	} else {
		assert(backend == KEYSTORE_BACKEND_PKCS11);
		keyid = strdup(param);
	}

	// create dnssec key
	ret = dnssec_key_new(&key);
	if (ret != DNSSEC_EOK) {
		goto fail;
	}
	ret = dnssec_key_set_dname(key, ctx->zone->dname);
	if (ret != DNSSEC_EOK) {
		goto fail;
	}
	dnssec_key_set_flags(key, dnskey_flags(flags & DNSKEY_GENERATE_SEP_ON));
	dnssec_key_set_algorithm(key, ctx->policy->algorithm);

	// fill key structure from keystore (incl. pubkey from privkey computation)
	ret = dnssec_keystore_export(ctx->keystore, keyid, key);
	if (ret != DNSSEC_EOK) {
		goto fail;
	}

	// allocate kasp key
	knot_kasp_key_t *kkey = calloc(1, sizeof(*kkey));
	if (kkey == NULL) {
		ret = KNOT_ENOMEM;
		goto fail;
	}
	kkey->id = keyid;
	kkey->key = key;
	kkey->timing = timing;
	kkey->is_ksk = (flags & DNSKEY_GENERATE_KSK);
	kkey->is_zsk = (flags & DNSKEY_GENERATE_ZSK);

	// append to zone
	ret = kasp_zone_append(ctx->zone, kkey);
	free(kkey);
	if (ret != KNOT_EOK) {
		goto fail;
	}
	ret = kdnssec_ctx_commit(ctx);
	if (ret == KNOT_EOK) {
		printf("%s\n", keyid);
		return KNOT_EOK;
	}
fail:
	dnssec_key_free(key);
	free(keyid);
	return knot_error_from_libdnssec(ret);
}

int keymgr_import_pem(kdnssec_ctx_t *ctx, const char *import_file, int argc, char *argv[])
{
	return import_key(ctx, KEYSTORE_BACKEND_PEM, import_file, argc, argv);
}

int keymgr_import_pkcs11(kdnssec_ctx_t *ctx, char *key_id, int argc, char *argv[])
{
	if (!dnssec_keyid_is_valid(key_id)) {
		return DNSSEC_INVALID_KEY_ID;
	}
	dnssec_keyid_normalize(key_id);
	return import_key(ctx, KEYSTORE_BACKEND_PKCS11, key_id, argc, argv);
}

int keymgr_nsec3_salt_print(kdnssec_ctx_t *ctx)
{
	dnssec_binary_t salt_bin;
	knot_time_t created;
	int ret = kasp_db_load_nsec3salt(ctx->kasp_db, ctx->zone->dname,
	                                 &salt_bin, &created);
	switch (ret) {
	case KNOT_EOK:
		printf("Current salt: ");
		if (salt_bin.size == 0) {
			printf("-");
		}
		for (size_t i = 0; i < salt_bin.size; i++) {
			printf("%02X", (unsigned)salt_bin.data[i]);
		}
		printf("\n");
		free(salt_bin.data);
		break;
	case KNOT_ENOENT:
		printf("-- no salt --\n");
		ret = KNOT_EOK;
		break;
	}
	return ret;
}

int keymgr_nsec3_salt_set(kdnssec_ctx_t *ctx, const char *new_salt)
{
	assert(new_salt);

	dnssec_binary_t salt_bin = { 0 };
	if (strcmp(new_salt, "-") != 0) {
		salt_bin.data = hex_to_bin(new_salt, &salt_bin.size);
		if (salt_bin.data == NULL) {
			return KNOT_EMALF;
		}
	}
	if (salt_bin.size != ctx->policy->nsec3_salt_length) {
		printf("Warning: specified salt doesn't match configured "
		       "salt length (%d).\n",
		       (int)ctx->policy->nsec3_salt_length);
	}
	int ret = kasp_db_store_nsec3salt(ctx->kasp_db, ctx->zone->dname,
	                                  &salt_bin, knot_time());
	if (salt_bin.size > 0) {
		free(salt_bin.data);
	}
	return ret;
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

int keymgr_generate_tsig(const char *tsig_name, const char *alg_name, int bits)
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

static bool is_hex(const char *string)
{
	for (const char *p = string; *p != '\0'; p++) {
		if (!is_xdigit(*p)) {
			return false;
		}
	}
	return (*string != '\0');
}

int keymgr_get_key(kdnssec_ctx_t *ctx, const char *key_spec, knot_kasp_key_t **key)
{
	// Check if type of key spec is prescribed.
	bool is_keytag = false, is_id = false;
	if (strncasecmp(key_spec, "keytag=", 7) == 0) {
		key_spec += 7;
		is_keytag = true;
	} else if (strncasecmp(key_spec, "id=", 3) == 0) {
		key_spec += 3;
		is_id = true;
	}

	uint16_t keytag = 0;
	bool can_be_keytag = (str_to_u16(key_spec, &keytag) == KNOT_EOK);
	long spec_len = strlen(key_spec);

	// Check if input is a valid key spec.
	if ((is_keytag && !can_be_keytag) ||
	    (is_id && !is_hex(key_spec)) ||
	    (!can_be_keytag && !is_hex(key_spec))) {
		printf("Error in key specification.\n");
		return KNOT_EINVAL;
	}

	*key = NULL;
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *candidate = &ctx->zone->keys[i];

		bool keyid_match = strncmp(candidate->id, key_spec, spec_len) == 0; // May be just a prefix.
		bool keytag_match = can_be_keytag &&
		                    dnssec_key_get_keytag(candidate->key) == keytag;

		// Terminate if found exact key ID match.
		if (keyid_match && !is_keytag && strlen(candidate->id) == spec_len) {
			*key = candidate;
			break;
		}
		// Check for key ID prefix or tag match.
		if ((is_keytag && keytag_match) || // Tag is prescribed.
		    (is_id && keyid_match) ||   // Key ID is prescribed.
		    ((!is_keytag && !is_id) && (keyid_match || keytag_match))) { // Nothing is prescribed.
			if (*key == NULL) {
				*key = candidate;
			} else {
				printf("Key is not specified uniquely. Please use id=Full_Key_ID.\n");
				return KNOT_EINVAL;
			}
		}
	}
	if (*key == NULL) {
		printf("Key not found.\n");
		return KNOT_ENOENT;
	}
	return KNOT_EOK;
}

int keymgr_foreign_key_id(char *argv[], knot_lmdb_db_t *kaspdb, knot_dname_t **key_zone, char **key_id)
{
	*key_zone = knot_dname_from_str_alloc(argv[0]);
	if (*key_zone == NULL) {
		return KNOT_ENOMEM;
	}
	knot_dname_to_lower(*key_zone);

	kdnssec_ctx_t kctx = { 0 };
	int ret = kdnssec_ctx_init(conf(), &kctx, *key_zone, kaspdb, NULL);
	if (ret != KNOT_EOK) {
		printf("Failed to initialize zone %s (%s)\n", argv[0], knot_strerror(ret));
		free(*key_zone);
		*key_zone = NULL;
		return KNOT_ENOZONE;
	}
	knot_kasp_key_t *key;
	ret = keymgr_get_key(&kctx, argv[2], &key);
	if (ret == KNOT_EOK) {
		*key_id = strdup(key->id);
		if (*key_id == NULL) {
			ret = KNOT_ENOMEM;
		}
	}
	kdnssec_ctx_deinit(&kctx);
	return ret;
}

int keymgr_set_timing(knot_kasp_key_t *key, int argc, char *argv[])
{
	knot_kasp_key_timing_t temp = key->timing;
	kdnssec_generate_flags_t flags = ((key->is_ksk ? DNSKEY_GENERATE_KSK : 0) | (key->is_zsk ? DNSKEY_GENERATE_ZSK : 0));

	if (genkeyargs(argc, argv, true, &flags, NULL, NULL, &temp, NULL)) {
		int ret = check_timers(&temp);
		if (ret != KNOT_EOK) {
			return ret;
		}
		key->timing = temp;
		key->is_ksk = (flags & DNSKEY_GENERATE_KSK);
		key->is_zsk = (flags & DNSKEY_GENERATE_ZSK);
		return KNOT_EOK;
	}
	return KNOT_EINVAL;
}

static void print_timer(const char *name, knot_time_t t, knot_time_print_t format,
                        char separator)
{
	static char buff[100];
	if (knot_time_print(format, t, buff, sizeof(buff)) < 0) {
		printf("%s=(error)%c", name, separator); // shall not happen
	} else {
		printf("%s=%s%c", name, buff, separator);
	}
}

int keymgr_list_keys(kdnssec_ctx_t *ctx, knot_time_print_t format)
{
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		printf("%s ksk=%s zsk=%s tag=%05d algorithm=%-2d size=%-4u public-only=%s ", key->id,
		       (key->is_ksk ? "yes" : "no "), (key->is_zsk ? "yes" : "no "),
		       dnssec_key_get_keytag(key->key), (int)dnssec_key_get_algorithm(key->key),
		       dnssec_key_get_size(key->key), (key->is_pub_only ? "yes" : "no "));
		print_timer("pre-active",    key->timing.pre_active,     format, ' ');
		print_timer("publish",       key->timing.publish,        format, ' ');
		print_timer("ready",         key->timing.ready,          format, ' ');
		print_timer("active",        key->timing.active,         format, ' ');
		print_timer("retire-active", key->timing.retire_active,  format, ' ');
		print_timer("retire",        key->timing.retire,         format, ' ');
		print_timer("post-active",   key->timing.post_active,    format, ' ');
		print_timer("remove",        key->timing.remove,         format, '\n');
	}
	return KNOT_EOK;
}

static int print_ds(const knot_dname_t *dname, const dnssec_binary_t *rdata)
{
	wire_ctx_t ctx = wire_ctx_init(rdata->data, rdata->size);
	if (wire_ctx_available(&ctx) < 4) {
		return KNOT_EMALF;
	}

	char *name = knot_dname_to_str_alloc(dname);
	if (!name) {
		return KNOT_ENOMEM;
	}

	uint16_t keytag   = wire_ctx_read_u16(&ctx);
	uint8_t algorithm = wire_ctx_read_u8(&ctx);
	uint8_t digest_type = wire_ctx_read_u8(&ctx);

	size_t digest_size = wire_ctx_available(&ctx);

	printf("%s DS %d %d %d ", name, keytag, algorithm, digest_type);
	for (size_t i = 0; i < digest_size; i++) {
		printf("%02x", ctx.position[i]);
	}
	printf("\n");

	free(name);
	return KNOT_EOK;
}

static int create_and_print_ds(const knot_dname_t *zone_name,
			       const dnssec_key_t *key, dnssec_key_digest_t digest)
{
	_cleanup_binary_ dnssec_binary_t rdata = { 0 };
	int r = dnssec_key_create_ds(key, digest, &rdata);
	if (r != DNSSEC_EOK) {
		return knot_error_from_libdnssec(r);
	}

	return print_ds(zone_name, &rdata);
}

int keymgr_generate_ds(const knot_dname_t *dname, const knot_kasp_key_t *key)
{
	static const dnssec_key_digest_t digests[] = {
		DNSSEC_KEY_DIGEST_SHA1,
		DNSSEC_KEY_DIGEST_SHA256,
		DNSSEC_KEY_DIGEST_SHA384,
		0
	};

	int ret = KNOT_EOK;
	for (int i = 0; digests[i] != 0 && ret == KNOT_EOK; i++) {
		ret = create_and_print_ds(dname, key->key, digests[i]);
	}

	return ret;
}

int keymgr_generate_dnskey(const knot_dname_t *dname, const knot_kasp_key_t *key)
{
	const dnssec_key_t *dnskey = key->key;

	char *name = knot_dname_to_str_alloc(dname);
	if (!name) {
		return KNOT_ENOMEM;
	}

	uint16_t flags = dnssec_key_get_flags(dnskey);
	uint8_t algorithm = dnssec_key_get_algorithm(dnskey);

	dnssec_binary_t pubkey = { 0 };
	int ret = dnssec_key_get_pubkey(dnskey, &pubkey);
	if (ret != DNSSEC_EOK) {
		free(name);
		return knot_error_from_libdnssec(ret);
	}

	uint8_t *base64_output = NULL;
	int len = base64_encode_alloc(pubkey.data, pubkey.size, &base64_output);
	if (len < 0) {
		free(name);
		return len;
	}

	printf("%s DNSKEY %u 3 %u %.*s\n", name, flags, algorithm, len, base64_output);

	free(base64_output);
	free(name);
	return KNOT_EOK;
}
