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

#include <limits.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <fcntl.h>

#include "utils/keymgr/functions.h"
#include "utils/keymgr/bind_privkey.h"
#include "contrib/base64.h"
#include "contrib/ctype.h"
#include "contrib/tolower.h"
#include "contrib/wire_ctx.h"
#include "dnssec/lib/dnssec/error.h"
#include "dnssec/shared/shared.h"
#include "knot/dnssec/kasp/policy.h"
#include "knot/dnssec/zone-keys.h"
#include "zscanner/scanner.h"

static bool is_timestamp(char *arg, knot_kasp_key_timing_t *timing)
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
	int ret = knot_time_parse("YMDhms|'now'+-#u|'t'+-#u|+-#u|'t'+-#|+-#|#",
	                          strchr(arg, '=') + 1, &stamp);
	if (ret < 0) {
		printf("Invalid timestamp: %s\n", arg);
		return true;
	}

	*dst = stamp;

	return true;
}

static bool genkeyargs(int argc, char *argv[], bool just_timing,
                       bool *isksk, dnssec_key_algorithm_t *algorithm,
                       uint16_t *keysize, knot_kasp_key_timing_t *timing)
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
			if (is_digit(argv[i][10]) && atol(argv[i] + 10) < 256) {
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
		} else if (!just_timing && strncasecmp(argv[i], "ksk=", 4) == 0) {
			switch (knot_tolower(argv[i][4])) {
			case '1':
			case 'y':
			case 't':
				*isksk = true;
				break;
			default:
				*isksk = false;
			}
		} else if (!just_timing && strncasecmp(argv[i], "size=", 5) == 0) {
			*keysize = atol(argv[i] + 5);
		} else if (!is_timestamp(argv[i], timing)) {
			printf("Invalid parameter: %s\n", argv[i]);
			return false;
		}
	}
	return true;
}

// modifies ctx->policy options, so don't do anything afterwards !
int keymgr_generate_key(kdnssec_ctx_t *ctx, int argc, char *argv[])
{
	knot_time_t now = knot_time(), infty = 0;
	knot_kasp_key_timing_t gen_timing = { now, infty, now, infty, now, infty, infty, infty, infty };
	bool isksk = false;
	uint16_t keysize = 0;
	if (!genkeyargs(argc, argv, false, &isksk, &ctx->policy->algorithm,
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

	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *kasp_key = &ctx->zone->keys[i];
		if (dnssec_key_get_flags(kasp_key->key) == dnskey_flags(isksk) &&
		    dnssec_key_get_algorithm(kasp_key->key) != ctx->policy->algorithm) {
			printf("warning: creating key with different algorithm than "
			       "configured in the policy\n");
			break;
		}
	}

	knot_kasp_key_t *key = NULL;
	int ret = kdnssec_generate_key(ctx, isksk, !isksk, &key);
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

int keymgr_import_pem(kdnssec_ctx_t *ctx, const char *import_file, int argc, char *argv[])
{
	if (ctx == NULL || import_file == NULL) {
		return KNOT_EINVAL;
	}

	// parse params
	knot_time_t now = knot_time();
	knot_kasp_key_timing_t timing = { .publish = now, .active = now };
	bool isksk = false;
	uint16_t keysize = 0;
	if (!genkeyargs(argc, argv, false, &isksk, &ctx->policy->algorithm,
	                &keysize, &timing)) {
		return KNOT_EINVAL;
	}

	// open file
	int fd = open(import_file, O_RDONLY, 0);
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

	dnssec_key_t *key = NULL;
	char *keyid = NULL;

	// alloc memory
	dnssec_binary_t pem = { 0 };
	int ret = dnssec_binary_alloc(&pem, fsize);
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

	// create dnssec key
	ret = dnssec_key_new(&key);
	if (ret != DNSSEC_EOK) {
		goto fail;
	}
	ret = dnssec_key_set_dname(key, ctx->zone->dname);
	if (ret != DNSSEC_EOK) {
		goto fail;
	}
	dnssec_key_set_flags(key, dnskey_flags(isksk));
	dnssec_key_set_algorithm(key, ctx->policy->algorithm);

	// fill key structure from keystore (incl. pubkey from privkey computation)
	ret = dnssec_key_import_keystore(key, ctx->keystore, keyid);
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

static long is_uint32(const char *string)
{
	if (*string == '\0') {
		return -1;
	}
	for (const char *p = string; *p != '\0'; p++) {
		if (!is_digit(*p)) {
			return -1;
		}
	}
	long res = atol(string);
	return (res <= UINT32_MAX ? res : -1);
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
	long spec_tag = is_uint32(key_spec), spec_len = strlen(key_spec);
	if (spec_tag < 0 && !is_hex(key_spec)) {
		printf("Error in key specification.\n");
		return KNOT_EINVAL;
	}

	*key = NULL;
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *candidate = &ctx->zone->keys[i];
		if ((spec_tag >= 0 && dnssec_key_get_keytag(candidate->key) == spec_tag) ||
		    (spec_tag < 0 && strncmp(candidate->id, key_spec, spec_len) == 0)) {
			if (*key == NULL) {
				*key = candidate;
			}
			else {
				printf("Key is not specified uniquely.\n");
				return KNOT_ELIMIT;
			}
		}
	}
	if (*key == NULL) {
		printf("Key not found.\n");
		return KNOT_ENOENT;
	}
	return KNOT_EOK;
}

int keymgr_foreign_key_id(char *argv[], knot_dname_t **key_zone, char **key_id)
{
	*key_zone = knot_dname_from_str_alloc(argv[0]);
	if (*key_zone == NULL) {
		return KNOT_ENOMEM;
	}
	(void)knot_dname_to_lower(*key_zone);

	kdnssec_ctx_t kctx = { 0 };
	int ret = kdnssec_ctx_init(conf(), &kctx, *key_zone, NULL);
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

	if (genkeyargs(argc, argv, true, NULL, NULL, NULL, &temp)) {
		key->timing = temp;
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
		printf("%s ksk=%s tag=%05d algorithm=%d public-only=%s ", key->id,
		       ((dnssec_key_get_flags(key->key) == dnskey_flags(true)) ? "yes" : "no "),
		       dnssec_key_get_keytag(key->key), (int)dnssec_key_get_algorithm(key->key),
		       (key->is_pub_only ? "yes" : "no "));
		print_timer("created",       key->timing.created,        format, ' ');
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
