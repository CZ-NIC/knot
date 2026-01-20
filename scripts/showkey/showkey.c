// Copyright (C) CZ.NIC, z.s.p.o. and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// For more information, see <https://www.knot-dns.cz/>

// NOTE: build with 'make' AFTER building .libs/libknot.so in the parent project, otherwise the
//       program won't be linked correctly

#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "contrib/base64.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/key/internal.h"
#include "libknot/libknot.h"

#define PROGRAM_NAME "showkey"
#define USAGE                                                               \
	"NAME                                                           \n" \
	"    "PROGRAM_NAME" - dnssec key dump utility                   \n" \
	"                                                               \n" \
	"SYNOPSIS                                                       \n" \
	"    "PROGRAM_NAME" -h                                          \n" \
	"    "PROGRAM_NAME" [-a ALGO] [-d DNAME] [-s KEYSIZE] [-f FLAGS]\n" \
	"    "PROGRAM_NAME" -p FILE -a ALGO -d DNAME -f FLAGS           \n" \
	"                                                               \n" \
	"DESCRIPTION                                                    \n" \
	"    This program dumps dnssec keys in format used by           \n" \
	"    libknot/dnssec/sample_keys.h.                              \n" \
	"                                                               \n" \
	"    Options                                                    \n" \
	"        -h help                                                \n" \
	"        -a key algorithm  (default: 13)                        \n" \
	"        -d DNAME          (default: example.)                  \n" \
	"        -s keysize        (default: 256 or deduced from -a)    \n" \
	"        -f DNSKEY flags   (default: 256)                       \n" \
	"        -p .pem file                                           \n" \
	"                                                               \n" \
	"        ALGO is one of:                                        \n" \
	"            5   (RSA-SHA1)           8   (RSA-SHA256)          \n" \
	"            10  (RSA-SHA512)         13  (ECDSA-P256-SHA256)   \n" \
	"            14  (ECDSA-P384-SHA384)  15  (ED25519)             \n" \
	"            16  (ED448)                                        \n"

typedef struct {
	char *pem;
	char *dname;
	dnssec_key_algorithm_t algo;
	uint16_t flags;
	uint16_t keysize;
} args_t;

static char *to_hex(const uint8_t *bytes, size_t nbytes, int colwidth)
{
	size_t alloced = nbytes * 9 + 1;
	char *buf = calloc(1, alloced);
	if (buf == NULL) {
		return buf;
	}

	size_t nwr, i;
	for (nwr = 0, i = 0; i < nbytes; ++i) {
		nwr += sprintf(&buf[nwr], (i % colwidth) ? "0x%02x, " : "\n\t\t0x%02x, ", bytes[i]);
		assert(nwr < alloced);
	}

	return buf;
}

static char *to_hex2(const uint8_t *bytes, size_t nbytes)
{
	size_t alloced = nbytes * 2 + 1;
	char *buf = calloc(1, alloced);
	if (buf == NULL) {
		return buf;
	}

	size_t nwr, i;
	for (nwr = 0, i = 0; i < nbytes; ++i) {
		nwr += sprintf(&buf[nwr], "%02X", bytes[i]);
		assert(nwr < alloced);
	}

	return buf;
}

static char *dname_wire_str(const knot_dname_t *dname)
{
	if (dname == NULL) {
		return NULL;
	}

	size_t alloced = strlen((const char *)dname) * 4 + 1;
	char *out = calloc(1, alloced);
	char *dst = out;
	for (const uint8_t *c = dname, *next = dname; *c != 0; ++c) {
		if (c == next) {
			dst += sprintf(dst,  "\"\\x%02x\"\"", *c);
			next += *next + 1;
		} else {
			dst += sprintf(dst, (c + 1 == next) ? "%c\"" : "%c", *c);
		}
	}

	return out;
}

static int print_key(const dnssec_key_t *key)
{
	int ret = KNOT_EOK;

	char *key_id              = NULL;
	char *str_pubkey          = NULL;
	char *str_pem             = NULL;
	const knot_dname_t *dname = NULL;
	char *str_dname           = NULL;
	char *txt_dname           = NULL;
	dnssec_binary_t ds[3]     = { 0 };
	char *str_ds[3]           = { 0 };
	char *txt_ds[3]           = { 0 };
	dnssec_binary_t pem       = { 0 };
	uint8_t *dnskey_base64    = NULL;

	uint8_t algo    = dnssec_key_get_algorithm(key);
	uint8_t proto   = dnssec_key_get_protocol(key);
	uint16_t flags  = dnssec_key_get_flags(key);
	uint16_t keytag = dnssec_key_get_keytag(key);
	uint32_t keysz  = dnssec_key_get_size(key);

	dnssec_binary_t pubkey;
	ret = dnssec_key_get_pubkey(key, &pubkey);
	str_pubkey = to_hex(pubkey.data, pubkey.size, 10);
	if (ret || str_pubkey == NULL) {
		goto finish;
	}

	static const dnssec_key_digest_t digests[] = {
		DNSSEC_KEY_DIGEST_SHA1,
		DNSSEC_KEY_DIGEST_SHA256,
		DNSSEC_KEY_DIGEST_SHA384,
	};
	for (int i = 0; i < 3; ++i) {
		ret = dnssec_key_create_ds(key, digests[i], &ds[i]);
		str_ds[i] = to_hex(ds[i].data, ds[i].size, 10);
		txt_ds[i] = to_hex2(ds[i].data + 4, ds[i].size - 4); // first 4B are keytag, keyalgo, dsalgo
		if (ret || str_ds[i] == NULL) {
			goto finish;
		}
	}

	ret = dnssec_pem_from_privkey(key->private_key, &pem);
	str_pem = to_hex(pem.data, pem.size, 10);
	if (ret || str_pem == NULL) {
		goto finish;
	}

	dname = dnssec_key_get_dname(key);
	str_dname = dname_wire_str(dname);
	txt_dname = knot_dname_to_str(NULL, dname, 0);
	ret = dnssec_key_get_keyid(key, &key_id);
	if (ret || dname == NULL || str_dname == NULL || txt_dname == NULL) {
		goto finish;
	}

	size_t dnskey_b64_len = knot_base64_encode_alloc(pubkey.data, pubkey.size, &dnskey_base64);
	if (dnskey_b64_len <= 0) {
		ret = 1;
		goto finish;
	}

	const char *str_algo = knot_lookup_by_id(knot_dnssec_alg_names, algo)->name;
	if (str_algo == NULL) {
		ret = 1;
		goto finish;
	}

	printf("/*\n"
	       "\n"
	       "%s (%db)\n"
	       "\n"
	       "%s\tDNSKEY\t%5d  %d  %d  %.*s\n"
	       "%s\tDS    \t%5d  %d  1  %s\n"
	       "%s\tDS    \t%5d  %d  2  %s\n"
	       "%s\tDS    \t%5d  %d  4  %s\n"
	       "\n"
	       "%.*s\n"
	       "*/\n"
	       "static const key_parameters_t KEY = {\n"
	       "	.name = (uint8_t *)%s,\n"
	       "	.flags = %hu,\n"
	       "	.protocol = %u,\n"
	       "	.algorithm = %u,\n"
	       "	.public_key = { .size = %zu, .data = (uint8_t []){%s\n"
	       "	}},\n"
	       "	.rdata = { .size = %zu, .data = (uint8_t []){\n"
	       "		0x%02x, 0x%02x, 0x%02x, 0x%02x,%s\n"
	       "	}},\n"
	       "	.key_id = \"%s\",\n"
	       "	.keytag = %d,\n"
	       "	.ds_sha1 = { .size = %zu, .data = (uint8_t []){%s\n"
	       "	}},\n"
	       "	.ds_sha256 = { .size = %zu, .data = (uint8_t []){%s\n"
	       "	}},\n"
	       "	.ds_sha384 = { .size = %zu, .data = (uint8_t []){%s\n"
	       "	}},\n"
	       "	.bit_size = %u,\n"
	       "	.pem = { .size = %zu, .data = (uint8_t []){%s\n"
	       "	}},\n"
	       "};\n",
	       str_algo, keysz,
	       txt_dname, flags, proto, algo, (int)dnskey_b64_len, dnskey_base64,
	       txt_dname, keytag, algo, txt_ds[0],
	       txt_dname, keytag, algo, txt_ds[1],
	       txt_dname, keytag, algo, txt_ds[2],
	       (int)pem.size, pem.data,
	       str_dname,
	       flags,
	       proto,
	       algo,
	       pubkey.size, str_pubkey,
	       pubkey.size + 4,
	       flags >> 8, flags & 0xff, proto, algo, str_pubkey,
	       key_id,
	       keytag,
	       ds[0].size, str_ds[0],
	       ds[1].size, str_ds[1],
	       ds[2].size, str_ds[2],
	       keysz,
	       pem.size, str_pem);

finish:
	free(key_id);
	free(str_dname);
	free(txt_dname);
	free(str_pubkey);
	free(str_pem);
	free(pem.data);
	free(dnskey_base64);
	for (int i = 0; i < 3; ++i) {
		free(ds[i].data);
		free(str_ds[i]);
		free(txt_ds[i]);
	}

	return ret;
}

static int set_dname(dnssec_key_t *key, const char *dname)
{
	if (key == NULL) {
		return 1;
	}

	knot_dname_t *_dname = knot_dname_from_str(NULL, dname, 0);
	int ret = dnssec_key_set_dname(key, _dname);
	free(_dname);
	if (_dname == NULL || ret != KNOT_EOK) {
		return 1;
	}

	return 0;
}

static dnssec_key_t *
make_key(const args_t *args, dnssec_keystore_t *keystore, const char *key_id)
{
	int ret = KNOT_EOK;

	dnssec_key_t *key;
	ret |= dnssec_key_new(&key);
	ret |= dnssec_key_set_algorithm(key, args->algo);
	ret |= dnssec_key_set_flags(key, args->flags);
	ret |= dnssec_keystore_get_private(keystore, key_id, key);
	ret |= set_dname(key, args->dname);
	if (ret) {
		dnssec_key_free(key);
		return (key = NULL);
	}

	return key;
}

static void *mmap_file(const char *path, size_t *fsize_out)
{
	void *map = NULL;

	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		return NULL;
	}

	struct stat st;
	int ret = fstat(fd, &st);
	size_t filesize = st.st_size;
	if (ret == -1 || filesize == 0) {
		close(fd);
		return NULL;
	}

	map = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		munmap(map, filesize);
		close(fd);
		return NULL;
	}

	close(fd);
	*fsize_out = filesize;
	return map;
}

static dnssec_key_t *load_key(const args_t *args, uint8_t *pem, size_t pemsz)
{
	int ret = KNOT_EOK;

	if (pem == NULL) {
		return NULL;
	}

	dnssec_key_t *key;
	ret |= dnssec_key_new(&key);
	ret |= dnssec_key_set_algorithm(key, args->algo);
	ret |= dnssec_key_set_flags(key, args->flags);
	ret |= set_dname(key, args->dname);
	ret |= dnssec_key_load_pkcs8(key, &(dnssec_binary_t){ .size = pemsz, .data = pem });
	if (ret) {
		dnssec_key_free(key);
		return (key = NULL);
	}

	return key;
}

int main(int argc, char **argv)
{
	int ret = 1;

	args_t args = {
		.algo    = DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256,
		.keysize = 256,
		.flags   = 256,
		.dname   = "example.",
		.pem     = NULL,
	};

	for (char c = 0; c != -1;) {
		c = getopt(argc, argv, "ha:d:s:p:f:");
		switch (c) {
		case 'h':
		case '?':
			fputs(USAGE, stderr);
			return c == '?';
		case 'a':
			args.algo = atoi(optarg);
			// some algos have fixed key sizes, so we can be helpful here
			switch (args.algo) {
			case DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256:
				args.keysize = 256;
				break;
			case DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384:
				args.keysize = 384;
				break;
			case DNSSEC_KEY_ALGORITHM_ED25519:
				args.keysize = 256;
				break;
			case DNSSEC_KEY_ALGORITHM_ED448:
				args.keysize = 456;
				break;
			default:
				break;
			}
			break;
		case 'f':
			args.flags = atoi(optarg);
			break;
		case 'd':
			args.dname = optarg;
			break;
		case 's':
			args.keysize = atoi(optarg);
			break;
		case 'p':
			args.pem = optarg;
			break;
		}
	}

	if (args.pem == NULL) {
		// generate mode
		char keystore_path[] = "/tmp/knot-showkey-XXXXXX";
		dnssec_keystore_t *keystore = NULL;
		char *key_id = NULL;

		mkdtemp(keystore_path);
		dnssec_keystore_init_pkcs8(&keystore);
		dnssec_keystore_init(keystore, keystore_path);
		dnssec_keystore_open(keystore, keystore_path);
		dnssec_keystore_generate(keystore, args.algo, args.keysize, NULL, &key_id);

		dnssec_key_t *key = make_key(&args, keystore, key_id);

		if (key != NULL) {
			ret = print_key(key);
		} else {
			fputs("error constructing key\n", stderr);
		}

		dnssec_keystore_remove(keystore, key_id);
		free(key_id);
		dnssec_key_free(key);
		dnssec_keystore_deinit(keystore);
		rmdir(keystore_path);
	} else {
		// load mode
		size_t pemsz = 0;
		uint8_t *pem = mmap_file(args.pem, &pemsz);
		dnssec_key_t *key = load_key(&args, pem, pemsz);

		if (key != NULL) {
			ret = print_key(key);
		} else {
			fputs("error loading key\n", stderr);
		}

		dnssec_key_free(key);
		munmap(pem, pemsz);
	}

	if (ret) {
		fputs("error\n", stderr);
	}
	return ret;
}
