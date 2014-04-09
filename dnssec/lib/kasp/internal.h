#pragma once

#include "key.h"
#include "kasp.h"

#define KASP_MAX_KEYS 16

struct dnssec_kasp {
	char *path;
};

struct dnssec_kasp_policy {
	char *name;
};

struct dnssec_kasp_zone {
	char *name;

	dnssec_kasp_t *kasp;
	dnssec_kasp_t *policy;

	dnssec_kasp_key_t keys[KASP_MAX_KEYS];
	size_t keys_count;
};
