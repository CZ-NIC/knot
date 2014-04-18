#pragma once

#include "key.h"
#include "kasp.h"
#include "clists.h"

#define KASP_MAX_KEYS 16

struct dnssec_kasp {
	char *path;
};

struct dnssec_kasp_policy {
	char *name;
};

struct dnssec_kasp_keyset {
	clist_t list;
};

struct dnssec_kasp_zone {
	char *name;
	uint8_t *dname;

	dnssec_kasp_t *kasp;
	dnssec_kasp_t *policy;

	dnssec_kasp_keyset_t keys;
};
