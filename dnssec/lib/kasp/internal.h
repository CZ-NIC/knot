#pragma once

#include "key.h"
#include "kasp.h"
#include "clists.h"

struct dnssec_kasp {
	char *path;
};

struct dnssec_kasp_keyset {
	clist_t list;
};

struct dnssec_kasp_zone {
	char *name;
	uint8_t *dname;

	dnssec_kasp_t *policy;

	dnssec_kasp_keyset_t keys;
};
