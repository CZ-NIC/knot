#pragma once

#include <stdint.h>

#include "kasp.h"
#include "kasp/internal.h"
#include "kasp/keyset.h"

struct dnssec_kasp_zone {
	char *name;
	uint8_t *dname;

	dnssec_kasp_t *policy;

	dnssec_kasp_keyset_t keys;
};
