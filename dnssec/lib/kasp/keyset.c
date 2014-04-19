#include <assert.h>

#include "clists.h"
#include "error.h"
#include "kasp.h"
#include "kasp/keyset.h"
#include "kasp/zone.h"
#include "shared.h"

_public_
void dnssec_kasp_keyset_init(dnssec_kasp_keyset_t *keyset)
{
	if (!keyset) {
		return;
	}

	clist_init(&keyset->list);
}

_public_
dnssec_kasp_keyset_t *dnssec_kasp_zone_get_keys(dnssec_kasp_zone_t *zone)
{
	if (!zone) {
		return NULL;
	}

	return &zone->keys;
}

_public_
size_t dnssec_kasp_keyset_count(dnssec_kasp_keyset_t *keys)
{
	if (!keys) {
		return 0;
	}

	return clist_size(&keys->list);
}

_public_
dnssec_kasp_key_t *dnssec_kasp_keyset_at(dnssec_kasp_keyset_t *keys, size_t search)
{
	if (!keys) {
		return NULL;
	}

	size_t index = 0;
	CLIST_FOR_EACH(cptrnode_t *, node, keys->list) {
		if (index++ == search) {
			return node->ptr;
		}
	}

	return NULL;
}

_public_
int dnssec_kasp_keyset_add(dnssec_kasp_keyset_t *keys, dnssec_kasp_key_t *kasp_key)
{
	if (!keys || !kasp_key) {
		return DNSSEC_EINVAL;
	}

	cptrnode_t *added = cptrlist_add(&keys->list, kasp_key);
	if (!added) {
		return DNSSEC_ENOMEM;
	}

	return DNSSEC_EOK;
}

static void free_kasp_key(dnssec_kasp_key_t *kasp_key)
{
	dnssec_key_free(kasp_key->key);
	free(kasp_key);
}

_public_
int dnssec_kasp_keyset_remove(dnssec_kasp_keyset_t *keys, dnssec_kasp_key_t *search)
{
	if (!keys || !search) {
		return DNSSEC_EINVAL;
	}

	CLIST_FOR_EACH(cptrnode_t *, node, keys->list) {
		if (node->ptr == search) {
			free_kasp_key(node->ptr);
			clist_remove((cnode_t *)node);
			free(node);
			return DNSSEC_EOK;
		}
	}

	return DNSSEC_EINVAL;
}

_public_
void dnssec_kasp_keyset_empty(dnssec_kasp_keyset_t *keys)
{
	if (!keys) {
		return;
	}

	cptrnode_t *current = NULL, *next = NULL;
	CLIST_WALK_DELSAFE(current, keys->list, next) {
		free_kasp_key(current->ptr);
		free(current);
	}

	dnssec_kasp_keyset_init(keys);
}
