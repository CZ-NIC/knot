/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/attribute.h"
#include "libknot/processing/overlay.h"
#include "libknot/errcode.h"
#include "contrib/mempattern.h"
#include "contrib/ucw/lists.h"

#define LAYERS(overlay)	((list_t *)overlay->layers)

/*! \note Macro for state-chaining layers. */
#define ITERATE_LAYERS(overlay, func, ...) \
	int state = overlay->state; \
	ptrnode_t *node = NULL; \
	WALK_LIST(node, *LAYERS(overlay)) { \
		knot_layer_t *layer = node->d; \
		layer->state = state; /* Pass-through state. */ \
		state = (func)(layer, ##__VA_ARGS__); \
	} \
	return overlay->state = state;

_public_
int knot_overlay_init(struct knot_overlay *overlay, knot_mm_t *mm)
{
	list_t *layers = mm_alloc(mm, sizeof(list_t));
	if (layers == NULL) {
		return KNOT_ENOMEM;
	}
	init_list(layers);

	overlay->mm = mm;
	overlay->state = KNOT_STATE_NOOP;
	overlay->layers = layers;

	return KNOT_EOK;
}

_public_
void knot_overlay_deinit(struct knot_overlay *overlay)
{
	ptrnode_t *node = NULL;
	WALK_LIST(node, *LAYERS(overlay)) {
		mm_free(overlay->mm, node->d);
	}

	ptrlist_free(LAYERS(overlay), overlay->mm);
	mm_free(overlay->mm, overlay->layers);
}

_public_
int knot_overlay_add(struct knot_overlay *overlay, const knot_layer_api_t *module,
                     void *module_param)
{
	struct knot_layer *layer = mm_alloc(overlay->mm, sizeof(struct knot_layer));
	if (layer == NULL) {
		return KNOT_ENOMEM;
	}
	memset(layer, 0, sizeof(struct knot_layer));

	layer->state = overlay->state;
	layer->mm = overlay->mm;

	ptrlist_add(LAYERS(overlay), layer, overlay->mm);
	overlay->state = knot_layer_begin(layer, module, module_param);

	return KNOT_EOK;
}

_public_
int knot_overlay_reset(struct knot_overlay *overlay)
{
	ITERATE_LAYERS(overlay, knot_layer_reset);
}

_public_
int knot_overlay_finish(struct knot_overlay *overlay)
{
	/* Only in operable state. */
	if (overlay->state == KNOT_STATE_NOOP) {
		return overlay->state;
	}

	ITERATE_LAYERS(overlay, knot_layer_finish);
}

_public_
int knot_overlay_consume(struct knot_overlay *overlay, knot_pkt_t *pkt)
{
	/* Only if expecting data. */
	if (overlay->state != KNOT_STATE_CONSUME) {
		return overlay->state;
	}

	ITERATE_LAYERS(overlay, knot_layer_consume, pkt);
}

_public_
int knot_overlay_produce(struct knot_overlay *overlay, knot_pkt_t *pkt)
{
	/* Only in operable state. */
	if (overlay->state == KNOT_STATE_NOOP) {
		return overlay->state;
	}

	ITERATE_LAYERS(overlay, knot_layer_produce, pkt);
}
