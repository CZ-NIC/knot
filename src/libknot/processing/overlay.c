#include "libknot/processing/overlay.h"
#include "libknot/common.h"

/*! \note Macro for state-chaining layers. */
#define ITERATE_LAYERS(overlay, func, ...) \
	int state = overlay->state; \
	struct knot_layer *layer = NULL; \
	WALK_LIST(layer, (overlay)->layers) { \
		layer->state = state; /* Pass-through state. */ \
		state = (func)(layer, ##__VA_ARGS__); \
	} \
	return overlay->state = state;

void knot_overlay_init(struct knot_overlay *overlay, mm_ctx_t *mm)
{
	init_list(&overlay->layers);
	overlay->mm = mm;
	overlay->state = NS_PROC_NOOP;
}

void knot_overlay_deinit(struct knot_overlay *overlay)
{
	struct knot_layer *layer = NULL, *next = NULL;
	WALK_LIST_DELSAFE(layer, next, overlay->layers) {
		mm_free(overlay->mm, layer);
	}
}

int knot_overlay_add(struct knot_overlay *overlay, const knot_layer_api_t *module,
                     void *module_param)
{
	struct knot_layer *layer = mm_alloc(overlay->mm, sizeof(struct knot_layer));
	if (layer == NULL) {
		return KNOT_ENOMEM;
	}

	memset(layer, 0, sizeof(struct knot_layer));
	layer->mm = overlay->mm;
	layer->state = overlay->state;
	add_tail(&overlay->layers, (node_t *)layer);

	overlay->state = knot_layer_begin(layer, module, module_param);

	return KNOT_EOK;
}

int knot_overlay_reset(struct knot_overlay *overlay)
{
	ITERATE_LAYERS(overlay, knot_layer_reset);
}

int knot_overlay_finish(struct knot_overlay *overlay)
{
	/* Only in operable state. */
	if (overlay->state == NS_PROC_NOOP) {
		return overlay->state;
	}

	ITERATE_LAYERS(overlay, knot_layer_finish);
}

int knot_overlay_in(struct knot_overlay *overlay, knot_pkt_t *pkt)
{
	/* Only if expecting data. */
	if (overlay->state != NS_PROC_MORE) {
		return overlay->state;
	}

	knot_pkt_parse(pkt, 0);

	ITERATE_LAYERS(overlay, knot_layer_in, pkt);
}

int knot_overlay_out(struct knot_overlay *overlay, knot_pkt_t *pkt)
{
	/* Only in operable state. */
	if (overlay->state == NS_PROC_NOOP) {
		return overlay->state;
	}

	ITERATE_LAYERS(overlay, knot_layer_out, pkt);
}
