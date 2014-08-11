#include "libknot/processing/overlay.h"
#include "libknot/common.h"

/*! \note Macro for state-chaining layers. */
#define ITERATE_LAYERS(overlay, func, ...) \
	int state = overlay->state; \
	struct knot_layer *layer = NULL; \
	WALK_LIST(layer, (overlay)->layers) { \
		layer->proc.state = state; /* Pass-through state. */ \
		state = (func)(&layer->proc, ##__VA_ARGS__); \
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

int knot_overlay_add(struct knot_overlay *overlay, void *module_param,
                     const knot_process_module_t *module)
{
	struct knot_layer *layer = mm_alloc(overlay->mm, sizeof(struct knot_layer));
	if (layer == NULL) {
		return KNOT_ENOMEM;
	}

	memset(layer, 0, sizeof(struct knot_layer));
	layer->proc.mm = overlay->mm;
	layer->proc.state = overlay->state;
	add_tail(&overlay->layers, (node_t *)layer);

	overlay->state = knot_process_begin(&layer->proc, module_param, module);

	return KNOT_EOK;
}

int knot_overlay_reset(struct knot_overlay *overlay)
{
	ITERATE_LAYERS(overlay, knot_process_reset);
}

int knot_overlay_finish(struct knot_overlay *overlay)
{
	ITERATE_LAYERS(overlay, knot_process_finish);
}

int knot_overlay_in(struct knot_overlay *overlay, const uint8_t *wire, uint16_t wire_len)
{
	ITERATE_LAYERS(overlay, knot_process_in, wire, wire_len);
}

int knot_overlay_out(struct knot_overlay *overlay, uint8_t *wire, uint16_t *wire_len)
{
	ITERATE_LAYERS(overlay, knot_process_out, wire, wire_len);
}
