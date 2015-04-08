#include "knot/nameserver/query_module.h"
#include "libknot/mempattern.h"
#include "libknot/errcode.h"
#include "common-knot/strlcpy.h"

/* Compiled-in module headers. */
#include "knot/modules/synth_record.h"
#if HAVE_ROSEDB
#include "knot/modules/rosedb.h"
#endif
#if USE_DNSTAP
#include "knot/modules/dnstap.h"
#endif

/* Compiled-in module table. */
struct compiled_module {
	const char *name;
	qmodule_load_t load;
	qmodule_unload_t unload;
};

/*! \note All modules should be dynamically loaded later on. */
struct compiled_module MODULES[] = {
        { "synth_record", &synth_record_load, &synth_record_unload },
#if HAVE_ROSEDB
        { "rosedb", &rosedb_load, &rosedb_unload },
#endif
#if USE_DNSTAP
        { "dnstap",       &dnstap_load,       &dnstap_unload }
#endif
};

#define MODULE_COUNT sizeof(MODULES) / sizeof(MODULES[0])

struct query_plan *query_plan_create(mm_ctx_t *mm)
{
	struct query_plan *plan = mm_alloc(mm, sizeof(struct query_plan));
	if (plan == NULL) {
		return NULL;
	}

	plan->mm = mm;
	for (unsigned i = 0; i < QUERY_PLAN_STAGES; ++i) {
		init_list(&plan->stage[i]);
	}

	return plan;
}

void query_plan_free(struct query_plan *plan)
{
	if (plan == NULL) {
		return;
	}

	for (unsigned i = 0; i < QUERY_PLAN_STAGES; ++i) {
		struct query_step *step = NULL, *next = NULL;
		WALK_LIST_DELSAFE(step, next, plan->stage[i]) {
			mm_free(plan->mm, step);
		}
	}

	mm_free(plan->mm, plan);
}

static struct query_step *make_step(mm_ctx_t *mm, qmodule_process_t process, void *ctx)
{
	struct query_step *step = mm_alloc(mm, sizeof(struct query_step));
	if (step == NULL) {
		return NULL;
	}

	memset(step, 0, sizeof(struct query_step));
	step->process = process;
	step->ctx = ctx;
	return step;
}

int query_plan_step(struct query_plan *plan, int stage, qmodule_process_t process, void *ctx)
{
	struct query_step *step = make_step(plan->mm, process, ctx);
	if (step == NULL) {
		return KNOT_ENOMEM;
	}

	add_tail(&plan->stage[stage], &step->node);
	return KNOT_EOK;
}

struct query_module *query_module_open(struct conf_t *config, const char *name,
                                       const char *param, mm_ctx_t *mm)
{
	/* Locate compiled-in modules. */
	struct compiled_module *found = NULL;
	for (unsigned i = 0; i < MODULE_COUNT; ++i) {
		if (strcmp(MODULES[i].name, name) == 0) {
			found = &MODULES[i];
			break;
		}
	}

	/* Module not found. */
	if (found == NULL) {
		return NULL;
	}

	struct query_module *module = mm_alloc(mm, sizeof(struct query_module));
	if (module == NULL) {
		return NULL;
	}

	size_t buflen = strlen(param) + 1;
	memset(module, 0, sizeof(struct query_module));
	module->mm = mm;
	module->config = config;
	module->load = found->load;
	module->unload = found->unload;
	module->param = mm_alloc(mm, buflen);
	if (module->param == NULL) {
		mm_free(mm, module);
		return NULL;
	}
	strlcpy(module->param, param, buflen);

	return module;
}

void query_module_close(struct query_module *module)
{
	if (module == NULL) {
		return;
	}

	module->unload(module);
	mm_free(module->mm, module->param);
	mm_free(module->mm, module);
}
