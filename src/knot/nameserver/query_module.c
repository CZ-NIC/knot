#include "knot/nameserver/query_module.h"
#include "libknot/libknot.h"
#include "libknot/internal/strlcpy.h"

/* Compiled-in module headers. */
#include "knot/modules/synth_record.h"
#include "knot/modules/dnsproxy.h"
#ifdef HAVE_ROSEDB
#include "knot/modules/rosedb.h"
#endif
#if USE_DNSTAP
#include "knot/modules/dnstap.h"
#endif

typedef struct static_module {
	const yp_name_t *name;
	qmodule_load_t load;
	qmodule_unload_t unload;
	unsigned scope;
} static_module_t;

/*! \note All modules should be dynamically loaded later on. */
static_module_t MODULES[] = {
        { C_MOD_SYNTH_RECORD, &synth_record_load, &synth_record_unload, MOD_SCOPE_ANY },
        { C_MOD_DNSPROXY,     &dnsproxy_load,     &dnsproxy_unload,     MOD_SCOPE_ANY },
#ifdef HAVE_ROSEDB
        { C_MOD_ROSEDB,       &rosedb_load,       &rosedb_unload,       MOD_SCOPE_ANY },
#endif
#if USE_DNSTAP
        { C_MOD_DNSTAP,       &dnstap_load,       &dnstap_unload,       MOD_SCOPE_ANY },
#endif
        { NULL }
};

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

static struct query_step *make_step(mm_ctx_t *mm, qmodule_process_t process,
                                    void *ctx)
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

int query_plan_step(struct query_plan *plan, int stage, qmodule_process_t process,
                    void *ctx)
{
	struct query_step *step = make_step(plan->mm, process, ctx);
	if (step == NULL) {
		return KNOT_ENOMEM;
	}

	add_tail(&plan->stage[stage], &step->node);

	return KNOT_EOK;
}

static static_module_t *find_module(const yp_name_t *name)
{
	/* Search for the module by name. */
	static_module_t *module = NULL;
	for (unsigned i = 0; MODULES[i].name != NULL; ++i) {
		if (name[0] == MODULES[i].name[0] &&
		    memcmp(name + 1, MODULES[i].name + 1, name[0]) == 0) {
			module = &MODULES[i];
			break;
		}
	}

	return module;
}

struct query_module *query_module_open(conf_t *config, conf_mod_id_t *mod_id,
                                       mm_ctx_t *mm)
{
	if (config == NULL || mod_id == NULL) {
		return NULL;
	}

	/* Locate the module. */
	static_module_t *found = find_module(mod_id->name);
	if (found == NULL) {
		return NULL;
	}

	/* Create query module. */
	struct query_module *module = mm_alloc(mm, sizeof(struct query_module));
	if (module == NULL) {
		return NULL;
	}
	memset(module, 0, sizeof(struct query_module));

	module->mm = mm;
	module->config = config;
	module->id = mod_id;
	module->load = found->load;
	module->unload = found->unload;
	module->scope = found->scope;

	return module;
}

void query_module_close(struct query_module *module)
{
	if (module == NULL) {
		return;
	}

	conf_free_mod_id(module->id);
	mm_free(module->mm, module);
}
