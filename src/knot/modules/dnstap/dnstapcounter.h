// <copyright file="dnstapcounter.h" company="Microsoft">
//  Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>

#pragma once
#include "knot/include/modcounter.h"

#define FOREACH_DNSTAP_COUNTER(OPS1, param1, OPS2, param2) \
    OPS2(param2, OPS1(param1, log_emitted)) \
    OPS2(param2, OPS1(param1, log_dropped)) \
    OPS2(param2, OPS1(param1, max))

#define FOREACH_LOG_EMITTED(OPS1, param1, OPS2, param2) \
    OPS2(param2, OPS1(param1, QUERY)) \
    OPS2(param2, OPS1(param1, RESPONSE))

#define FOREACH_LOG_DROPPED(OPS1, param1, OPS2, param2) \
    OPS2(param2, OPS1(param1, QUERY)) \
    OPS2(param2, OPS1(param1, RESPONSE))

#define FOREACH_MAX(OPS1, param1, OPS2, param2) OPS2(param2, OPS1(param1, max))

CREATE_COUNTERS(dnstap_counter, FOREACH_DNSTAP_COUNTER)
CREATE_DIMENSIONS(log_emitted, FOREACH_LOG_EMITTED)
CREATE_DIMENSIONS(log_dropped, FOREACH_LOG_DROPPED)
CREATE_DIMENSIONS(max, FOREACH_MAX)
CREATE_NAME_MAP(dnstap_counter, FOREACH_DNSTAP_COUNTER)

/*!
 * \brief Creates all counters for module.
 *
 * \param mod Module handle for the counters.
 *
 */
int dnstap_create_counters(knotd_mod_t *mod);

/*!
 * \brief cleans up the counters for the module.
 *
 * \param mod Module handle for the counters.
 */
void dnstap_delete_counters(knotd_mod_t *mod);