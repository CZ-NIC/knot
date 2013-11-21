#include <config.h>

#include "libknot/nameserver/update.h"
#include "libknot/nameserver/ns_proc_query.h"

int update_answer(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata)
{
	qdata->rcode = KNOT_RCODE_NOTIMPL;
	return NS_PROC_FAIL;
}
