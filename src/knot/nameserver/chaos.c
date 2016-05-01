/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <strings.h>

#include "knot/nameserver/chaos.h"
#include "knot/conf/conf.h"
#include "libknot/libknot.h"

/*!
 * \brief Get a string result for a given TXT query.
 */
static const char *get_txt_response_string(const knot_dname_t *qname)
{
	char *qname_str = knot_dname_to_str_alloc(qname);
	const char *response = NULL;

	/* id.server and hostname.bind should have similar meaning. */
	if (strcasecmp("id.server.",     qname_str) == 0 ||
	    strcasecmp("hostname.bind.", qname_str) == 0) {
		conf_val_t val = conf_get(conf(), C_SRV, C_IDENT);
		response = conf_str(&val);
		/* No item means auto. */
		if (val.code != KNOT_EOK) {
			response = conf()->hostname;
		}
	/* Allow both version version.{server, bind}. for compatibility. */
	} else if (strcasecmp("version.server.", qname_str) == 0 ||
	           strcasecmp("version.bind.",   qname_str) == 0) {
		conf_val_t val = conf_get(conf(), C_SRV, C_VERSION);
		response = conf_str(&val);
		/* No item means auto. */
		if (val.code != KNOT_EOK) {
			response = "Knot DNS " PACKAGE_VERSION;
		}
	}

	free(qname_str);

	return response;
}

/*!
 * \brief Create TXT RR with a given string content.
 *
 * \param owner     RR owner name.
 * \param response  String to be saved in RDATA. Truncated to 255 chars.
 * \param mm        Memory context.
 * \param rrset     Store here.
 *
 * \return KNOT_EOK
 */
static int create_txt_rrset(knot_rrset_t *rrset, const knot_dname_t *owner,
                            const char *response, knot_mm_t *mm)
{
	/* Truncate response to one TXT label. */
	size_t response_len = strlen(response);
	if (response_len > KNOT_DNAME_MAXLEN) {
		response_len = KNOT_DNAME_MAXLEN;
	}

	knot_dname_t *rowner = knot_dname_copy(owner, mm);
	if (!rowner) {
		return KNOT_ENOMEM;
	}

	knot_rrset_init(rrset, rowner, KNOT_RRTYPE_TXT, KNOT_CLASS_CH);
	uint8_t rdata[response_len + 1];

	rdata[0] = response_len;
	memcpy(&rdata[1], response, response_len);

	int ret = knot_rrset_add_rdata(rrset, rdata, response_len + 1, 0, mm);
	if (ret != KNOT_EOK) {
		knot_dname_free(&rrset->owner, mm);
		return ret;
	}

	return KNOT_EOK;
}

/*!
 * \brief Create a response for a TXT CHAOS query.
 *
 * \param return KNOT_RCODE_NOERROR if the response was successfully created,
 *               otherwise an RCODE representing the failure.
 */
static int answer_txt(knot_pkt_t *response)
{
	const knot_dname_t *qname = knot_pkt_qname(response);
	const char *response_str = get_txt_response_string(qname);
	if (response_str == NULL || response_str[0] == '\0') {
		return KNOT_RCODE_REFUSED;
	}

	knot_rrset_t rrset;
	int ret = create_txt_rrset(&rrset, qname, response_str, &response->mm);
	if (ret != KNOT_EOK) {
		return KNOT_RCODE_SERVFAIL;
	}

	int result = knot_pkt_put(response, 0, &rrset, KNOT_PF_FREE);
	if (result != KNOT_EOK) {
		knot_rrset_clear(&rrset, &response->mm);
		return KNOT_RCODE_SERVFAIL;
	}

	return KNOT_RCODE_NOERROR;
}

int knot_chaos_answer(knot_pkt_t *pkt)
{
	if (knot_pkt_qtype(pkt) != KNOT_RRTYPE_TXT) {
		return KNOT_RCODE_REFUSED;
	}

	return answer_txt(pkt);
}
