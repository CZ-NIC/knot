/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "load_queries.h"
#include "libknot/libknot.h"
#include "utils/common/msg.h"

#define ERR_PREFIX "failed loading queries "

enum qflags {
	QFLAG_EDNS = 1,
	QFLAG_DO = 2,
};

struct pkt_payload *global_payloads = NULL;

void free_global_payloads(void)
{
	struct pkt_payload *g_payloads_p = global_payloads, *tmp;
	while (g_payloads_p != NULL) {
		tmp = g_payloads_p;
		g_payloads_p = tmp->next;
		free(tmp);
	}
	global_payloads = NULL;
}

typedef struct {
	char line[KNOT_DNAME_TXT_MAXLEN + 256];
	char dname_txt[KNOT_DNAME_TXT_MAXLEN + 1];
	uint8_t dname[KNOT_DNAME_MAXLEN];
	char type_txt[128];
	char flags_txt[128];
} txt_bufs_t;

typedef struct {
	char line[USHRT_MAX];
} bin_bufs_t;

static int read_txt(struct pkt_payload **g_payloads_top_p, FILE *f, txt_bufs_t *bufs,
                    uint16_t edns_size, uint16_t msgid)
{
	assert(g_payloads_top_p != NULL);
	struct pkt_payload *g_payloads_top = *g_payloads_top_p;
	if (fgets(bufs->line, sizeof(bufs->line), f) == NULL) {
		return 0;
	}
	bufs->flags_txt[0] = '\0';
	int ret = sscanf(bufs->line, "%s%s%s", bufs->dname_txt, bufs->type_txt,
	                 bufs->flags_txt);
	if (ret < 2) {
		ERR2(ERR_PREFIX "(faulty line): '%.*s'",
		     (int)strcspn(bufs->line, "\n"), bufs->line);
		return KNOT_EINVAL;
	}

	void *pret = knot_dname_from_str(bufs->dname, bufs->dname_txt, sizeof(bufs->dname));
	if (pret == NULL) {
		ERR2(ERR_PREFIX "(faulty dname): '%s'", bufs->dname_txt);
		return KNOT_EINVAL;
	}

	uint16_t type;
	ret = knot_rrtype_from_string(bufs->type_txt, &type);
	if (ret < 0) {
		ERR2(ERR_PREFIX "(faulty type): '%s'", bufs->type_txt);
		return KNOT_EINVAL;
	}

	enum qflags flags = 0;
	switch (bufs->flags_txt[0]) {
	case '\0':
		break;
	case 'e':
	case 'E':
		flags |= QFLAG_EDNS;
		break;
	case 'd':
	case 'D':
		flags |= QFLAG_EDNS | QFLAG_DO;
		break;
	default:
		ERR2(ERR_PREFIX "(faulty flag): '%s'", bufs->flags_txt);
		return KNOT_EINVAL;
	}

	size_t dname_len = knot_dname_size(bufs->dname);
	size_t pkt_len = KNOT_WIRE_HEADER_SIZE + 2 * sizeof(uint16_t) + dname_len;
	if (flags & QFLAG_EDNS) {
		pkt_len += KNOT_EDNS_MIN_SIZE;
	}

	struct pkt_payload *pkt = calloc(1, sizeof(*pkt) + pkt_len);
	if (pkt == NULL) {
		ERR2(ERR_PREFIX "(out of memory)");
		return KNOT_ENOMEM;
	}
	pkt->len = pkt_len;
	memcpy(pkt->payload, &msgid, sizeof(msgid));
	pkt->payload[2] = 0x01; // RD bit
	pkt->payload[5] = 0x01; // 1 question
	pkt->payload[11] = (flags & QFLAG_EDNS) ? 0x01 : 0x00;
	memcpy(pkt->payload + 12, bufs->dname, dname_len);
	pkt->payload[dname_len + 12] = type >> 8;
	pkt->payload[dname_len + 13] = type & 0xff;
	pkt->payload[dname_len + 15] = KNOT_CLASS_IN;
	if (flags & QFLAG_EDNS) {
		pkt->payload[dname_len + 18] = KNOT_RRTYPE_OPT;
		pkt->payload[dname_len + 19] = edns_size >> 8;
		pkt->payload[dname_len + 20] = edns_size & 0xff;
		pkt->payload[dname_len + 23] = (flags & QFLAG_DO) ? 0x80 : 0x00;
	}

	// add pkt to list global_payloads
	if (g_payloads_top == NULL) {
		global_payloads = pkt;
		*g_payloads_top_p = pkt;
	} else {
		g_payloads_top->next = pkt;
		*g_payloads_top_p = pkt;
	}
	return pkt_len;
}

static int read_bin(struct pkt_payload **g_payloads_top_p, FILE *f, bin_bufs_t *bufs,
                    uint16_t msgid)
{
	assert(g_payloads_top_p != NULL);
	struct pkt_payload *g_payloads_top = *g_payloads_top_p;
	uint16_t size;
	if (fread(&size, sizeof(size), 1, f) < 1) {
		return 0;
	}
	size = ntohs(size);
	if (fread(bufs->line, size, 1, f) < 1) {
		return KNOT_EINVAL;
	}
	struct pkt_payload *pkt = calloc(1, sizeof(*pkt) + size);
	if (pkt == NULL) {
		ERR2(ERR_PREFIX "(out of memory)");
		return KNOT_ENOMEM;
	}
	pkt->len = size;
	memcpy(pkt->payload, &msgid, sizeof(msgid)); // Override msgID
	memcpy(pkt->payload + 2, bufs->line + 2, size - 2);

	// add pkt to list global_payloads
	if (g_payloads_top == NULL) {
		global_payloads = pkt;
		*g_payloads_top_p = pkt;
	} else {
		g_payloads_top->next = pkt;
		*g_payloads_top_p = pkt;
	}
	return size;
}

bool load_queries(const input_t *input, uint16_t edns_size, uint16_t msgid, size_t maxcount)
{
	size_t read = 0;
	FILE *f = fopen(input->path, (input->format == BIN) ? "rb" : "r");
	if (f == NULL) {
		ERR2(ERR_PREFIX "file '%s' (%s)", input->path, strerror(errno));
		return false;
	}

	void *bufs = NULL;
	switch (input->format) {
	case TXT:
		bufs = malloc(sizeof(txt_bufs_t)); // avoiding too much stuff on stack
		break;
	case BIN:
		bufs = malloc(sizeof(bin_bufs_t));
		break;
	default:
		assert(0);
		goto fail;
	}
	if (bufs == NULL) {
		ERR2(ERR_PREFIX "(out of memory)");
		goto fail;
	}

	struct pkt_payload *g_payloads_top = NULL;
	while (read < maxcount) {
		int ret = 0;
		switch (input->format) {
		case TXT:
			ret = read_txt(&g_payloads_top, f, bufs, edns_size, msgid);
			break;
		case BIN:
			ret = read_bin(&g_payloads_top, f, bufs, msgid);
			break;
		default:
			ret = -1;
			break;
		}
		if (ret == 0) {
			break;
		} else if (ret < 0) {
			goto fail;
		}
		read++;
	}

	if (global_payloads == NULL) {
		ERR2(ERR_PREFIX "(no queries in file)");
		goto fail;
	}

	free(bufs);
	fclose(f);
	return true;

fail:
	free_global_payloads();
	free(bufs);
	fclose(f);
	return false;
}
