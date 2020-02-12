/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/xdp/bpf-kernel-obj.h"
#include "libknot/xdp/bpf-user.h"

#include "libknot/endian.h"
#include "libknot/error.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>

static int ensure_udp_prog(struct kxsk_iface *iface, const char *prog_fname, bool overwrite)
{
	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall */
	int prog_fd;
	int ret = bpf_prog_load(prog_fname, BPF_PROG_TYPE_XDP, &iface->prog_obj, &prog_fd);
	if (ret) {
		return KNOT_EPROGRAM;
	}

	ret = bpf_set_link_xdp_fd(iface->ifindex, prog_fd,
			overwrite ? 0 : XDP_FLAGS_UPDATE_IF_NOEXIST);
	if (ret) {
		close(prog_fd);
	}
	if (ret == -EBUSY && !overwrite) { /* We try accepting the present program. */
		uint32_t prog_id = 0;
		ret = bpf_get_link_xdp_id(iface->ifindex, &prog_id, 0);
		if (!ret && prog_id) {
			ret = prog_fd = bpf_prog_get_fd_by_id(prog_id);
		}
	}
	if (ret < 0) {
		return KNOT_EFD;
	} else {
		return prog_fd;
	}
}

static int array2file(char *filename, const uint8_t *array, unsigned len)
{
	int fd = mkstemp(filename);
	if (fd < 0) {
		return -errno;
	}

	int ret = write(fd, array, len);
	if (ret < len) {
		return -errno;
	}

	ret = close(fd);
	if (ret < 0) {
		return -errno;
	}

	return KNOT_EOK;
}

static int ensure_udp_prog_builtin(struct kxsk_iface *iface, bool overwrite)
{
	if (bpf_kernel_o_len < 2) {
		return KNOT_ENOTSUP;
	}

	char filename[] = "/tmp/knotd_bpf_prog_obj_XXXXXX";
	int ret = array2file(filename, bpf_kernel_o, bpf_kernel_o_len);
	if (ret) {
		return ret;
	}

	ret = ensure_udp_prog(iface, filename, overwrite);
	unlink(filename);
	return ret;
}

/** Get FDs for the two maps and assign them into xsk_info-> fields.
 *
 * It's almost precise copy of xsk_lookup_bpf_maps() from libbpf
 * (version before they eliminated qidconf_map)
 * Copyright by Intel, LGPL-2.1 or BSD-2-Clause. */
static int get_bpf_maps(int prog_fd, struct kxsk_iface *iface)
{
	__u32 i, *map_ids, num_maps, prog_len = sizeof(struct bpf_prog_info);
	__u32 map_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info prog_info = {};
	struct bpf_map_info map_info;
	int fd, err;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err) {
		return err;
	}

	num_maps = prog_info.nr_map_ids;

	map_ids = calloc(prog_info.nr_map_ids, sizeof(*map_ids));
	if (map_ids == NULL) {
		return KNOT_ENOMEM;
	}

	memset(&prog_info, 0, prog_len);
	prog_info.nr_map_ids = num_maps;
	prog_info.map_ids = (__u64)(unsigned long)map_ids;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err) {
		goto out_map_ids;
	}

	for (i = 0; i < prog_info.nr_map_ids; ++i) {
		if (iface->qidconf_map_fd >= 0 && iface->xsks_map_fd >= 0) {
			break;
		}

		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0) {
			continue;
		}

		err = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (err) {
			close(fd);
			continue;
		}

		if (!strcmp(map_info.name, "qidconf_map")) {
			iface->qidconf_map_fd = fd;
			continue;
		}

		if (!strcmp(map_info.name, "xsks_map")) {
			iface->xsks_map_fd = fd;
			continue;
		}

		close(fd);
	}

	if (iface->qidconf_map_fd < 0 || iface->xsks_map_fd < 0) {
		err = KNOT_ENOENT;
		close(iface->qidconf_map_fd);
		close(iface->xsks_map_fd);
		iface->qidconf_map_fd = iface->xsks_map_fd = -1;
		goto out_map_ids;
	}

	err = KNOT_EOK; // success!

out_map_ids:
	free(map_ids);
	return err;
}

static void unget_bpf_maps(struct kxsk_iface *iface)
{
	close(iface->qidconf_map_fd);
	close(iface->xsks_map_fd);
	iface->qidconf_map_fd = iface->xsks_map_fd = -1;
}

int kxsk_socket_start(const struct kxsk_iface *iface, int queue_id,
                      uint32_t listen_port, struct xsk_socket *xsk)
{
	int fd = xsk_socket__fd(xsk);
	int err = bpf_map_update_elem(iface->xsks_map_fd, &queue_id, &fd, 0);
	if (err) {
		return err;
	}

	int qid = (listen_port & 0xffff0000) | htobe16(listen_port & 0xffff);
	err = bpf_map_update_elem(iface->qidconf_map_fd, &queue_id, &qid, 0);
	if (err) {
		bpf_map_delete_elem(iface->xsks_map_fd, &queue_id);
	}
	return err;
}

int kxsk_socket_stop(const struct kxsk_iface *iface, int queue_id)
{
	int qid = false;
	int err = bpf_map_update_elem(iface->qidconf_map_fd, &queue_id, &qid, 0);
	// Clearing the second map doesn't seem important, but why not.
	bpf_map_delete_elem(iface->xsks_map_fd, &queue_id);
	return err;
}

int kxsk_iface_new(const char *ifname, knot_xsk_load_bpf_t load_bpf,
		   struct kxsk_iface **out_iface)
{
	struct kxsk_iface *iface = calloc(1, sizeof(*iface));
	if (iface == NULL) {
		return KNOT_ENOMEM;
	}
	iface->ifname = ifname; // we strdup it later
	iface->ifindex = if_nametoindex(ifname);
	if (!iface->ifindex) {
		free(iface);
		return knot_map_errno();
	}
	iface->qidconf_map_fd = iface->xsks_map_fd = -1;

	int ret;
	switch (load_bpf) {
	case KNOT_XSK_LOAD_BPF_NEVER:
		(void)0;
		uint32_t prog_id = 0;
		ret = bpf_get_link_xdp_id(iface->ifindex, &prog_id, 0);
		if (!ret && prog_id) {
			ret = bpf_prog_get_fd_by_id(prog_id);
		}
		break;
	case KNOT_XSK_LOAD_BPF_ALWAYS:
		ret = ensure_udp_prog_builtin(iface, true);
		break;
	case KNOT_XSK_LOAD_BPF_MAYBE:
		ret = ensure_udp_prog_builtin(iface, false);
		break;
	default:
		return KNOT_EINVAL;
	}

	if (ret >= 0) {
		ret = get_bpf_maps(ret, iface);
	}
	if (ret < 0) {
		free(iface);
		return ret;
	}

	iface->ifname = strdup(iface->ifname);
	*out_iface = iface;
	return KNOT_EOK;
}

void kxsk_iface_free(struct kxsk_iface *iface)
{
	unget_bpf_maps(iface);

	if (iface->prog_obj != NULL) {
		(void)bpf_object__close(iface->prog_obj);
	}

	free((char *)/*const-cast*/iface->ifname);
	free(iface);
}
