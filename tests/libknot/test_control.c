/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <tap/basic.h>
#include <tap/files.h>

#define CTL_BUFF_SIZE	18
#include "libknot/control/control.c"

#define fake_ok(condition, msg, ...) \
	if (!(condition)) { \
		if (msg != NULL) { \
			printf("error: " msg "\n", ##__VA_ARGS__); \
		} \
		exit(-1); \
	}

static void ctl_client(const char *socket, size_t argc, knot_ctl_data_t *argv)
{
	knot_ctl_t *ctl = knot_ctl_alloc();
	fake_ok(ctl != NULL, "Allocate control");

	int ret;
	for (int i = 0; i < 20; i++) {
		ret = knot_ctl_connect(ctl, socket);
		if (ret == KNOT_EOK) {
			break;
		}
		usleep(100000);
	}
	fake_ok(ret == KNOT_EOK, "Connect to socket");

	diag("BEGIN: Client -> Server");

	if (argc > 0) {
		for (size_t i = 0; i < argc; i++) {
			if (argv[i][KNOT_CTL_IDX_CMD] != NULL &&
			    argv[i][KNOT_CTL_IDX_CMD][0] == '\0') {
				ret = knot_ctl_send(ctl, KNOT_CTL_TYPE_BLOCK, NULL);
				fake_ok(ret == KNOT_EOK, "Client send data block end type");
			} else {
				ret = knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, &argv[i]);
				fake_ok(ret == KNOT_EOK, "Client send data %zu", i);
			}
		}
	}

	ret = knot_ctl_send(ctl, KNOT_CTL_TYPE_END, NULL);
	fake_ok(ret == KNOT_EOK, "Client send final data");

	diag("END: Client -> Server");
	diag("BEGIN: Client <- Server");

	size_t count = 0;
	knot_ctl_data_t data;
	knot_ctl_type_t type;
	while ((ret = knot_ctl_receive(ctl, &type, &data)) == KNOT_EOK) {
		if (type == KNOT_CTL_TYPE_END) {
			break;
		}
		if (argv[count][KNOT_CTL_IDX_CMD] != NULL &&
		    argv[count][KNOT_CTL_IDX_CMD][0] == '\0') {
			fake_ok(type == KNOT_CTL_TYPE_BLOCK, "Receive block end type");
		} else {
			fake_ok(type == KNOT_CTL_TYPE_DATA, "Check data type");
			for (size_t i = 0; i < KNOT_CTL_IDX__COUNT; i++) {
				fake_ok((data[i] == NULL && argv[count][i] == NULL) ||
					(data[i] != NULL && argv[count][i] != NULL),
					"Client compare input item occupation %zu", i);
				if (data[i] == NULL) {
					continue;
				}

				fake_ok(strcmp(data[i], argv[count][i]) == 0,
					"Client compare input item '%s", argv[count][i]);
			}
		}
		count++;
	}
	fake_ok(ret == KNOT_EOK, "Receive OK check");
	fake_ok(type == KNOT_CTL_TYPE_END, "Receive EOF type");
	fake_ok(count == argc, "Client compare input count '%zu'", argc);

	diag("END: Client <- Server");

	knot_ctl_close(ctl);
	knot_ctl_free(ctl);
}

static void ctl_server(const char *socket, size_t argc, knot_ctl_data_t *argv)
{
	knot_ctl_t *ctl = knot_ctl_alloc();
	ok(ctl != NULL, "Allocate control");

	int ret = knot_ctl_bind(ctl, socket);
	is_int(KNOT_EOK, ret, "Bind control socket");

	ret = knot_ctl_accept(ctl);
	is_int(KNOT_EOK, ret, "Accept a connection");

	diag("BEGIN: Server <- Client");

	size_t count = 0;
	knot_ctl_data_t data;
	knot_ctl_type_t type;
	while ((ret = knot_ctl_receive(ctl, &type, &data)) == KNOT_EOK) {
		if (type == KNOT_CTL_TYPE_END) {
			break;
		}
		if (argv[count][KNOT_CTL_IDX_CMD] != NULL &&
		    argv[count][KNOT_CTL_IDX_CMD][0] == '\0') {
			ok(type == KNOT_CTL_TYPE_BLOCK, "Receive block end type");
		} else {
			ok(type == KNOT_CTL_TYPE_DATA, "Check data type");
			for (size_t i = 0; i < KNOT_CTL_IDX__COUNT; i++) {
				ok((data[i] == NULL && argv[count][i] == NULL) ||
				   (data[i] != NULL && argv[count][i] != NULL),
				   "Server compare input item occupation %zu", i);
				if (data[i] == NULL) {
					continue;
				}

				ok(strcmp(data[i], argv[count][i]) == 0,
				   "Server compare input item '%s", argv[count][i]);
			}
		}
		count++;
	}
	is_int(KNOT_EOK, ret, "Receive OK check");
	ok(type == KNOT_CTL_TYPE_END, "Receive EOF type");
	ok(count == argc, "Server compare input count '%zu'", argc);

	diag("END: Server <- Client");
	diag("BEGIN: Server -> Client");

	if (argc > 0) {
		for (size_t i = 0; i < argc; i++) {
			if (argv[i][KNOT_CTL_IDX_CMD] != NULL &&
			    argv[i][KNOT_CTL_IDX_CMD][0] == '\0') {
				ret = knot_ctl_send(ctl, KNOT_CTL_TYPE_BLOCK, NULL);
				is_int(KNOT_EOK, ret, "Client send data block end type");
			} else {
				ret = knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, &argv[i]);
				is_int(KNOT_EOK, ret, "Server send data %zu", i);
			}
		}
	}

	ret = knot_ctl_send(ctl, KNOT_CTL_TYPE_END, NULL);
	is_int(KNOT_EOK, ret, "Server send final data");

	diag("END: Server -> Client");

	knot_ctl_close(ctl);
	knot_ctl_unbind(ctl);
	knot_ctl_free(ctl);
}

static void test_client_server_client(void)
{
	char *socket = test_mktemp();
	ok(socket != NULL, "Make a temporary socket file '%s'", socket);

	size_t data_len = 5;
	knot_ctl_data_t data[] = {
		{ "command", "error", "section", "item", "identifier",
		  "zone", "owner", "ttl", "type", "data" },
		{ [KNOT_CTL_IDX_DATA] = "\x01\x02" },
		{ [KNOT_CTL_IDX_CMD] = "\0" }, // This means block end in this test!
		{ NULL },
		{ [KNOT_CTL_IDX_ERROR] = "Ultra long message" }
	};

	// Fork a client process.
	pid_t child_pid = fork();
	if (child_pid == -1) {
		ok(child_pid >= 0, "Process fork");
		return;
	}
	if (child_pid == 0) {
		ctl_client(socket, data_len, data);
		free(socket);
		return;
	} else {
		ctl_server(socket, data_len, data);
	}

	int status = 0;
	wait(&status);
	ok(WIFEXITED(status), "Wait for client");

	test_rm_rf(socket);
	free(socket);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	diag("Client -> Server -> Client");
	test_client_server_client();

	return 0;
}
