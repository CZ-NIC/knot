#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libknot/probe/client.h>

int main(int argc, char **argv)
{
	knot_probe_pollfd_t pfd;
	knot_probe_init(&pfd, 8);
	knot_probe_bind(&pfd, "/tmp/kprobe-");

	knot_probe_datagram_t d;

	int ret = poll(pfd.pfds, pfd.nfds, -1);
	for (struct pollfd *it = pfd.pfds; it < &pfd.pfds[pfd.nfds]; ++it) {
		if (it->revents & POLLIN) {
			recv(it->fd, &d, sizeof(d), 0);
			// Here you can process datagram
		}
	}

	knot_probe_close(&pfd);
	knot_probe_deinit(&pfd);

	return 0;
}
