

/*
 * Wrap function server_reconfigure to initialize udp_master to stdin
 */
#define server_reconfigure _orig_server_reconfigure
#include "knot/server/server.c"
#undef server_reconfigure

extern void udp_master_init_stdio(server_t *server);

int server_reconfigure(conf_t *conf, void* data)
{
	log_info("AFL, Wrap server_reconfigure()");
	int ret = _orig_server_reconfigure(conf, data);
	udp_master_init_stdio(data);
	return ret;
}
