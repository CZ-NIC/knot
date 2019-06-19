#!/usr/bin/env python3

"""Simple program for exposing statistics from Knot DNS over HTTP/HTTPS."""

import http.server
import libknot.control
import json
import ssl
import time

# Configuration.
#libknot.control.load_lib("../src/.libs/libknot.so")
ctl_socket = "/tmp/knot.sock"
ctl_timeout = 2
ctl_flags = "" # set "F" for all supported counters.
http_host = "127.0.0.1"
http_port = 8080
ssl_enable = False
ssl_keyfile = "./mykey.key"
ssl_certfile = "./mycert.crt"


class StatsServer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        # Connect to Knot server.
        ctl = libknot.control.KnotCtl()
        ctl.connect(ctl_socket)
        ctl.set_timeout(ctl_timeout)

        # Get global metrics.
        global_stats = dict()
        try:
            ctl.send_block(cmd="stats", flags=ctl_flags)
            global_stats = ctl.receive_stats()
        except:
            pass

        # Get zone metrics.
        zone_stats = dict()
        try:
            ctl.send_block(cmd="zone-stats", flags=ctl_flags)
            zone_stats = ctl.receive_stats()
        except:
           pass

        # Disconnect from the server.
        ctl.send(libknot.control.KnotCtlType.END)
        ctl.close()

        # Publish the stats.
        stats = {**global_stats, **zone_stats}
        self.wfile.write(bytes(json.dumps(stats, indent=4, sort_keys=True), "utf-8"))


httpd = http.server.HTTPServer((http_host, http_port), StatsServer)

if ssl_enable:
    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=ssl_keyfile,
                                   certfile=ssl_certfile, server_side=True)

print("%s: HTTP%s Server Start - %s:%s" %
      (time.asctime(), "S" if ssl_enable else "", http_host, http_port))

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    pass

httpd.server_close()
