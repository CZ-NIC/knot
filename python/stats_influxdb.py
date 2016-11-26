#!/usr/bin/env python3

"""Simple program for exporting statistics from Knot DNS to influxdb."""

import libknot.control
import io
import json
import os
import time

# Configuration.
#libknot.control.load_lib("../src/.libs/libknot.so")
ctl_socket = "/tmp/knot.sock"
ctl_timeout = 2
# InfluxDB parameters.
host = "217.31.192.164"
port = "8086"
db = "KnotDNS"
instance = "Knot"
# Send metrics every N seconds.
send_interval = 5


def send():
    # Connect to Knot server.
    ctl = libknot.control.KnotCtl()
    ctl.connect(ctl_socket)
    ctl.set_timeout(ctl_timeout)

    # Get global metrics.
    global_stats = dict()
    try:
        ctl.send_block(cmd="stats", flags="F")
        global_stats = ctl.receive_stats()
    except:
        pass

    # Get zone metrics.
    zone_stats = dict()
    try:
        ctl.send_block(cmd="zone-stats", flags="F")
        zone_stats = ctl.receive_stats()
    except:
        pass

    # Disconnect from the server.
    ctl.send(libknot.control.KnotCtlType.END)
    ctl.close()

    # Prepare the metrics to publish.
    output = io.StringIO()

    stats = {**global_stats, **zone_stats}
    timestamp = str(int(time.time()))

    for metric in stats["server"]:
        print("server,instance=" + instance + ",metric=" + metric + " value=" +
              stats["server"][metric] + " " + timestamp, file=output)

    for group in stats["mod-stats"]:
        for metric in stats["mod-stats"][group]:
            print(group + ",instance=" + instance + ",metric=" + metric +
                  " value=" + stats["mod-stats"][group][metric] + " " + timestamp,
                  file=output)

    # Publish the metrics.
    os.system("curl -i -XPOST 'http://%s:%s/write?db=%s&precision=s' --data-binary '%s'"
              % (host, port, db, output.getvalue()))


print("%s: Graphite sender - Server Start - %s:%s" %
      (time.asctime(), host, port))

try:
   while(True):
      send()
      time.sleep(send_interval)
except KeyboardInterrupt:
   pass
