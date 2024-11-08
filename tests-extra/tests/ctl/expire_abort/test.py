#!/usr/bin/env python3

'''Test for automatic zone transaction abort when zone expires'''

from dnstest.libknot import libknot
from dnstest.test import Test
from dnstest.utils import *

def check_txn(server, zone, is_open):
    ctl = libknot.control.KnotCtl()
    ctl.connect(os.path.join(slave.dir, "knot.sock"))

    ctl.send_block(cmd="zone-status", zone=zone, flags="B", filters="t")
    resp = ctl.receive_block()
    if is_open:
        isset(resp[zone]["transaction"] == "open", "open transaction")
    else:
        isset(resp[zone]["transaction"] == "-", "no transaction")

    ctl.send(libknot.control.KnotCtlType.END)
    ctl.close()

def test_expire(master, slave, zone, manual_expiration):
    slave.ctl("zone-refresh")
    slave.zone_wait(zone)
    master.stop()

    slave.ctl("zone-begin expire")
    check_txn(slave, zone[0].name, True)
    slave.ctl("zone-set expire test TXT test")

    if manual_expiration:
        slave.ctl("-f zone-purge +expire expire")
    else:
        t.sleep(5)

    try:
        slave.ctl("zone-commit expire")
        set_err("control txn not aborted")
    except Exception:
        pass

    check_txn(slave, zone[0].name, False)
    resp = slave.dig("test.expire", "TXT")
    resp.check(rcode="SERVFAIL")

    master.start()

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone("expire.", storage=".")
t.link(zone, master, slave)

t.start()

# Expire manually
test_expire(master, slave, zone, True)

# Expire by the SOA timer
test_expire(master, slave, zone, False)

t.end()
