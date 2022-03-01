#!/usr/bin/env python3

"""
Perform an incremental signing routine when re-sign is already pending.
"""

from dnstest.utils import *
from dnstest.test import Test
import random

MANUAL = random.choice([False, True])
FAIL2ROLL = random.choice([False, True])
detail_log("Manual %s, Fail2roll %s" % (str(MANUAL), str(FAIL2ROLL)))

t = Test()

master = t.server("knot")
slave = t.server("knot")
zone = t.zone_rnd(1, records=500, dnssec=False)
t.link(zone, master, slave, ddns=True)

ZONE = zone[0].name

slave.zonefile_sync = "-1"
if FAIL2ROLL:
    slave.journal_max_usage = 128 * 1024

slave.dnssec(zone).enable = True
slave.dnssec(zone).dnskey_ttl = 3
slave.dnssec(zone).zsk_lifetime = 16 # enough to signing of the zone be faster than this
slave.dnssec(zone).propagation_delay = 3

slave.dnssec(zone).manual = MANUAL

if slave.dnssec(zone).manual:
    # generate initial keys
    slave.gen_confile()
    KSK_INIT = slave.key_gen(ZONE, ksk="true", created="+0", publish="+0", active="+0")
    ZSK_INIT = slave.key_gen(ZONE, ksk="false", created="+0", publish="+0", active="+0")

t.start()
serial = slave.zone_wait(zone)

if slave.dnssec(zone).manual:
    slave.key_gen(ZONE, ksk="false", created="+0", publish="+3", active="+9")
    slave.key_set(ZONE, ZSK_INIT, retire="+9")
    slave.ctl("zone-keys-load")

serial = slave.zone_wait(zone, serial) # wait for new ZSK publish

slave.ctl("zone-freeze")

# queue incremental re-sign (within IXFR) after thaw
up = master.update(zone)
up.add("additional."+ZONE, 3600, "AAAA", "1::2")
up.send()

# ZSK rollover queues itself

t.sleep(6) # prop-delay + dnskey-ttl
slave.ctl("zone-thaw")

slave.zone_wait(zone, serial)

if not FAIL2ROLL:
    slave.zone_wait(zone, serial + 1)

slave.ctl("-f zone-flush")

# wait for zonefile flush
for i in range(60):
    t.sleep(1)
    try:
        if slave.zones[ZONE].zfile.get_soa_serial() == serial:
            break
    except:
        pass

slave.zone_verify(zone)

t.end()
