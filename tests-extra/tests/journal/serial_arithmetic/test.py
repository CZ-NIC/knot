#!/usr/bin/env python3

'''Test for serial number arithmetics'''

import os
from dnstest.test import Test

TEMPL = """$ORIGIN %s
$TTL 3600

@    SOA   dns1 hostmaster %d 10800 3600 1209600 7200
     NS    dns1
     NS    dns2
     MX    10 mail

dns1 A     192.0.2.1
     AAAA  2001:DB8::1

dns2 A     192.0.2.2
     AAAA  2001:DB8::2

mail A     192.0.2.3
     AAAA  2001:DB8::3

new  A     1.1.1.%d"""

SERIALS = {
    "z1.": [0, 1, 2147483648, 4294967295, 0],
    "z2.": [0, 1, 2147483648, 4294967295, 1],
    "z3.": [0, 1, 2147483648, 4294967295, 2]
}

t = Test()

master = t.server("knot")
refer = t.server("bind")
zones = [t.zone(z, storage=t.zones_dir, exists=False)[0] for z in SERIALS]

for dname in SERIALS:
    sequence = SERIALS[dname]
    for index, serial in enumerate(sequence):
        fn = "%szone" % dname if index == 0 else "%szone.%d" % (dname, index)
        with open(os.path.join(t.zones_dir, fn), "w") as f:
            f.write(TEMPL % (dname, serial, index))

t.link(zones, master, ixfr=True)
t.link(zones, refer, ixfr=True)

t.start()

master.zones_wait(zones)
refer.zones_wait(zones)
t.xfr_diff(master, refer, zones)

for i in range(1, 5):
    # Update zone files.
    for zone in zones:
        master.update_zonefile(zone, version=i, storage=t.zones_dir)
        refer.update_zonefile(zone, version=i, storage=t.zones_dir)
    master.reload()
    refer.reload()

    previous = dict()

    for zone in zones:
        master.zone_wait(zone, SERIALS[zone.name][i], equal=True, greater=False)
        refer.zone_wait(zone, SERIALS[zone.name][i], equal=True, greater=False)
        previous[zone.name] = SERIALS[zone.name][i - 1]

    t.xfr_diff(master, refer, zones)
    if i < 4: # Dnspython fails for i = 4.
        # Compare last IXFR changeset.
        t.xfr_diff(master, refer, zones, serials=previous)
t.end()
