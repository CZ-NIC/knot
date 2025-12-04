#!/usr/bin/env python3

'''Test of chained catalog interpreter and generator.'''

from dnstest.utils import *
from dnstest.test import Test
import glob
import random
import shutil

t = Test(stress=False)

master = t.server("knot")
slave = t.server("knot")

os.mkdir(slave.dir + "/catalog")
for zf in glob.glob(t.data_dir + "/*.zone"):
    shutil.copy(zf, slave.dir + "/catalog")

catz = t.zone("example.") + t.zone("example.com.")

t.link([ catz[0] ], master)
t.link([ catz[1] ], master, slave)

for z in master.zones.values():
    z.zfile.append_rndTXT("version", rdata="2")

master.cat_interpret(catz[0])
master.cat_generate(catz[1])
slave.cat_interpret(catz[1])

t.start()

# set master to generate catalog into catz[1] from members of catz[0]
confsock = master.ctl_sock_rnd()
master.ctl("conf-begin", custom_parm=confsock)
master.ctl("conf-set template[catalog-default].catalog-role member", custom_parm=confsock)
master.ctl("conf-set template[catalog-default].catalog-zone %s" % catz[1].name, custom_parm=confsock)
master.ctl("conf-commit", custom_parm=confsock)

# add first member
up = master.update(catz[0])
up.add("uniq1.zones", 3600, "PTR", "cataloged1.")
up.send()
t.sleep(4)
resp = slave.dig("cataloged1.", "NS")
resp.check(rcode="NOERROR", rdata="ns.cataloged1.")

# add second member
up = master.update(catz[0])
up.add("uniq2.zones", 3600, "PTR", "cataloged2.")
up.send()
t.sleep(4)
resp = slave.dig("cataloged2.", "NS")
resp.check(rcode="NOERROR", rdata="ns.cataloged2.")

# remove first member
up = master.update(catz[0])
up.delete("uniq1.zones", "PTR")
up.send()
t.sleep(4)
resp = slave.dig("cataloged1.", "NS")
resp.check(rcode="REFUSED", nordata="ns.cataloged1.")
resp = slave.dig("cataloged2.", "NS")
resp.check(rcode="NOERROR", rdata="ns.cataloged2.")
resp = master.dig("cataloged2.", "NS")
resp.check(rcode="SERVFAIL")

t.end()
