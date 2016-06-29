#!/usr/bin/env python3

'''Randomized test for DDNS NSEC(3) chain fix'''

import random
from string import digits, ascii_uppercase, ascii_lowercase

from dnstest.utils import *
from dnstest.test import Test

################################ SETUP #######################################

MAX_LABELS = 15
MAX_UPDATE_SIZE = 256

RUNS = 1

############################### HELPERS ######################################

DNAME_ALLOWED = ascii_uppercase + ascii_lowercase + digits

def gen_dname(origin):
    name = ""
    label_count = random.randint(1, MAX_LABELS)
    label_lengths = []
    for i in range(label_count):
        label_lengths.append(random.randint(1, 15))
    for l in label_lengths:
        for i in range(l):
            name += random.choice(DNAME_ALLOWED)
        name += "."
    name += origin
    if (len(name) <= 255):
        return name
    else:
        return origin

names = []

def add_rand_name(up, zone, version):
    name = gen_dname(zone[0].name)
    names.append(name)
    up.add(name, 3600, "TXT", "generated_v" + str(version))

def remove_added_name(up):
    name = random.choice(names)
    up.delete(name, "TXT")

def modify_added_name(up):
    name = random.choice(names)
    up.add(name, 3600, "SPF", "text")

def verify(master, zone):
    t.sleep(3)
    master.flush()
    t.sleep(3)
    master.zone_verify(zone)

def test_run(master, zone, msg):
    names = []
    for i in range(RUNS):
        check_log(msg + " Run " + str(i + 1) + " of " + str(RUNS))

        # add records
        check_log(msg + " Additions")
        update = master.update(zone)
        add_count = random.randint(1, MAX_UPDATE_SIZE)
        for j in range(add_count):
            add_rand_name(update, zone, i)
        update.send("NOERROR")
        verify(master, zone)

        # remove some of previously added records
        check_log(msg + " Removals")
        update = master.update(zone)
        remove_count = random.randint(1, int(add_count / 2) + 1)
        for j in range(remove_count):
            remove_added_name(update)
        update.send("NOERROR")
        verify(master, zone)

        # modify existing names
        check_log(msg + " Modifications")
        update = master.update(zone)
        mod_count = random.randint(1, int(add_count / 2) + 1)
        for j in range(mod_count):
            modify_added_name(update)
        update.send("NOERROR")
        verify(master, zone)

        # add and remove records
        check_log(msg + " Add / Remove mix")
        update = master.update(zone)
        for j in range(mod_count):
            add_rand_name(update, zone, i)
            remove_added_name(update)
        update.send("NOERROR")
        verify(master, zone)

############################## TEST START #####################################

random.seed()

t = Test()

zone = t.zone_rnd(1, dnssec=False)
master = t.server("knot")
t.link(zone, master, ddns=True)

master.dnssec(zone).enable = True
master.gen_confile()

t.start()
master.zone_wait(zone)

# Test NSEC fix
check_log("============ NSEC test ============")
test_run(master, zone, "NSEC")

master.dnssec(zone).nsec3 = True
master.reload()
t.sleep(2)

# Test NSEC3 fix
check_log("============ NSEC3 test ===========")
test_run(master, zone, "NSEC3")

t.end()
