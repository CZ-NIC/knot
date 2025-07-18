from RLTest import Env

def test_zone_begin():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    txn = env.cmd('KNOT.ZONE.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong transaction number")

    resp = env.cmd('KNOT.ZONE.ABORT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

    # multiple transactions
    for i in range(0, 9):
        txn = env.cmd('KNOT.ZONE.BEGIN', 'nu', 1)
        env.assertEqual(txn, 10 + i, message="Wrong transaction number")

    for i in range(0, 9):
        resp = env.cmd('KNOT.ZONE.ABORT', 'nu', 10 + i)
        env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

def test_zone_commit():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    # non-existent SOA
    txn = env.cmd('KNOT.ZONE.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong transaction number")

    with env.assertResponseError(msg="Should not commit zone without SOA"):
        env.cmd('KNOT.ZONE.COMMIT', 'nu', txn)

    # with SOA
    resp = env.cmd('KNOT.ZONE.STORE', 'nu', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.assertEqual(resp, b'OK', message="Failed to store SOA")

    resp = env.cmd('KNOT.ZONE.COMMIT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit")

    # new transaction with active zone
    txn = env.cmd('KNOT.ZONE.BEGIN', 'nu', 1)
    env.assertEqual(txn, 11, message="Wrong implicit instance transaction number")

    resp = env.cmd('KNOT.ZONE.ABORT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

def test_zone_load():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    txn = env.cmd('KNOT.ZONE.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")

    resp = env.cmd('KNOT.ZONE.STORE', 'nu', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.assertEqual(resp, b'OK', message="Failed to store SOA")

    ZONE = [[b'nu.', b'3600', b'SOA', b'ns.icann.org. noc.dns.icann.org. 1 7200 3600 1209600 3600']]

    # load uncommited
    resp = env.cmd('KNOT.ZONE.LOAD', 'nu', txn)
    env.assertEqual(resp, ZONE, message="Failed to store SOA")

    # load commited
    resp = env.cmd('KNOT.ZONE.COMMIT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit")

    resp = env.cmd('KNOT.ZONE.LOAD', 'nu', 1)
    env.assertEqual(resp, ZONE, message="Failed to store SOA")

def test_zone_purge():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    txn = env.cmd('KNOT.ZONE.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")

    resp = env.cmd('KNOT.ZONE.STORE', 'nu', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.assertEqual(resp, b'OK', message="Failed to store SOA")

    resp = env.cmd('KNOT.ZONE.COMMIT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit")

    txn = env.cmd('KNOT.UPD.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")

    resp = env.cmd('KNOT.UPD.ADD', 'nu', txn, "example IN A 1.1.1.1")
    env.assertEqual(resp, b'OK', message="Failed to add record into update")

    resp = env.cmd('KNOT.UPD.COMMIT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit update")

    resp = env.cmd('KNOT.ZONE.PURGE', 'nu', 1)
    env.assertEqual(resp, b'OK', message="Failed to purge zone")

    with env.assertResponseError(msg="Zone has not been purged"):
        env.cmd('KNOT.ZONE.LOAD', 'nu', txn)

def test_upd_begin():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    # implicit instance
    txn = env.cmd('KNOT.UPD.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")

    resp = env.cmd('KNOT.UPD.ABORT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

    # explicit instance
    txn = env.cmd('KNOT.UPD.BEGIN', 'nu', 2)
    env.assertEqual(txn, 20, message="Wrong transaction number")

    resp = env.cmd('KNOT.UPD.ABORT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

    # multiple transactions
    for i in range(0, 9):
        txn = env.cmd('KNOT.UPD.BEGIN', 'nu', 2)
        env.assertEqual(txn, 20 + i, message="Wrong transaction number")

    for i in range(0, 9):
        resp = env.cmd('KNOT.UPD.ABORT', 'nu', 20 + i)
        env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

def test_upd_add_rem():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    txn = env.cmd('KNOT.ZONE.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")
    resp = env.cmd('KNOT.ZONE.STORE', 'nu', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.assertEqual(resp, b'OK', message="Failed to store SOA")
    resp = env.cmd('KNOT.ZONE.STORE', 'nu', txn, "example IN A 1.1.1.1")
    env.assertEqual(resp, b'OK', message="Failed to store A")
    resp = env.cmd('KNOT.ZONE.COMMIT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit")

    txn = env.cmd('KNOT.UPD.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")

    resp = env.cmd('KNOT.UPD.ADD', 'nu', txn, "example 600 IN A 2.2.2.2")
    env.assertEqual(resp, b'OK', message="Failed to add record into update")

    resp = env.cmd('KNOT.UPD.REMOVE', 'nu', txn, "example IN A 1.1.1.1")
    env.assertEqual(resp, b'OK', message="Failed to remove record from update")

    UPD = [[
        [[b'example.nu.', b'NONE', b'A', b'1.1.1.1']],
        [[b'example.nu.', b'600', b'A', b'2.2.2.2']]
    ]]

    resp = env.cmd('KNOT.UPD.DIFF', 'nu', txn)
    env.assertEqual(resp, UPD, message="Wrong update output")

    resp = env.cmd('KNOT.UPD.COMMIT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit update")

    ZONE = [
        [b'nu.', b'3600', b'SOA', b'ns.icann.org. noc.dns.icann.org. 2 7200 3600 1209600 3600'],
        [b'example.nu.', b'600', b'A', b'2.2.2.2']
    ]
    resp = env.cmd('KNOT.ZONE.LOAD', 'nu', 1)
    env.assertEqual(resp, ZONE, message="Wrong update output")

def test_upd_commit():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    txn = env.cmd('KNOT.UPD.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")

    with env.assertResponseError(msg="Should not commit, zone doesn't exists"):
        txn = env.cmd('KNOT.UPD.COMMIT', 'nu', txn)

    txn = env.cmd('KNOT.ZONE.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")

    resp = env.cmd('KNOT.ZONE.STORE', 'nu', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.assertEqual(resp, b'OK', message="Failed to store SOA")

    resp = env.cmd('KNOT.ZONE.COMMIT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit")

    resp = env.cmd('KNOT.UPD.ADD', 'nu', txn, "example IN A 1.1.1.1")
    env.assertEqual(resp, b'OK', message="Failed to add record into update")

    resp = env.cmd('KNOT.UPD.COMMIT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit update")

def test_upd_load():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    txn = env.cmd('KNOT.UPD.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")

    with env.assertResponseError(msg="Should not commit, zone doesn't exists"):
        txn = env.cmd('KNOT.UPD.COMMIT', 'nu', txn)

    resp = env.cmd('KNOT.UPD.ABORT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

    txn = env.cmd('KNOT.ZONE.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")

    resp = env.cmd('KNOT.ZONE.STORE', 'nu', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.assertEqual(resp, b'OK', message="Failed to store SOA")

    resp = env.cmd('KNOT.ZONE.COMMIT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit")

    txn = env.cmd('KNOT.UPD.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")

    resp = env.cmd('KNOT.UPD.ADD', 'nu', txn, "example IN A 1.1.1.1")
    env.assertEqual(resp, b'OK', message="Failed to add record into update")

    ZONE = [
        [b'nu.', b'3600', b'SOA', b'ns.icann.org. noc.dns.icann.org. 2 7200 3600 1209600 3600'],
        [b'example.nu.', b'3600', b'A', b'1.1.1.1']
    ]

    resp = env.cmd('KNOT.UPD.DIFF', 'nu', txn)
    env.assertEqual(resp, [[[], [ZONE[1]]]], message="Wrong update output")

    resp = env.cmd('KNOT.UPD.COMMIT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit update")

    resp = env.cmd('KNOT.ZONE.LOAD', 'nu', 1)
    env.assertEqual(resp, ZONE, message="Wrong update output")

    txn = env.cmd('KNOT.UPD.BEGIN', 'nu', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")

    resp = env.cmd('KNOT.UPD.ADD', 'nu', txn, "dns1 IN A 2.2.2.2")
    env.assertEqual(resp, b'OK', message="Failed to add record into update")

    resp = env.cmd('KNOT.UPD.COMMIT', 'nu', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit update")

    UPD = [[
        [
            [[b'nu.', b'0', b'SOA', b'ns.icann.org. noc.dns.icann.org. 1 7200 3600 1209600 3600']],
            [[b'nu.', b'3600', b'SOA', b'ns.icann.org. noc.dns.icann.org. 2 7200 3600 1209600 3600']]
        ], [
            [],
            [[b'example.nu.', b'3600', b'A', b'1.1.1.1']]
        ]
    ], [
        [
            [[b'nu.', b'0', b'SOA', b'ns.icann.org. noc.dns.icann.org. 2 7200 3600 1209600 3600']],
            [[b'nu.', b'3600', b'SOA', b'ns.icann.org. noc.dns.icann.org. 3 7200 3600 1209600 3600']]
        ], [
            [],
            [[b'dns1.nu.', b'3600', b'A', b'2.2.2.2']]
        ]
    ]]

    resp = env.cmd('KNOT.UPD.LOAD', 'nu', 1, 1)
    env.assertEqual(resp, UPD, message="Wrong update output")
