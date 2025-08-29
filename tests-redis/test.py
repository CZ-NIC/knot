from math import floor
from RLTest import Env


def txn_get_instance(txn : int) -> int:
    return floor(txn / 10)

def test_zone_begin():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    # basic transaction
    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.assertEqual(txn, 10, message="Wrong transaction number")

    resp = env.cmd('KNOT.ZONE.ABORT', 'example.com', txn)
    env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

    # multiple zones
    txn1 = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.assertEqual(txn1, 10, message="Wrong transaction number")

    txn2 = env.cmd('KNOT.ZONE.BEGIN', 'example.net', 1)
    env.assertEqual(txn2, 10, message="Wrong transaction number")

    resp = env.cmd('KNOT.ZONE.ABORT', 'example.com', txn1)
    env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

    resp = env.cmd('KNOT.ZONE.ABORT', 'example.net', txn2)
    env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

    # multiple transactions
    for i in range(9):
        txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
        env.assertEqual(txn, 10 + i, message="Wrong transaction number")

    with env.assertResponseError(msg="Should not allow so much transactions"):
        env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)

    for i in range(9):
        env.cmd('KNOT.ZONE.ABORT', 'example.com', 10 + i)
        env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

    # multiple instances
    for i in range(1, 9):
        txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', i)
        env.assertEqual(txn, i * 10, message="Wrong transaction number")

    with env.assertResponseError(msg="Should not allow so much instances"):
        txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 9)

    for i in range(1, 9):
        resp = env.cmd('KNOT.ZONE.ABORT', 'example.com', i * 10)
        env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

def test_zone_store():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    # basic
    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)

    resp = env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.assertEqual(resp, b'OK', message="Fail while store SOA")

    resp = env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "dns1.example.com. IN A 1.1.1.1")
    env.assertEqual(resp, b'OK', message="Fail while store A")

    resp = env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "dns2 IN A 1.1.1.1")
    env.assertEqual(resp, b'OK', message="Fail while store implicit A")

    resp = env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "dns3 123 IN A 1.1.1.1")
    env.assertEqual(resp, b'OK', message="Fail while store TTL")

    resp = env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "dns4 A 1.1.1.1")
    env.assertEqual(resp, b'OK', message="Fail while store without class")

    resp = env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "mail MX 10 dns1.example.com.")
    env.assertEqual(resp, b'OK', message="Fail while store MX")

    ZONE1=[[b'example.com.', b'3600', b'SOA', b'ns.icann.org. noc.dns.icann.org. 1 7200 3600 1209600 3600'], [b'dns1.example.com.', b'3600', b'A', b'1.1.1.1'], [b'dns2.example.com.', b'3600', b'A', b'1.1.1.1'], [b'dns3.example.com.', b'123', b'A', b'1.1.1.1'], [b'dns4.example.com.', b'3600', b'A', b'1.1.1.1'], [b'mail.example.com.', b'3600', b'MX', b'10 dns1.example.com.']]
    resp = env.cmd('KNOT.ZONE.LOAD', 'example.com', txn)
    env.assertEqual(resp, ZONE1, message="Basic store")

    # multiple transactions
    txn1 = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 2)

    resp = env.cmd('KNOT.ZONE.STORE', 'example.com', txn1, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.assertEqual(resp, b'OK', message="Fail while store")

    ZONE2=[[b'example.com.', b'3600', b'SOA', b'ns.icann.org. noc.dns.icann.org. 1 7200 3600 1209600 3600']]
    resp = env.cmd('KNOT.ZONE.LOAD', 'example.com', txn1)
    env.assertEqual(resp, ZONE2, message="Mixed zones")

    env.cmd('KNOT.ZONE.ABORT', 'example.com', txn)
    env.cmd('KNOT.ZONE.ABORT', 'example.com', txn1)

def test_zone_commit():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    # without SOA
    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    with env.assertResponseError(msg="Should not commit zone without SOA"):
        env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn)

    # with SOA
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    resp = env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit")

    # multiple SOA
    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "dns1.example.com. IN SOA ns.icann.org. noc.dns.icann.org. ( 2 7200  3600 1209600 3600 )")
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 3 7200  3600 1209600 3600 )")

    resp = env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit")

    resp = env.cmd('KNOT_BIN.ZONE.EXISTS', '\aexample\x03com\x00', '\x01')
    env.assertEqual(resp, 3, message="Failed to commit")

    # new transaction with active zone
    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")

    txn1 = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.assertEqual(txn1, 12, message="Wrong implicit instance transaction number")
    resp = env.cmd('KNOT.ZONE.ABORT', 'example.com', txn)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn1, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 3 7200  3600 1209600 3600 )")

    old_zone = env.cmd('KNOT.ZONE.LOAD', 'example.com', 1)

    resp = env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn1)
    env.assertEqual(resp, b'OK', message="Failed to commit")

    new_zone =env.cmd('KNOT.ZONE.LOAD', 'example.com', 1)
    env.assertNotEqual(old_zone, new_zone)


def test_zone_abort():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    # basic
    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    resp = env.cmd('KNOT.ZONE.ABORT', 'example.com', txn)
    env.assertEqual(resp, b'OK', message="Failed to abort")
    with env.assertResponseError(msg="Should not be available after abort"):
        env.cmd('KNOT.ZONE.LOAD', 'example.com', txn)

    # after abort
    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")

    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn)
    with env.assertResponseError(msg="Should not be able to abort commited zone"):
        env.cmd('KNOT.ZONE.ABORT', 'example.com', txn)

def test_zone_load():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")

    ZONE = [[b'example.com.', b'3600', b'SOA', b'ns.icann.org. noc.dns.icann.org. 1 7200 3600 1209600 3600']]

    # load uncommited
    zone_txn = env.cmd('KNOT.ZONE.LOAD', 'example.com', txn)
    env.assertEqual(zone_txn, ZONE, message="Zone is not equals to template")

    # load commited
    env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn)
    resp = env.cmd('KNOT.ZONE.LOAD', 'example.com', txn_get_instance(txn))
    env.assertEqual(resp, ZONE, message="Zone is not equals to template")
    env.assertEqual(resp, zone_txn, message="Zones from transaction and instance does not equals")

def test_zone_purge():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn)

    txn1 = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn1, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")

    txn2 = env.cmd('KNOT.UPD.BEGIN', 'example.com', 1)
    txn3 = env.cmd('KNOT.UPD.BEGIN', 'example.com', 1)

    env.cmd('KNOT.UPD.ADD', 'example.com', txn2, "dns IN A 1.1.1.1")
    env.cmd('KNOT.UPD.COMMIT','example.com', txn2)

    env.cmd('KNOT.UPD.ADD', 'example.com', txn3, "dns IN A 2.2.2.2")

    # basic
    resp = env.cmd('KNOT.ZONE.PURGE', 'example.com', txn_get_instance(txn))
    env.assertEqual(resp, b'OK', message="Failed to purge zone")

    with env.assertResponseError(msg="Zone has not been purged"):
        env.cmd('KNOT.ZONE.LOAD', 'example.com', txn_get_instance(txn))
    with env.assertResponseError(msg="Zone has not been purged"):
        env.cmd('KNOT.ZONE.LOAD', 'example.com', txn)
    with env.assertResponseError(msg="Update has not been purged"):
        env.cmd('KNOT.UPD.DIFF', 'example.com', txn2)

    # test whether uncommitted update transaction remains available before commit
    with env.assertResponseError(msg="Zone should not be available anymore"):
        env.cmd('KNOT.UPD.COMMIT','example.com', txn3)

    # test whether uncommitted zone transaction remains available
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn1, "dns IN A 1.1.1.1")
    resp = env.cmd('KNOT.ZONE.COMMIT','example.com', txn1)
    ZONE = [[b'example.com.', b'3600', b'SOA', b'ns.icann.org. noc.dns.icann.org. 1 7200 3600 1209600 3600'], [b'dns.example.com.', b'3600', b'A', b'1.1.1.1']]
    env.assertEqual(resp, b'OK', message="Failed to commit after purge")
    resp = env.cmd('KNOT.ZONE.LOAD', 'example.com', txn_get_instance(txn1))
    env.assertEqual(resp, ZONE, message="Zone does not equals template")

    # test whether uncommitted update transaction remains available after commit
    resp = env.cmd('KNOT.UPD.COMMIT','example.com', txn3)
    env.assertEqual(resp, b'OK', message="Failed to commit update")

def test_zone_list():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    # First zone
    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn)

    resp = env.cmd('KNOT.ZONE.LIST', txn_get_instance(txn))
    env.assertEqual(len(resp), 1, message="Failed to purge zone")

    # Rewrite zone
    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn)

    resp = env.cmd('KNOT.ZONE.LIST', txn_get_instance(txn))
    env.assertEqual(len(resp), 1, message="Failed to purge zone")

    # Second zone
    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.net', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.net', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.cmd('KNOT.ZONE.COMMIT', 'example.net', txn)

    resp = env.cmd('KNOT.ZONE.LIST', txn_get_instance(txn))
    env.assertEqual(len(resp), 2, message="Failed to purge zone")

def test_upd_begin():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    # missing zone
    with env.assertResponseError(msg="Update on non-existent zone"):
        env.cmd('KNOT.UPD.BEGIN', 'example.com', 1)

    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn)

    # missing zone at instance
    with env.assertResponseError(msg="Update on non-existent zone"):
        env.cmd('KNOT.UPD.BEGIN', 'example.com', 2)

    # basic
    txn = env.cmd('KNOT.UPD.BEGIN', 'example.com', 1)
    env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")
    env.cmd('KNOT.UPD.COMMIT', 'example.com', txn)

    # multiple transactions
    for i in range(0, 9):
        txn = env.cmd('KNOT.UPD.BEGIN', 'example.com', 1)
        env.assertEqual(txn, 10 + i, message="Wrong transaction number")

    for i in range(0, 9):
        env.cmd('KNOT.UPD.ABORT', 'example.com', 10 + i)

def test_upd_add_rem():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "dns IN A 1.1.1.1")
    env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn)

    # add/remove nonexistent transaction
    with env.assertResponseError(msg="Should not add to nonexistent transaction"):
        env.cmd('KNOT.UPD.ADD', 'example.com', txn, "dns 600 IN A 2.2.2.2")
    with env.assertResponseError(msg="Should not add to nonexistent transaction"):
        env.cmd('KNOT.UPD.REMOVE', 'example.com', txn, "dns 600 IN A 2.2.2.2")

    # basic
    txn = env.cmd('KNOT.UPD.BEGIN', 'example.com', 1)
    resp = env.cmd('KNOT.UPD.ADD', 'example.com', txn, "dns 600 IN A 2.2.2.2")
    env.assertEqual(resp, b'OK', message="Failed to add record into update")

    resp = env.cmd('KNOT.UPD.REMOVE', 'example.com', txn, "dns IN A 1.1.1.1")
    env.assertEqual(resp, b'OK', message="Failed to remove record from update")

    UPD = [[
        [[b'dns.example.com.', b'NONE', b'A', b'1.1.1.1']],
        [[b'dns.example.com.', b'600', b'A', b'2.2.2.2']]
    ]]

    resp = env.cmd('KNOT.UPD.DIFF', 'example.com', txn)
    env.assertEqual(resp, UPD, message="Wrong update output")

    resp = env.cmd('KNOT.UPD.COMMIT', 'example.com', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit update")

    ZONE = [
        [b'example.com.', b'3600', b'SOA', b'ns.icann.org. noc.dns.icann.org. 2 7200 3600 1209600 3600'],
        [b'dns.example.com.', b'600', b'A', b'2.2.2.2']
    ]
    resp = env.cmd('KNOT.ZONE.LOAD', 'example.com', 1)
    env.assertEqual(resp, ZONE, message="Wrong update output")

def test_upd_commit():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "dns IN A 1.1.1.1")
    env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn)

    # commit non-existent
    txn = env.cmd('KNOT.UPD.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.PURGE', 'example.com', 1)
    with env.assertResponseError(msg="Should not commit, zone doesn't exists"):
        env.cmd('KNOT.UPD.COMMIT', 'example.com', txn)

    txn1 = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn1, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn1)

    # basic add
    resp = env.cmd('KNOT.UPD.ADD', 'example.com', txn, "example IN A 1.1.1.1")
    env.assertEqual(resp, b'OK', message="Failed to add record into update")
    resp = env.cmd('KNOT.UPD.COMMIT', 'example.com', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit update")

    # basic remove
    txn = env.cmd('KNOT.UPD.BEGIN', 'example.com', 1)
    resp = env.cmd('KNOT.UPD.REMOVE', 'example.com', txn, "example IN A 1.1.1.1")
    env.assertEqual(resp, b'OK', message="Failed to add record into update")
    resp = env.cmd('KNOT.UPD.COMMIT', 'example.com', txn)
    env.assertEqual(resp, b'OK', message="Failed to commit update")

def test_upd_abort():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "dns IN A 1.1.1.1")
    env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn)

    old_zone = env.cmd('KNOT.ZONE.LOAD', 'example.com', txn)

    txn = env.cmd('KNOT.UPD.BEGIN', 'example.com', 1)
    env.cmd('KNOT.UPD.ADD', 'example.com', txn, "dns 600 IN A 2.2.2.2")
    resp = env.cmd('KNOT.UPD.ABORT', 'example.com', txn)
    env.assertEqual(resp, b'OK', message="Failed to abort update")

    with env.assertResponseError(msg="Should be aborted"):
        env.cmd('KNOT.UPD.DIFF', 'example.com', txn)
    resp = env.cmd('KNOT.ZONE.LOAD', 'example.com', txn)
    env.assertEqual(resp, old_zone, message="Zone should not be changed after abort of update")

def test_upd_diff_load():
    env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

    txn = env.cmd('KNOT.ZONE.BEGIN', 'example.com', 1)
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
    env.cmd('KNOT.ZONE.STORE', 'example.com', txn, "dns IN A 1.1.1.1")
    env.cmd('KNOT.ZONE.COMMIT', 'example.com', txn)

    txn = env.cmd('KNOT.UPD.BEGIN', 'example.com', 1)
    env.cmd('KNOT.UPD.ADD', 'example.com', txn, "dns IN A 2.2.2.2")
    resp = env.cmd('KNOT.UPD.DIFF', 'example.com', txn)
    env.cmd('KNOT.UPD.COMMIT', 'example.com', txn)

    with env.assertResponseError(msg="Should be commited"):
        env.cmd('KNOT.UPD.DIFF', 'example.com', txn)

    UPD = [[], [[b'dns.example.com.', b'3600', b'A', b'2.2.2.2']]]
    env.assertEqual([UPD], resp, message="Update doesn't match template")

    TRANSFER = [
        [
            [
                [[b'example.com.', b'3600', b'SOA', b'ns.icann.org. noc.dns.icann.org. 1 7200 3600 1209600 3600']],
                [[b'example.com.', b'3600', b'SOA', b'ns.icann.org. noc.dns.icann.org. 2 7200 3600 1209600 3600']]
            ], UPD
        ]
    ]

    resp = env.cmd('KNOT.UPD.LOAD', 'example.com', 1, 1)
    env.assertEqual(resp, TRANSFER, message="Wrong update output")
