from RLTest import Env

def test_begin():
	env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

	# implicit instance
	txn = env.cmd('KNOT.ZONE.BEGIN', 'nu')
	env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")
	resp = env.cmd('KNOT.ZONE.ABORT', 'nu', txn)
	# TODO assertOK dont work, because of format (b'OK' vs 'OK')
	# env.assertOk(resp, message="Fail while aborting transaction")
	env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

	# explicit instance
	txn = env.cmd('KNOT.ZONE.BEGIN', 'nu', '2')
	env.assertEqual(txn, 20, message="Wrong transaction number")
	resp = env.cmd('KNOT.ZONE.ABORT', 'nu', txn)
	env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

def test_store():
	env = Env(moduleArgs=['max-event-age', '60', 'default-ttl', '3600'])

	# implicit instance
	txn = env.cmd('KNOT.ZONE.BEGIN', 'nu')
	env.assertEqual(txn, 10, message="Wrong implicit instance transaction number")
	resp = env.cmd('KNOT.ZONE.STORE', 'nu', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )")
	env.assertEqual(resp, b'OK', message="Fail while aborting transaction")
	resp = env.cmd('KNOT.ZONE.ABORT', 'nu', 10)
	# TODO assertOK dont work, because of format (b'OK' vs 'OK')
	# env.assertOk(resp, message="Fail while aborting transaction")
	env.assertEqual(resp, b'OK', message="Fail while aborting transaction")

	# explicit instance
	resp = env.cmd('KNOT.ZONE.BEGIN', 'nu', '2')
	env.assertEqual(resp, 20, message="Wrong transaction number")


# def test_example_2():
# 	env = Env()
# 	env.assertOk(env.cmd('set', 'x', '1'))
# 	env.expect('get', 'x').equal('1')

# 	env.expect('lpush', 'list', '1', '2', '3').equal(3)
# 	env.expect('lrange', 'list', '0', '-1').debugPrint().contains('1')
# 	env.debugPrint('this is some debug printing')


# def test_example_3():
# 	env = Env(useSlaves=True, env='oss')
# 	con = env.getConnection()
# 	con.set('x', 1)
# 	con2 = env.getSlaveConnection()
# 	time.sleep(0.1)
# 	env.assertEqual(con2.get('x'), '1')