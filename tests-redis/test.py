#!/usr/bin/env python3

import sys

# NOTE that ConfigParser was renamed to configparser, need to force libraries to try load configparser first
try:
	# Try to import new name
	import configparser
	sys.modules['ConfigParser'] = configparser # Map the old name to the new module
except ImportError:
	# Try to import old name
	try:
		import ConfigParser
	except ImportError:
		print("Error: Neither 'configparser' nor 'ConfigParser' could be imported.")
		print("Please ensure you have the correct ConfigParser/configparser library for your Python version.")
		sys.exit(1)

import unittest
from enum import IntEnum
from rmtest import ModuleTestCase

DEFAULT_TTL=b'3600'

class Idx(IntEnum):
	OWNER  = 0
	TTL    = 1
	RTYPE  = 2
	RECORD = 3

def get_serial_txt(input : str) -> int | None:
	try:
		return int(input.split()[2])
	except:
		return None

class KnotModuleTestCase(ModuleTestCase('/home/jhak/Work/knot-dns/build/lib/knot/redis/knot.so', module_args=('max-event-age', '60', 'default-ttl', DEFAULT_TTL))):
			
	def testZoneStoreTxtBasic(self):
		INSTANCE=1
		txn = self.cmd('KNOT.ZONE.BEGIN', 'nu', INSTANCE)
		self.assertOk(self.cmd('KNOT.ZONE.STORE', 'nu', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )"))
		self.assertOk(self.cmd('KNOT.ZONE.COMMIT', 'nu', txn))

		resp = self.cmd('KNOT.ZONE.LOAD', 'nu', INSTANCE)
		self.assertEqual(len(resp), 1, "Wrong number of records")

		soa = resp[0]
		self.assertEqual(soa[Idx.OWNER],  b'nu.')
		self.assertEqual(soa[Idx.TTL],    DEFAULT_TTL)
		self.assertEqual(soa[Idx.RTYPE],  b'SOA')

		soa_serial = get_serial_txt(soa[Idx.RECORD])
		self.assertEqual(soa_serial, 1)

	def testZoneUpdateTxtBasic(self):
		INSTANCE=2
		txn = self.cmd('KNOT.ZONE.BEGIN', 'nu', INSTANCE)
		self.assertOk(self.cmd('KNOT.ZONE.STORE', 'nu', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )"))
		self.assertOk(self.cmd('KNOT.ZONE.COMMIT', 'nu', txn))

		txn = self.cmd('KNOT.UPD.BEGIN', 'nu', INSTANCE)
		self.assertOk(self.cmd('KNOT.UPD.ADD', 'nu', txn, "example 1234 IN A 1.1.1.1"))
		self.assertOk(self.cmd('KNOT.UPD.COMMIT', 'nu', txn))

		resp = self.cmd('KNOT.ZONE.LOAD', 'nu', INSTANCE)
		self.assertEqual(len(resp), 2, "Wrong number of records")

		soa = resp[0]
		self.assertEqual(soa[Idx.OWNER],  b'nu.')
		self.assertEqual(soa[Idx.TTL],    DEFAULT_TTL)
		self.assertEqual(soa[Idx.RTYPE],  b'SOA')
		soa_serial = get_serial_txt(soa[Idx.RECORD])
		self.assertEqual(soa_serial, 2)

		a = resp[1]
		self.assertEqual(a[Idx.OWNER],  b'example.nu.')
		self.assertEqual(a[Idx.TTL],    DEFAULT_TTL)
		self.assertEqual(a[Idx.RTYPE],  b'A')
		self.assertEqual(a[Idx.RECORD], b'1.1.1.1')



	def testZoneUpdateTxtSoa(self):
		INSTANCE=3
		txn = self.cmd('KNOT.ZONE.BEGIN', 'nu', INSTANCE)
		self.assertOk(self.cmd('KNOT.ZONE.STORE', 'nu', txn, "@ IN SOA ns.icann.org. noc.dns.icann.org. ( 1 7200  3600 1209600 3600 )"))
		self.assertOk(self.cmd('KNOT.ZONE.COMMIT', 'nu', txn))

		txn = self.cmd('KNOT.UPD.BEGIN', 'nu', INSTANCE)
		self.assertOk(self.cmd('KNOT.UPD.ADD', 'nu', txn, "example 1234 IN A 1.1.1.1"))
		self.assertOk(self.cmd('KNOT.UPD.COMMIT', 'nu', txn))

		resp = self.cmd('KNOT.ZONE.LOAD', 'nu', INSTANCE)
		self.assertEqual(len(resp), 2)
if __name__ == '__main__':
	unittest.main()      