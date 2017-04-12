#!/usr/bin/env python
# vim: et ts=4 sw=4 sts=4
#
# Manipulate LMDB-beckended KASP database (import from obsolete JSON KASP, list, modify...).
#

import datetime
import time
import lmdb
import json
import sys
import re
import glob
import argparse
import time
import traceback
import os
import hashlib

opt_force = False

# workarounding that python 2 doesn't have int.to_bytes()
def to_bytes(n, length, endianess='big'):
	h = '%x' % n
	assert len(h) <= length * 2
	s = ('0'*(len(h) % 2) + h).zfill(length * 2).decode('hex')
	return bytearray(s) if endianess == 'big' else bytearray(s[::-1])

def from_bytes(ba, endianess='big'):
	x = ba if endianess == 'big' else bytearray(s[::-1])
	return int(str(x).encode('hex'), 16)

# aka knot_dname_from_str_alloc()
def str2dname(s):
	if s.endswith('.') is False:
		s += '.'
	res = bytearray("")
	nodes = s.lower().split('.')
	if nodes[-1] != "":
		nodes.append("")

	for node in nodes:
		res.append(len(node))
		res.extend(bytearray(node.lower()))

	return res

def dname2str(dn):
	res = ""
	beg = 0
	end = ord(dn[0]) + 1
	while ord(dn[beg]) > 0:
		res += str(dn[beg+1:end]) + "."
		beg = end
		end = beg + ord(dn[beg]) + 1

	return res

# this is just helper for shuffling time
def shuffle_unixtime(base_time, shuffle_years, shuffle_months):
	rsm = shuffle_months + 12 * shuffle_years
	dt = datetime.datetime.fromtimestamp(base_time)
	newmonth = (dt.month - 1 + rsm) % 12 + 1 # in python, % always returns [0, 11]
	sameyear = dt.month + rsm % 12
	newyear = dt.year + rsm / 12 + (0 if sameyear in range(1, 13) else 1) # in python, (-1)/12 = -1
	dt2 = dt.replace(month=newmonth, year=newyear)
	print dt2.month, "/", dt2.year
	ttuple = dt2.timetuple()
	return int(time.mktime(ttuple))

def timespec2unix(spec):
	if re.match(r"^\d+$", spec):
		return int(spec)

	now = int(time.time())
	s = re.sub(r"^now", "t", spec)
	if s == "t":
		return now

	unitmap = { "" : 1, "mi" : 60, "h" : 3600, "d" : 86400 }
	unitmap_mo = { "mo" : 1, "y" : 12 }

	if re.match(r"^t[-+]\d+", s):
		unit = re.sub(r"^t[-+]\d+", "", s)
		cutend = len(s) if unit == "" else -len(unit)
		if unit in unitmap.keys():
			return now + int(s[1:cutend]) * unitmap[unit]
		elif unit in unitmap_mo.keys():
			return shuffle_unixtime(now, 0, int(s[1:cutend]) * unitmap_mo[unit])
		else:
			print "Error in time unit specification"

	print "Error in time specification"	

class Keykey:
	'''Kasp DB key serialized (type, zone_name, key_id)'''

	def __init__(self, raw_bytearray):
		self.raw = bytearray(raw_bytearray)

	@classmethod
	def from_params(self, valtype, zone_name, key_id):
		selfraw = to_bytes(valtype, 1)
		if zone_name is not None:
			selfraw.extend(zone_name)
		if key_id is not None:
			selfraw.extend(bytearray(key_id.encode("ascii")))
			selfraw.append(0)
		return Keykey(selfraw)

	def getRaw(self):
		return bytearray(self.raw)

	def getType(self):
		return self.raw[0]

	def __getSplit(self):
		x = self.raw.find(to_bytes(0, 1))
		assert x > 0
		return x + 1

	def getZone(self):
		if self.getType() == 2:
			return None
		return str(self.raw[1:self.__getSplit()])

	def getKeyid(self):
		if self.getType() != 1:
			return None
		return str(self.raw[self.__getSplit():])

class Keyparams:
	'''Serialized key parameters for kasp-db.'''

	def __init__(self, raw_bytearray):
		self.raw = bytearray(raw_bytearray)
		self.timers_dict = { "created" : [ 0, 20, 28 ],
		                     "publish" : [ 1, 28, 36 ],
		                     "ready"   : [ 2, 36, 44 ],
		                     "active"  : [ 3, 44, 52 ],
		                     "retire"  : [ 4, 52, 60 ],
		                     "remove"  : [ 5, 60, 68 ] }

	@classmethod
	def from_params(self, pubkey, keytag, algorithm, isksk, timers):
		assert len(timers) == 6
		pk = pubkey.decode("base64")
		selfraw = to_bytes(len(pk), 8)
		selfraw.extend(to_bytes(0, 8)) # zero length of unused-future
		selfraw.extend(to_bytes(int(keytag), 2))
		selfraw.extend(to_bytes(int(algorithm), 1))
		selfraw.extend(to_bytes((1 if isksk else 0), 1))
		for t in timers:
			if t < 0:
				print "keytag=%i timers=(%i, %i, %i, %i, %i, %i)" % (keytag,
				timers[0], timers[1], timers[2], timers[3], timers[4], timers[5])
				assert False
			selfraw.extend(to_bytes(t, 8))
		selfraw.extend(pk)
		return Keyparams(selfraw)

	def _check(self):
		assert len(self.raw) >= 16
		pkl = from_bytes(self.raw[0:8])
		ufl = from_bytes(self.raw[8:16])
		assert len(self.raw) == 68 + pkl + ufl
		assert self.raw[19] < 2

	def getRaw(self):
		self._check()
		return bytearray(self.raw)

	def getAlgorithm(self):
		self._check()
		return int(self.raw[18])

	def setAlgorithm(self, algorithm):
		self._check()
		self.raw[18] = to_bytes(algorithm, 1)[0]

	def isKSK(self):
		self._check()
		return 1 if self.raw[19] != 0 else 0

	def setKSK(self, isksk):
		self._check()
		self.raw[11] = (b"\01" if isksk else b"\00")[0]

	def getKeytag(self):
		self._check()
		return from_bytes(self.raw[16:18])

	def setKeytag(self, keytag):
		self._check()
		self.raw[16:18] = to_bytes(keytag, 2)

	def getTimers(self):
		self._check()
		res = [ 0, 0, 0, 0, 0 ]
		for i, x, y in self.timers_dict.values():
			res[i] = from_bytes(self.raw[x:y])
		return res

	def getTimersString(self):
		self._check()
		res = "["
		for ti in self.timers_dict.keys():
			_, x, y = self.timers_dict[ti];
			res += (" " if res == "[" else ", ") + ti + ": " + str(from_bytes(self.raw[x:y]))
		return res + " ]"

	def setTimers(self, timers):
		self._check()
		assert len(timers) == 5
		for i, x, y in self.timers_dict.values():
			self.raw[x:y] = to_bytes(timers[i], 8)

	def getPubKey(self):
		self._check()
		pkl = from_bytes(self.raw[0:8])
		return self.raw[68:68+pkl].encode("base64")

	def getParams(self):
		return [ self.getPubKey(), self.getKeytag(), self.getAlgorithm(),
		         self.isKSK(), self.getTimers() ];

	def setByParamName(self, param_name, new_val):
		if param_name == "algorithm":
			self.setAlgorithm(int(new_val))
		elif param_name == "isksk":
			if new_val in ("1", "True", "true", "on", "yes", "Yes"):
				self.setKSK(True)
			elif new_val in ("0", "False", "false", "off", "no", "No"):
				self.setKSK(False)
			else:
				print "Error: bad true/false value", new_val
		elif param_name == "keytag":
			self.setKeytag(int(new_val))
		elif param_name in self.timers_dict.keys():
			_, x, y = self.timers_dict[param_name]
			self.raw[x:y] = to_bytes(timespec2unix(new_val), 8)
		else:
			print "Error: bad parameter", param_name

	def computeDS(self, zone_str, digestalg):
		ds_raw = bytearray(str2dname(zone_str))
		ds_raw.extend(to_bytes(257 if self.isKSK() else 256, 2))
		ds_raw.extend(b"\x03") # protocol is always == 3
		ds_raw.extend(self.raw[18:19]) # algorithm
		pkl = from_bytes(self.raw[0:8])
		ds_raw.extend(self.raw[68:68+pkl]) # pubkey
		if digestalg == "sha1":
			ds_hash = hashlib.sha1(ds_raw).hexdigest()
			algno = " 1 "
		elif digestalg == "sha256":
			ds_hash = hashlib.sha256(ds_raw).hexdigest()
			algno = " 2 "
		elif digestalg == "sha384":
			ds_hash = hashlib.sha384(ds_raw).hexdigest()
			algno = " 4 "
		else:
			print "Error: bad DS digest algorith", ds_hash
			return
		return zone_str + ' DS ' + str(self.getKeytag()) + ' ' + str(self.getAlgorithm()) + algno + ds_hash

	def isPublished(self, moment):
		tmrs = self.getTimers()
		if tmrs[self.timers_dict["publish"][0]] <= moment:
			if moment < tmrs[self.timers_dict["remove"][0]]:
				return True
		return False

	def isReady(self, moment):
		tmrs = self.getTimers()
		if tmrs[self.timers_dict["ready"][0]] <= moment:
			if moment < tmrs[self.timers_dict["ready"][0]]:
				return True
		return False

	def isActive(self, moment):
		tmrs = self.getTimers()
		if tmrs[self.timers_dict["active"][0]] <= moment:
			if moment < tmrs[self.timers_dict["retire"][0]]:
				return True
		return False

	def isRetired(self, moment):
		tmrs = self.getTimers()
		if tmrs[self.timers_dict["retire"][0]] <= moment:
			return True
		return False

# static: just for use in following method
def arr_ind2unix(arr, ind, defaul):
	try:
		ttuple = datetime.datetime.strptime(arr[ind], "%Y-%m-%dT%H:%M:%S+0000").timetuple()
		res = int(time.mktime(ttuple))
		return res if res >= 0 else 0
	except KeyError:
		return defaul

# import single JSON zone config into open LMDB env
def import_file(fname, env, db_keys):
	with open(fname) as f:
		keys = json.load(f)

	try:
		zname_str = re.sub(r'^zone_', '', re.sub(r'\.json$', '', re.sub(r'.*/', '', fname)))
		print "Importing zone", zname_str
		zname = str2dname(zname_str)

		try: # store nsec3salt
			with lmdb.Transaction(env, db_keys, write=True) as txn_keys:
				dbk1 = Keykey.from_params(3, zname, None).getRaw()
				dbv1 = keys["nsec3_salt"].decode("base64")
				txn_keys.put(dbk1, dbv1, dupdata=False, overwrite=True)
				dbk2 = Keykey.from_params(4, zname, None).getRaw()
				dbv2 = to_bytes(arr_ind2unix(keys, "nsec3_salt_created", 0), 8)
				txn_keys.put(dbk2, dbv2, dupdata=False, overwrite=True)
		except (KeyError, AttributeError):
			pass # nsec3salt not configured or set to null, no problem

		for key in keys["keys"]:
			dbk3 = Keykey.from_params(1, zname, key["id"]).getRaw()

			infty = 0x00ffffffffffff00 # time infinity, this is year 142'715'360

			dbv3 = Keyparams.from_params(key["public_key"], key["keytag"],
			                             key["algorithm"], key["ksk"], [
			                               arr_ind2unix(key, "created", 0),
			                               arr_ind2unix(key, "publish", 0),
			                               arr_ind2unix(key, "active", 0), # taking active for ready
			                               arr_ind2unix(key, "active", 0),
			                               arr_ind2unix(key, "retire", infty),
			                               arr_ind2unix(key, "remove", infty)
			                             ]).getRaw()

			with lmdb.Transaction(env, db_keys, write=True) as txn_keys:
				txn_keys.put(dbk3, dbv3, dupdata=False, overwrite=True)

	except (KeyError, KeyboardInterrupt, TypeError):
		print "Warning: not imported ", fname
		return False

	return True

def import_dir(dirname):
	print "Importing json key config in", dirname
	if os.path.isfile(dirname + "/data.mdb"):
		print "Warning: LMDB key configuratin in", dirname, "already exists."
		if opt_force:
			print "...deleting it."
			os.remove(dirname + "/data.mdb")
			os.remove(dirname + "/lock.mdb")
		else:
			print "If you want to delete it and import again, use 'force' option."
			return False

	env = lmdb.open(dirname, max_dbs=2, map_size=500*1024*1024)
	db_keys = env.open_db("keys_db")
	something_imported = False
	for json_file in glob.glob(dirname + "/*.json"):
		something_imported = import_file(json_file, env, db_keys) or something_imported

	if not something_imported:
		print "Warning: nothing imported in", dirname

def zone2keyids(dirname, zone_str):
	env = lmdb.open(dirname, max_dbs=2, map_size=500*1024*1024)
	db_zones = env.open_db("zones_db", dupsort=True)
	ret = [ ]
	zone = str2dname(zone_str)
	with lmdb.Transaction(env, db_keys, write=False) as txn_keys:
		curs = txn_keys.cursor()
		r = curs.set_range(Keykey.from_params(1, zone, None).getRaw())
		while r:
			k = Keykey(curs.key())
			if k.getZone() != zone:
				break
			ret.append(k.getKeyid())
			r = curs.next()
	return ret

def key_matches(keyid, keyparam, key_spec, attrs):
	if key_spec is not None:
		base_key_tag = -1 if re.match(r"^\d+$", key_spec) is None else int(key_spec)
		if len(key_spec) < 6 or not keyid.startswith(key_spec): # key id prefix not matches
			if keyparam.getKeytag() != base_key_tag: # keytag not matches
				return False

	now = int(time.time())
	for attr in attrs.lower().split('&'):
		if attr == "all" or attr == "":
			pass
		elif attr == "ksk" and not keyparam.isKSK():
			return False
		elif attr == "zsk" and keyparam.isKSK():
			return False
		elif attr == "published" and not keyparam.isPublished(now):
			return False
		elif attr == "ready" and not keyparam.isReady(now):
			return False
		elif attr == "active" and not keyparam.isActive(now):
			return False
		elif attr == "retired" and not keyparam.isRetired(now):
			return False
		elif attr not in ("ksk", "zsk", "published", "active", "retired"):
			print "Warning: unknown key attribute", attr
			return False
	return True

# FIXME for current KASP db format !!!
def update_param(dirname, zone_str, key_spec, param_name, new_val):
	#zone gets actually ignored
	if param_name in ("keytag", "algorithm") and not opt_force:
		print "Error: modification of", param_name, "requires force option"
		return False

	env = lmdb.open(dirname, max_dbs=2, map_size=500*1024*1024)
	db_keys = env.open_db("keys_db")
	something_updated = False
	with lmdb.Transaction(env, db_keys, write=True) as txn_keys:
		for k, v in txn_keys.cursor():
			try:
				kp = Keyparams(v)
				if key_matches(k, kp, key_spec, "all"):
					kp.setByParamName(param_name, new_val)
					txn_keys.put(k, kp.getRaw(), dupdata=False, overwrite=True)
					something_updated = True
					return
			except AssertionError:
				pass # some key-val which is not proper key param
	print "Error updating key parameter (probably the key not found)"

# FIXME for current KASP db format !!!
def calculate_ds(dirname, zone_str, key_spec):
	env = lmdb.open(dirname, max_dbs=2, map_size=500*1024*1024)
	db_keys = env.open_db("keys_db")
	with lmdb.Transaction(env, db_keys, write=True) as txn_keys:
		for k in zone2keyids(dirname, zone_str):
			kp = Keyparams(txn_keys.get(k + "\x00"))
			if key_matches(k, kp, key_spec, "all"):
				for digestalg in ("sha1", "sha256", "sha384"):
					print kp.computeDS(zone_str, digestalg)
				return
	print "Error finding specified key"

# FIXME for current KASP db format !!!
def list_keys(dirname, keyattr):
	env = lmdb.open(dirname, max_dbs=2, map_size=500*1024*1024)
	db_keys = env.open_db("keys_db")
	with lmdb.Transaction(env, db_keys, write=False) as txn_keys:
		for k, v in txn_keys.cursor():
			try:
				kp = Keyparams(v)
				if key_matches(k, kp, None, keyattr):
					print ("id=%s ksk=%s tag=%i timers:" %
					      (k, ("yes" if kp.isKSK() else "no"),
					      kp.getKeytag())), kp.getTimersString()
			except AssertionError:
				pass # some key-val which is not proper key param

# FIXME for current KASP db format !!!
def list_zones(dirname):
	print "dirname:", dirname
	env = lmdb.open(dirname, max_dbs=2, map_size=500*1024*1024)
	db_zones = env.open_db("zones_db", dupsort=True)
	zonedict = dict()
	with lmdb.Transaction(env, db_zones, write=False) as txn_zones:
		for k, v in txn_zones.cursor():
			dn = dname2str(k)
			ki = v.rstrip("\x00")
			try:
				zonedict[dn].insert(0, ki)
			except KeyError:
				zonedict[dn] = [ ki ]
	for zone in zonedict.keys():
		print zone, zonedict[zone]

def main():
	global opt_force
	parser = argparse.ArgumentParser(description="Knot DNSSEC PyKeyManager",
	                                 usage="use --help for more info.",
	                                 formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument("-i", "--import", action="append", nargs="?", dest="importdir",
	                    help='''Import zone-key configuration from JSON.
Syntax: -i <key_dir>
(You can import multiple key_dirs at once by repeating this option.)''')
#	parser.add_argument("-s", "--set", action="append", nargs=5, dest="setparam",
#	                    help='''Zone-key set params.
#Syntax: -s <key_dir> <zone_name> <key_id|key_tag> <parameter> <new_value>''')
#	parser.add_argument("-l", "--list", action="append", nargs=2, dest="listdir",
#	                    help='''List zone-key configuration (no key-zone relation).
#Syntax: -l <key_dir> <filter>''')
#	parser.add_argument("-z", "--zones", action="append", nargs=1, dest="zonesdir",
#	                    help='''List zones together with key IDs belonging to them.
#Syntax: -z <key_dir>''')
#	parser.add_argument("-d", "--ds", action="append", nargs=3, dest="ds",
#	                    help='''Calculate DS record for specified key.
#Syntax: -d <key_dir> <zone_name> <key_id|key_tag>''')
	parser.add_argument("-f", "--force", action="store_true", dest="force", help="Do stuff even if dangerous.")
	args = parser.parse_args()
	opt_force = args.force

	if args.importdir is not None:
		if isinstance(args.importdir, (list, tuple)):
			importdir = args.importdir
		else:
			importdir = [args.importdir]

		for dirn in importdir:
			import_dir(dirn)
			
#	if args.listdir is not None:
#		for dirn, filte in args.listdir:
#			list_keys(dirn, filte)

#	if args.zonesdir is not None:
#		for dirn in args.zonesdir:
#			list_zones(dirn[0])

#	if args.setparam is not None:
#		for dirn, zone, key, parmn, val in args.setparam:
#			update_param(dirn, zone, key, parmn, val)

#	if args.ds is not None:
#		for dirn, zone, key in args.ds:
#			calculate_ds(dirn, zone, key)

if __name__ == "__main__":
	main()
