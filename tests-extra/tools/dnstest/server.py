#!/usr/bin/env python3

import base64
import glob
import inspect
import ipaddress
import psutil
import re
import random
import shutil
import socket
import time
import dns.message
import dns.query
import dns.update
from subprocess import Popen, PIPE, check_call, CalledProcessError, check_output, DEVNULL
from dnstest.utils import *
from dnstest.context import Context
import dnstest.config
import dnstest.inquirer
import dnstest.params as params
import dnstest.keys
import dnstest.module
import dnstest.response
import dnstest.update
import distutils.dir_util
from shutil import copyfile

def zone_arg_check(zone):
    # Convert one item list to single object.
    if isinstance(zone, list):
        if len(zone) != 1:
            raise Failed("One zone required")
        return zone[0]
    return zone

class ZoneDnssec(object):
    '''Zone DNSSEC signing configuration'''

    def __init__(self):
        self.enable = None
        self.validate = None
        self.disable = None # create the policy in config, but set dnssec-signing: off
        self.manual = None
        self.single_type_signing = None
        self.alg = None
        self.ksk_size = None
        self.zsk_size = None
        self.dnskey_ttl = None
        self.zone_max_ttl = None
        self.ksk_lifetime = None
        self.zsk_lifetime = None
        self.delete_delay = None
        self.propagation_delay = None
        self.rrsig_lifetime = None
        self.rrsig_refresh = None
        self.rrsig_prerefresh = None
        self.repro_sign = None
        self.nsec3 = None
        self.nsec3_iters = None
        self.nsec3_opt_out = None
        self.nsec3_salt_lifetime = None
        self.nsec3_salt_len = None
        self.ksk_sbm_check = []
        self.ksk_sbm_check_interval = None
        self.ksk_sbm_timeout = None
        self.ds_push = None
        self.ksk_shared = None
        self.shared_policy_with = None
        self.cds_publish = None
        self.cds_digesttype = None
        self.offline_ksk = None

class Zone(object):
    '''DNS zone description'''

    def __init__(self, zone_file, ddns=False, ixfr=False, journal_content="changes"):
        self.zfile = zone_file
        self.masters = set()
        self.slaves = set()
        self.ddns = ddns
        self.ixfr = ixfr
        self.journal_content = journal_content # journal contents
        self.modules = []
        self.dnssec = ZoneDnssec()
        self.catalog = None
        self.catalog_zone = None
        self.catalog_group = None

    @property
    def name(self):
        return self.zfile.name

    def add_module(self, module):
        self.modules.append(module)

    def get_module(self, mod_name):
        for m in self.modules:
            if m.mod_name == mod_name:
               return m;

    def clear_modules(self):
        self.modules.clear()

    def catalog_gen_link(self, catalog_zone):
        self.catalog_zone = catalog_zone
        catalog_zone.catalog_zone = catalog_zone

    def disable_master(self, new_zone_file):
        self.zfile.remove()
        self.zfile = new_zone_file
        self.ixfr = False

class Server(object):
    '''Specification of DNS server'''

    START_WAIT = 2
    START_WAIT_VALGRIND = 5
    START_WAIT_ATTEMPTS = 60
    START_MAX_ATTEMPTS = 10
    STOP_TIMEOUT = 30
    COMPILE_TIMEOUT = 60
    DIG_TIMEOUT = 5

    # Instance counter.
    count = 0

    def __init__(self):
        self.proc = None
        self.valgrind = []
        self.start_params = None
        self.ctl_params = None
        self.ctl_params_append = None # The last parameter wins.

        self.data_dir = None

        self.nsid = None
        self.ident = None
        self.version = None

        self.addr = None
        self.addr_extra = list()
        self.port = 53 # Needed for keymgr when port not yet generated
        self.udp_workers = None
        self.fixed_port = False
        self.ctlport = None
        self.external = False
        self.ctlkey = None
        self.ctlkeyfile = None
        self.tsig = None
        self.tsig_test = None
        self.no_xfr_edns = None

        self.zones = dict()

        self.tcp_reuseport = None
        self.tcp_remote_io_timeout = None
        self.tcp_io_timeout = None
        self.udp_max_payload = None
        self.udp_max_payload_ipv4 = None
        self.udp_max_payload_ipv6 = None
        self.disable_notify = None
        self.semantic_check = True
        self.zonefile_sync = "1d"
        self.zonefile_load = None
        self.zonemd_verify = None
        self.zonemd_generate = None
        self.journal_db_size = 20 * 1024 * 1024
        self.journal_max_usage = 5 * 1024 * 1024
        self.timer_db_size = 1 * 1024 * 1024
        self.kasp_db_size = 10 * 1024 * 1024
        self.catalog_db_size = 10 * 1024 * 1024
        self.zone_size_limit = None
        self.serial_policy = None

        self.inquirer = None

        self.modules = []

        # Working directory.
        self.dir = None
        # Name of server instance.
        self.name = None
        self.fout = None
        self.ferr = None
        self.valgrind_log = None
        self.confile = None

        self.binding_errors = 0

    def _check_socket(self, proto, port):
        if ipaddress.ip_address(self.addr).version == 4:
            iface = "4%s@%s:%i" % (proto, self.addr, port)
        else:
            iface = "6%s@[%s]:%i" % (proto, self.addr, port)

        for i in range(5):
            proc = Popen(["lsof", "-t", "-i", iface],
                         stdout=PIPE, stderr=PIPE, universal_newlines=True)
            (out, err) = proc.communicate()

            # Create list of pids excluding last empty line.
            pids = list(filter(None, out.split("\n")))

            # Check for successful bind.
            if len(pids) == 1 and str(self.proc.pid) in pids:
                return True

            time.sleep(2)

        return False

    def set_master(self, zone, slave=None, ddns=False, ixfr=False, journal_content="changes"):
        '''Set the server as a master for the zone'''

        if zone.name not in self.zones:
            master_file = zone.clone(self.dir + "/master")
            z = Zone(master_file, ddns, ixfr, journal_content)
            self.zones[zone.name] = z
        else:
            z = self.zones[zone.name]

        if slave:
            z.slaves.add(slave)

    def set_slave(self, zone, master, ddns=False, ixfr=False, journal_content="changes"):
        '''Set the server as a slave for the zone'''

        slave_file = zone.clone(self.dir + "/slave", exists=False)

        if zone.name not in self.zones:
            z = Zone(slave_file, ddns, ixfr, journal_content)
            self.zones[zone.name] = z
        else:
            z = self.zones[zone.name]
            z.disable_master(slave_file)

        z.masters.add(master)

    def compile(self):
        try:
            p = Popen([self.control_bin] + self.compile_params,
                      stdout=self.fout, stderr=self.ferr)
            p.communicate(timeout=Server.COMPILE_TIMEOUT)
        except:
            raise Failed("Can't compile server='%s'" %self.name)

    def wait_for_pidfile(self, attempts=8):
        '''Wait for a PID file to disappear, with a timeout'''

        pidf = os.path.join(self.dir, self.pidfile)
        for i in range(attempts):
            if not os.path.isfile(pidf):
                break
            time.sleep(0.5)

    def start_server(self, clean=False):
        '''Start the server'''
        mode = "w" if clean else "a"

        try:
            if os.path.isfile(self.valgrind_log):
                copyfile(self.valgrind_log, self.valgrind_log + str(int(time.time())))

            if self.daemon_bin != None:
                self.proc = Popen(self.valgrind + [self.daemon_bin] + \
                                  self.start_params,
                                  stdout=open(self.fout, mode=mode),
                                  stderr=open(self.ferr, mode=mode))

            if self.valgrind:
                time.sleep(Server.START_WAIT_VALGRIND)
            else:
                time.sleep(Server.START_WAIT)
        except OSError:
            raise Failed("Can't start server='%s'" % self.name)

        # Start inquirer if enabled.
        if Context().test.stress and self.inquirer:
            self.inquirer.start(self)

    def start(self, clean=False):
        '''Start the server with all bindings successful'''

        errors = 0 if clean else self.binding_errors
        for attempt in range(Server.START_MAX_ATTEMPTS):
            self.binding_errors = errors
            self.wait_for_pidfile()
            self.start_server(clean)
            errors = self.log_search_count(self.binding_fail)
            if errors == self.binding_errors:
                break
            self.stop()
            if attempt < (Server.START_MAX_ATTEMPTS - 1):
                time.sleep(Server.START_WAIT_ATTEMPTS)
                check_log("STARTING %s AGAIN" % self.name)

        if errors > self.binding_errors:
            raise Failed("Couldn't bind all addresses or ports")

        self.binding_errors = errors

    def ctl(self, cmd, wait=False, availability=True):
        if availability:
            # Check for listening control interface.
            ok = False
            for i in range(0, 5):
                try:
                    self.ctl("status", availability=False)
                except Failed:
                    time.sleep(1)
                    continue
                ok = True
                break
            if not ok:
                self.backtrace()
                raise Failed("Unavailable remote control server='%s'" % self.name)

        # Send control command.
        args = self.ctl_params + (self.control_wait if wait else []) + cmd.split()
        try:
            check_call([self.control_bin] + args,
                       stdout=open(self.dir + "/call.out", mode="a"),
                       stderr=open(self.dir + "/call.err", mode="a"))
        except CalledProcessError as e:
            self.backtrace()
            raise Failed("Can't control='%s' server='%s', ret='%i'" %
                         (cmd, self.name, e.returncode))

        # Allow the command to complete, Bind needs this.
        self.wait_function(wait)

    def reload(self):
        self.ctl("reload")
        time.sleep(Server.START_WAIT)

    def running(self):
        proc = psutil.Process(self.proc.pid)
        status = proc.status
        # psutil 2.0.0+ makes status a function
        if psutil.version_info[0] >= 2:
            status = proc.status()
        if status == psutil.STATUS_RUNNING or \
           status == psutil.STATUS_SLEEPING or \
           status == psutil.STATUS_DISK_SLEEP:
            return True
        else:
            return False

    def _valgrind_check(self):
        if not self.valgrind:
            return

        check_log("VALGRIND CHECK %s" % self.name)

        lock = False
        lost = 0
        reachable = 0
        errcount = 0

        try:
            f = open(self.valgrind_log, "r")
        except:
            detail_log("No err log file")
            detail_log(SEP)
            return

        for line in f:
            if re.search("(HEAP|LEAK) SUMMARY", line):
                lost = 0
                reachable = 0
                errcount = 0
                lock = True
                continue

            if lock:
                lost_line = re.search("lost:", line)
                if lost_line:
                    lost += int(line[lost_line.end():].lstrip(). \
                                split(" ")[0].replace(",", ""))
                    continue

                reach_line = re.search("reachable:", line)
                if reach_line:
                    reachable += int(line[reach_line.end():].lstrip(). \
                                     split(" ")[0].replace(",", ""))
                    continue

                err_line = re.search("ERROR SUMMARY:", line)
                if err_line:
                    errcount += int(line[err_line.end():].lstrip(). \
                                    split(" ")[0].replace(",", ""))

                    if lost > 0 or reachable > 0 or errcount > 0:
                        set_err("VALGRIND")
                        detail_log("%s memcheck: lost(%i B), reachable(%i B), " \
                                   "errcount(%i)" \
                                   % (self.name, lost, reachable, errcount))

                    lock = False
                    continue

        detail_log(SEP)
        f.close()

    def backtrace(self):
        if self.valgrind:
            check_log("BACKTRACE %s" % self.name)

            try:
                check_call([params.gdb_bin, "-ex", "set confirm off", "-ex",
                            "target remote | %s --pid=%s" %
                            (params.vgdb_bin, self.proc.pid),
                            "-ex", "info threads",
                            "-ex", "thread apply all bt full", "-ex", "q",
                            self.daemon_bin],
                           stdout=open(self.dir + "/gdb.out", mode="a"),
                           stderr=open(self.dir + "/gdb.err", mode="a"))
            except:
                detail_log("!Failed to get backtrace")

            detail_log(SEP)

    def stop(self, check=True):
        if Context().test.stress and self.inquirer:
            self.inquirer.stop()

        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(Server.STOP_TIMEOUT)
            except ProcessLookupError:
                pass
            except:
                self.backtrace()
                check_log("WARNING: KILLING %s" % self.name)
                detail_log(SEP)
                self.kill()
        if check:
            self._valgrind_check()

    def kill(self):
        if Context().test.stress and self.inquirer:
            self.inquirer.stop()

        if self.proc:
            # Store PID before kill.
            pid = self.proc.pid

            self.proc.kill()

            # Remove uncleaned vgdb pipes.
            for f in glob.glob("/tmp/vgdb-pipe*-%s-*" % pid):
                try:
                    os.remove(f)
                except:
                    pass

    def gen_confile(self):
        f = open(self.confile, mode="w")
        f.write(self.get_config())
        f.close()

    def dig(self, rname, rtype, rclass="IN", udp=None, serial=None, timeout=None,
            tries=3, flags="", bufsize=None, edns=None, nsid=False, dnssec=False,
            log_no_sep=False, tsig=None, addr=None, source=None):

        # Convert one item zone list to zone name.
        if isinstance(rname, list):
            if len(rname) != 1:
                raise Failed("One zone required")
            rname = rname[0].name

        rtype_str = rtype.upper()

        # Set port type.
        if rtype.upper() == "AXFR":
            # Always use TCP.
            udp = False
        elif rtype.upper() == "IXFR":
            # Use TCP if not specified.
            udp = udp if udp != None else False
            rtype_str += "=%i" % int(serial)
        else:
            # Use TCP or UDP at random if not specified.
            udp = udp if udp != None else random.choice([True, False])

        if udp:
            dig_flags = "+notcp"
        else:
            dig_flags = "+tcp"

        dig_flags += " +retry=%i" % (tries - 1)

        # Set timeout.
        if timeout is None:
            timeout = self.DIG_TIMEOUT
        dig_flags += " +time=%i" % timeout

        # Prepare query (useless for XFR).
        query = dns.message.make_query(rname, rtype, rclass)

        # Remove implicit RD flag.
        query.flags &= ~dns.flags.RD

        # Set packet flags.
        flag_names = flags.split()
        for flag in flag_names:
            if flag == "AA":
                query.flags |= dns.flags.AA
                dig_flags += " +aa"
            elif flag == "TC":
                query.flags |= dns.flags.TC
                dig_flags += " +tc"
            elif flag == "RD":
                query.flags |= dns.flags.RD
                dig_flags += " +rd"
            elif flag == "RA":
                query.flags |= dns.flags.RA
                dig_flags += " +ra"
            elif flag == "AD":
                query.flags |= dns.flags.AD
                dig_flags += " +ad"
            elif flag == "CD":
                query.flags |= dns.flags.CD
                dig_flags += " +cd"
            elif flag == "Z":
                query.flags |= 64
                dig_flags += " +z"

        # Set EDNS.
        if edns != None or bufsize or nsid:
            class NsidFix(object):
                '''Old pythondns doesn't implement NSID option.'''
                def __init__(self):
                    self.otype = dns.edns.NSID
                def to_wire(self, file=None):
                    pass

            if edns:
                edns = int(edns)
            else:
                edns = 0
            dig_flags += " +edns=%i" % edns

            if bufsize:
                payload = int(bufsize)
            else:
                payload = 1232
            dig_flags += " +bufsize=%i" % payload

            if nsid:
                if not hasattr(dns, 'version') or dns.version.MAJOR == 1:
                    options = [NsidFix()]
                else:
                    options = [dns.edns.GenericOption(dns.edns.NSID, b'')]
                dig_flags += " +nsid"
            else:
                options = None

            query.use_edns(edns=edns, payload=payload, options=options)

        # Set DO flag.
        if dnssec:
            query.want_dnssec()
            dig_flags += " +dnssec +bufsize=%i" % query.payload

        # Store function arguments for possible comparison.
        args = dict()
        params = inspect.getargvalues(inspect.currentframe())
        for param in params.args:
            if param != "self":
                args[param] = params.locals[param]

        if addr is None:
            addr = self.addr

        # Add source to dig flags if present
        if source is not None:
            dig_flags += " -b " + source

        check_log("DIG %s %s %s @%s -p %i %s" %
                  (rname, rtype_str, rclass, addr, self.port, dig_flags))

        # Set TSIG for a normal query if explicitly specified.
        key_params = dict()
        if tsig != None:
            if type(tsig) is dnstest.keys.Tsig:
                key_params = tsig.key_params
            elif tsig and self.tsig_test:
                key_params = self.tsig_test.key_params
        if key_params:
            query.use_tsig(keyring=key_params["keyring"],
                           keyname=key_params["keyname"],
                           algorithm=key_params["keyalgorithm"])

        # Set TSIG for a transfer if available.
        if rtype.upper() == "AXFR" or rtype.upper() == "IXFR":
            if self.tsig_test and tsig != False:
                key_params = self.tsig_test.key_params

        if key_params:
            detail_log("%s:%s:%s" %
                (key_params["keyalgorithm"], key_params["keyname"],
                 base64.b64encode(list(key_params["keyring"].values())[0]).decode('ascii')))

        for t in range(tries):
            try:
                if rtype.upper() == "AXFR":
                    resp = dns.query.xfr(addr, rname, rtype, rclass,
                                         port=self.port, lifetime=timeout,
                                         use_udp=udp, **key_params)
                elif rtype.upper() == "IXFR":
                    resp = dns.query.xfr(addr, rname, rtype, rclass,
                                         port=self.port, lifetime=timeout,
                                         use_udp=udp, serial=int(serial),
                                         **key_params)
                elif udp:
                    resp = dns.query.udp(query, addr, port=self.port,
                                         timeout=timeout, source=source)
                else:
                    resp = dns.query.tcp(query, addr, port=self.port,
                                         timeout=timeout, source=source)

                if not log_no_sep:
                    detail_log(SEP)

                return dnstest.response.Response(self, resp, query, args)
            except dns.exception.Timeout:
                pass
            except:
                time.sleep(timeout)

        raise Failed("Can't query server='%s' for '%s %s %s'" % \
                     (self.name, rname, rclass, rtype))

    def create_sock(self, socket_type):
        family = socket.AF_INET
        if ipaddress.ip_address(self.addr).version == 6:
            family = socket.AF_INET6
        return socket.socket(family, socket_type)

    def send_raw(self, data, sock=None):
        if sock is None:
            sock = self.create_sock(socket.SOCK_DGRAM)
        sent = sock.sendto(bytes(data, 'utf-8'), (self.addr, self.port))
        if sent != len(data):
            raise Failed("Can't send RAW data (%d bytes) to server='%s'" %
                         (len(data), self.name))

    def log_search(self, pattern):
        with open(self.fout) as log:
            for line in log:
                if pattern in line:
                    return True
        with open(self.ferr) as log:
            for line in log:
                if pattern in line:
                    return True
        return False

    def log_search_count(self, pattern):
        count = 0
        with open(self.fout) as log:
            for line in log:
                if pattern in line:
                    count += 1
        with open(self.ferr) as log:
            for line in log:
                if pattern in line:
                    count += 1
        return count

    def zone_wait(self, zone, serial=None, equal=False, greater=True, udp=True, tsig=None):
        '''Try to get SOA record. With an optional serial number and given
           relation (equal or/and greater).'''

        zone = zone_arg_check(zone)

        _serial = 0

        check_log("ZONE WAIT %s: %s" % (self.name, zone.name))

        attempts = 60 if not self.valgrind else 100
        for t in range(attempts):
            try:
                resp = self.dig(zone.name, "SOA", udp=udp, tries=1,
                                timeout=2, log_no_sep=True, tsig=tsig)
            except:
                pass
            else:
                if resp.resp.rcode() == 0:
                    if not resp.resp.answer:
                        raise Failed("No SOA in ANSWER, zone='%s', server='%s'" %
                                     (zone.name, self.name))

                    soa = str((resp.resp.answer[0]).to_rdataset())
                    _serial = int(soa.split()[5])

                    if not serial:
                        break
                    elif equal and serial == _serial:
                        break
                    elif greater and serial < _serial:
                        break
            time.sleep(2)
        else:
            self.backtrace()
            serial_str = ""
            if serial:
                serial_str = "%s%s%i" % (">" if greater else "",
                                         "=" if equal else "", serial)
            raise Failed("Can't get SOA%s, zone='%s', server='%s'" %
                         (serial_str, zone.name, self.name))

        detail_log(SEP)

        return _serial

    def zones_wait(self, zone_list, serials=None, serials_zfile=False, equal=False, greater=True):
        new_serials = dict()

        if serials_zfile:
            if serials is not None:
                raise Exception('serials_zfile incompatible with serials')
            serials = dict()
            for zone in zone_list:
                serials[zone.name] = self.zones[zone.name].zfile.get_soa_serial()

        for zone in zone_list:
            old_serial = serials[zone.name] if serials else None
            new_serial = self.zone_wait(zone, serial=old_serial, equal=equal,
                                        greater=greater)
            new_serials[zone.name] = new_serial

        return new_serials

    def zone_backup(self, zone, flush=False):
        zone = zone_arg_check(zone)

        if flush:
            self.flush(zone=zone, wait=True)

        self.zones[zone.name].zfile.backup()

    def zone_verify(self, zone, bind_check=True, ldns_check=True):
        zone = zone_arg_check(zone)

        self.zones[zone.name].zfile.dnssec_verify(bind_check, ldns_check)

    def check_nsec(self, zone, nsec3=False, nonsec=False):
        zone = zone_arg_check(zone)

        resp = self.dig("0-x-not-existing-x-0." + zone.name, "ANY", dnssec=True)
        resp.check_nsec(nsec3=nsec3, nonsec=nonsec)

    def update(self, zone):
        zone = zone_arg_check(zone)

        key_params = self.tsig_test.key_params if self.tsig_test else dict()

        return dnstest.update.Update(self, dns.update.Update(zone.name,
                                                             **key_params))

    def gen_key(self, zone, **args):
        zone = zone_arg_check(zone)

        key = dnstest.keys.Key(self.confile, zone.name, **args)
        key.generate()

        return key

    @property
    def keydir(self):
        d = os.path.join(self.dir, "keys")
        if not os.path.exists(d):
            os.makedirs(d)
        return d

    def use_keys(self, zone):
        zone = zone_arg_check(zone)
        # copy all keys, even for other zones
        distutils.dir_util.copy_tree(zone.key_dir, self.keydir, update=True)

    def dnssec(self, zone):
        zone = zone_arg_check(zone)

        return self.zones[zone.name].dnssec

    def enable_nsec3(self, zone, **args):
        zone = zone_arg_check(zone)

        self.zones[zone.name].zfile.enable_nsec3(**args)

    def disable_nsec3(self, zone):
        zone = zone_arg_check(zone)

        self.zones[zone.name].zfile.disable_nsec3()

    def backup_zone(self, zone):
        zone = zone_arg_check(zone)

        self.zones[zone.name].zfile.backup()

    def update_zonefile(self, zone, version=None, random=False, storage=None):
        zone = zone_arg_check(zone)

        if not storage:
            storage = self.data_dir

        if random:
            self.zones[zone.name].zfile.update_rnd()
        else:
            self.zones[zone.name].zfile.upd_file(storage=storage, version=version)

    def random_ddns(self, zone, allow_empty=True):
        zone = zone_arg_check(zone)

        while True:
            up = self.update(zone)

            while True:
                changes = self.zones[zone.name].zfile.gen_rnd_ddns(up)
                if allow_empty or changes > 0:
                    break

            if up.try_send() == "NOERROR":
                break

    def add_module(self, zone, module):
        zone = zone_arg_check(zone)

        if zone:
            self.zones[zone.name].add_module(module)
        else:
            self.modules.append(module)

    def clear_modules(self, zone):
        zone = zone_arg_check(zone)

        if zone:
            self.zones[zone.name].clear_modules()
        else:
            self.modules.clear()

    def clean(self, zone=True, timers=True):
        if zone:
            zone = zone_arg_check(zone)

            # Remove all zonefiles.
            if zone is True:
                for _z in sorted(self.zones):
                    zfile = self.zones[_z].zfile.path
                    try:
                        os.remove(zfile)
                    except:
                        pass
            # Remove specified zonefile.
            else:
                zfile = self.zones[zone.name].zfile.path
                try:
                    os.remove(zfile)
                except:
                    pass

        if timers:
            try:
                shutil.rmtree(self.dir + "/timers")
            except:
                pass

class Bind(Server):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not params.bind_bin:
            raise Skip("No Bind")
        self.daemon_bin = params.bind_bin
        self.control_bin = params.bind_ctl
        self.control_wait = []
        self.ctlkey = dnstest.keys.Tsig(alg="hmac-md5")
        self.binding_fail = "address in use"
        self.pidfile = "bind.pid"

    def listening(self):
        tcp = super()._check_socket("tcp", self.port)
        udp = super()._check_socket("udp", self.port)
        ctltcp = super()._check_socket("tcp", self.ctlport)
        return (tcp and udp and ctltcp)

    def wait_function(self, wait=False):
        # There's no blocking mode in rndc, simulating it.
        time.sleep(Server.START_WAIT + (3 if wait else 0))

    def flush(self, zone=None, wait=False):
        zone_name = (" " + zone.name) if zone else ""
        self.ctl("sync%s" % zone_name, wait=wait)

    def _str(self, conf, name, value):
        if value and value != True:
            conf.item_str(name, value)

    def get_config(self):
        s = dnstest.config.BindConf()
        s.begin("options")
        self._str(s, "server-id", self.ident)
        self._str(s, "version", self.version)
        s.item_str("directory", self.dir)
        s.item_str("key-directory", self.dir)
        s.item_str("managed-keys-directory", self.dir)
        s.item_str("session-keyfile", self.dir + "/session.key")
        s.item_str("pid-file", os.path.join(self.dir, self.pidfile))
        if ipaddress.ip_address(self.addr).version == 4:
            s.item("listen-on port", "%i { %s; }" % (self.port, self.addr))
            s.item("listen-on-v6", "{ }")
        else:
            s.item("listen-on", "{ }")
            s.item("listen-on-v6 port", "%i { %s; }" % (self.port, self.addr))
        s.item("auth-nxdomain", "no")
        s.item("recursion", "no")
        s.item("masterfile-format", "text")
        s.item("max-refresh-time", "2")
        s.item("max-retry-time", "2")
        s.item("transfers-in", "30")
        s.item("transfers-out", "30")
        s.item("minimal-responses", "true")
        s.item("notify-delay", "0")
        s.item("notify-rate", "1000")
        s.item("max-journal-size", "unlimited")
        s.item("startup-notify-rate", "1000")
        s.item("serial-query-rate", "1000")
        s.end()

        s.begin("key", self.ctlkey.name)
        s.item("algorithm", self.ctlkey.alg)
        s.item_str("secret", self.ctlkey.key)
        s.end()

        s.begin("controls")
        s.item("inet %s port %i allow { %s; } keys { %s; }"
               % (self.addr, self.ctlport, Context().test.addr, self.ctlkey.name))
        s.end()

        if self.tsig:
            t = self.tsig
            s.begin("key", t.name)
            s.item("# Local key")
            s.item("algorithm", t.alg)
            s.item_str("secret", t.key)
            s.end()
            t = self.tsig_test
            s.begin("key", t.name)
            s.item("# Test key")
            s.item("algorithm", t.alg)
            s.item_str("secret", t.key)
            s.end()

            keys = set() # Duplicy check.
            for zone in sorted(self.zones):
                z = self.zones[zone]
                for master in z.masters:
                    if master.tsig.name not in keys:
                        t = master.tsig
                        s.begin("key", t.name)
                        s.item("algorithm", t.alg)
                        s.item_str("secret", t.key)
                        s.end()
                        keys.add(t.name)
                for slave in z.slaves:
                    if slave.tsig and slave.tsig.name not in keys:
                        t = slave.tsig
                        s.begin("key", t.name)
                        s.item("algorithm", t.alg)
                        s.item_str("secret", t.key)
                        s.end()
                        keys.add(t.name)

        for zone in sorted(self.zones):
            z = self.zones[zone]
            s.begin("zone", z.name)
            s.item_str("file", z.zfile.path)
            s.item("check-names", "warn")

            if z.masters:
                s.item("type", "slave")

                masters = ""
                masters_notify = ""
                for master in z.masters:
                    if self.tsig:
                        masters += "%s port %i key %s; " \
                                   % (master.addr, master.port, master.tsig.name)
                        if not master.disable_notify:
                            masters_notify += "key %s; " % master.tsig.name
                    else:
                        masters += "%s port %i; " \
                                   % (master.addr, master.port)
                        if not master.disable_notify:
                            masters_notify += "%s; " % master.addr
                s.item("masters", "{ %s}" % masters)
                if masters_notify:
                    s.item("allow-notify", "{ %s}" % masters_notify)
            else:
                s.item("type", "master")
                s.item("notify", "explicit")
                s.item("check-integrity", "no")

            if z.ixfr and not z.masters:
                s.item("ixfr-from-differences", "yes")

            if z.slaves:
                slaves = ""
                for slave in z.slaves:
                    if slave.disable_notify:
                        continue
                    if self.tsig:
                        slaves += "%s port %i key %s; " \
                                  % (slave.addr, slave.port, self.tsig.name)
                    else:
                        slaves += "%s port %i; " % (slave.addr, slave.port)
                if slaves:
                    s.item("also-notify", "{ %s}" % slaves)

            if z.ddns:
                if self.tsig_test:
                    upd = "key %s; " % self.tsig_test.name
                else:
                    upd = "%s; " % Context().test.addr

                if z.masters:
                    s.item("allow-update-forwarding", "{ %s}" % upd)
                else:
                    s.item("allow-update", "{ %s}" % upd)

            if self.tsig or self.tsig_test:
                s.item("allow-transfer", "{%s%s }" %
                       ((" key %s;" % self.tsig.name) if self.tsig else "",
                        (" key %s;" % self.tsig_test.name) if self.tsig_test else ""))
            else:
                s.item("allow-transfer", "{ any; }")

            if z.dnssec.enable:
                s.item("inline-signing", "yes")
                s.item("auto-dnssec", "maintain")
                s.item_str("key-directory", self.keydir)

            s.end()

        self.start_params = ["-c", self.confile, "-g"]
        self.ctl_params = ["-s", self.addr, "-p", str(self.ctlport), \
                           "-k", self.ctlkeyfile]

        return s.conf

    def start(self, clean=False):
        for zname in self.zones:
            z = self.zones[zname]
            if z.dnssec.enable != True:
                continue

            # unrelated: generate keys as Bind won't do
            ps = [ 'dnssec-keygen', '-n', 'ZONE', '-a', 'RSASHA256', '-b', '1024', '-K', self.keydir ]
            if z.dnssec.nsec3:
                ps += ['-3']
            k1 = check_output(ps + [z.name], stderr=DEVNULL)
            k2 = check_output(ps + ["-f", "KSK"] + [z.name], stderr=DEVNULL)

            k1 = self.keydir + '/' + k1.rstrip().decode('ascii')
            k2 = self.keydir + '/' + k2.rstrip().decode('ascii')

            # Append to zone
            with open(z.zfile.path, 'a') as outf:
                outf.write('\n')
                with open(k1 + '.key', 'r') as kf:
                    for line in kf:
                        if len(line) > 0 and line[0] != ';':
                            outf.write(line)
                with open(k2 + '.key', 'r') as kf:
                    for line in kf:
                        if len(line) > 0 and line[0] != ';':
                            outf.write(line)
                #if z.dnssec.nsec3:
                    #n3flag =  1 if z.dnssec.nsec3_opt_out else 0
                    #n3iters = z.dnssec.nsec3_iters or 10
                    #outf.write("%s NSEC3PARAM 1 %d %d -\n" % (z.name, n3flag, n3iters)) # this does not work!

        super().start(clean)

        for zname in self.zones:
            z = self.zones[zname]
            if z.dnssec.nsec3:
                n3flag =  1 if z.dnssec.nsec3_opt_out else 0
                n3iters = z.dnssec.nsec3_iters or 10
                self.ctl("signing -nsec3param 1 %d %d - %s" % (n3flag, n3iters, z.name))

class Knot(Server):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not params.knot_bin:
            raise Skip("No Knot")
        self.daemon_bin = params.knot_bin
        self.control_bin = params.knot_ctl
        self.control_wait = ["-b"]
        self.inquirer = dnstest.inquirer.Inquirer()
        self.includes = set()
        self.binding_fail = "cannot bind address"
        self.pidfile = "knot.pid"

    def listening(self):
        tcp = super()._check_socket("tcp", self.port)
        udp = super()._check_socket("udp", self.port)
        return (tcp and udp)

    def wait_function(self, wait=False): # needed for compatibility with Bind class
        pass

    def flush(self, zone=None, wait=False):
        params = "-f " if str(self.zonefile_sync)[0] == '-' else ""
        if zone:
            self.ctl("%szone-flush %s" % (params, zone.name), wait=wait)
        else:
            self.ctl("%szone-flush" % params, wait=wait)

    def key_gen(self, zone_name, **new_params):
        set_params = [ option + "=" + value for option, value in new_params.items() ]
        res = dnstest.keys.Keymgr.run_check(self.confile, zone_name, "generate", *set_params)
        errcode, stdo, stde = res
        return stdo.split()[-1]

    def key_set(self, zone_name, key_id, **new_values):
        set_params = [ option + "=" + value for option, value in new_values.items() ]
        dnstest.keys.Keymgr.run_check(self.confile, zone_name, "set", key_id, *set_params)

    def key_import_bind(self, zone_name):
        if zone_name not in self.zones:
            assert(0)
        bind_keydir = self.zones[zone_name].zfile.key_dir_bind
        assert(zone_name.endswith("."))
        for pkey_path in glob.glob("%s/K*.private" % glob.escape(bind_keydir)):
            pkey = os.path.basename(pkey_path)
            m = re.match(r'K(?P<name>[^+]+)\+(?P<algo>\d+)\+(?P<tag>\d+)\.private', pkey)
            if m and m.group("name") == zone_name.lower():
                dnstest.keys.Keymgr.run_check(self.confile, zone_name, "import-bind", pkey_path)

    def _on_str_hex(self, conf, name, value):
        if value == True:
            return
        elif value == False:
            conf.item_str(name, "")
        elif value:
            conf.item_str(name, value)

    def _key(self, conf, key):
        if key:
            conf.id_item("id", key.name)
            conf.item_str("algorithm", key.alg)
            conf.item_str("secret", key.key)

    def _bool(self, conf, name, value):
        if value != None:
            conf.item_str(name, "on" if value else "off")

    def _str(self, conf, name, value):
        if value != None:
            conf.item_str(name, value)

    def data_add(self, file_name, storage=None):
        if storage == ".":
            src_dir = self.data_dir
        elif storage:
            src_dir = storage
        else:
            src_dir = params.common_data_dir

        src_file = src_dir + file_name
        dst_file = self.dir + '/' + file_name
        shutil.copyfile(src_file, dst_file)

        return dst_file

    def include(self, file_name, storage=None, empty=False):
        if empty:
            self.includes.add(file_name)
        else:
            dst_file = self.data_add(file_name, storage)
            self.includes.add(dst_file)

    def first_master(self, zone_name):
        return sorted(self.zones[zone_name].masters, key=lambda srv: srv.name)[0]

    def config_xfr(self, zone, knotconf):
        acl = ""
        if zone.masters:
            masters = ""
            for master in sorted(zone.masters, key=lambda srv: srv.name):
                if masters:
                    masters += ", "
                masters += master.name
                if not master.disable_notify:
                    if acl:
                        acl += ", "
                    acl += "acl_%s" % master.name
            knotconf.item("master", "[%s]" % masters)
        if zone.slaves:
            slaves = ""
            for slave in zone.slaves:
                if slave.disable_notify:
                    continue
                if slaves:
                    slaves += ", "
                slaves += slave.name
            if slaves:
                knotconf.item("notify", "[%s]" % slaves)
        if acl:
            acl += ", "
        acl += "acl_local, acl_test"
        knotconf.item("acl", "[%s]" % acl)

    def get_config(self):
        s = dnstest.config.KnotConf()

        for file in self.includes:
            s.include(file)

        s.begin("server")
        self._on_str_hex(s, "identity", self.ident)
        self._on_str_hex(s, "version", self.version)
        self._on_str_hex(s, "nsid", self.nsid)
        s.item_str("rundir", self.dir)
        s.item_str("pidfile", os.path.join(self.dir, self.pidfile))
        s.item_str("listen", "%s@%s" % (self.addr, self.port))
        if self.udp_workers:
            s.item_str("udp-workers", self.udp_workers)

        for addr in self.addr_extra:
            s.item_str("listen", "%s@%s" % (addr, self.port))
        self._str(s, "tcp-remote-io-timeout", self.tcp_remote_io_timeout)
        self._str(s, "tcp-io-timeout", self.tcp_io_timeout)
        self._bool(s, "tcp-reuseport", self.tcp_reuseport)
        self._str(s, "udp-max-payload", self.udp_max_payload)
        self._str(s, "udp-max-payload-ipv4", self.udp_max_payload_ipv4)
        self._str(s, "udp-max-payload-ipv6", self.udp_max_payload_ipv6)
        s.end()

        s.begin("control")
        s.item_str("listen", "knot.sock")
        s.item_str("timeout", "15")
        s.end()

        if self.tsig:
            s.begin("key")
            self._key(s, self.tsig)
            self._key(s, self.tsig_test)

            keys = set() # Duplicy check.
            for zone in sorted(self.zones):
                z = self.zones[zone]
                for master in z.masters:
                    if master.tsig.name not in keys:
                        t = master.tsig
                        self._key(s, t)
                        keys.add(t.name)
                for slave in z.slaves:
                    if slave.tsig.name not in keys:
                        t = slave.tsig
                        self._key(s, t)
                        keys.add(t.name)
            s.end()

        have_remote = False
        servers = set() # Duplicity check.
        for zone in sorted(self.zones):
            z = self.zones[zone]
            for master in z.masters:
                if master.name not in servers:
                    if not have_remote:
                        s.begin("remote")
                        have_remote = True
                    s.id_item("id", master.name)
                    s.item_str("address", "%s@%s" % (master.addr, master.port))
                    if master.tsig:
                        s.item_str("key", master.tsig.name)
                    if master.no_xfr_edns:
                        s.item_str("no-edns", "on")
                    servers.add(master.name)
            for slave in z.slaves:
                if slave.name not in servers:
                    if not have_remote:
                        s.begin("remote")
                        have_remote = True
                    s.id_item("id", slave.name)
                    s.item_str("address", "%s@%s" % (slave.addr, slave.port))
                    if slave.tsig:
                        s.item_str("key", slave.tsig.name)
                    servers.add(slave.name)
            for parent in z.dnssec.ksk_sbm_check + [ z.dnssec.ds_push ] if z.dnssec.ds_push else z.dnssec.ksk_sbm_check:
                if parent.name not in servers:
                    if not have_remote:
                        s.begin("remote")
                        have_remote = True
                    s.id_item("id", parent.name)
                    s.item_str("address", "%s@%s" % (parent.addr, parent.port))
                    servers.add(parent.name)

        if have_remote:
            s.end()

        s.begin("acl")
        s.id_item("id", "acl_local")
        s.item_str("address", Context().test.addr)
        if self.tsig:
            s.item_str("key", self.tsig.name)
        s.item("action", "[transfer, notify, update]")

        s.id_item("id", "acl_test")
        s.item_str("address", Context().test.addr)
        if self.tsig_test:
            s.item_str("key", self.tsig_test.name)
        s.item("action", "[transfer, notify, update]")

        servers = set() # Duplicity check.
        for zone in sorted(self.zones):
            z = self.zones[zone]
            for master in z.masters:
                if master.name not in servers:
                    s.id_item("id", "acl_%s" % master.name)
                    s.item_str("address", master.addr)
                    if master.tsig:
                        s.item_str("key", master.tsig.name)
                    s.item("action", "notify")
                    servers.add(master.name)
            for slave in z.slaves:
                if slave.name in servers:
                    continue
                s.id_item("id", "acl_%s" % slave.name)
                s.item_str("address", slave.addr)
                if slave.tsig:
                    s.item_str("key", slave.tsig.name)
                s.item("action", "transfer")
                servers.add(slave.name)
        s.end()

        if len(self.modules) > 0:
            for module in self.modules:
                module.get_conf(s)

        for zone in sorted(self.zones):
            z = self.zones[zone]
            if len(z.modules) > 0:
                for module in z.modules:
                    module.get_conf(s)

        have_sbm = False
        for zone in sorted(self.zones):
            z = self.zones[zone]
            if not z.dnssec.enable:
                continue
            if len(z.dnssec.ksk_sbm_check) < 1 and z.dnssec.ksk_sbm_timeout is None:
                continue
            if not have_sbm:
                s.begin("submission")
                have_sbm = True
            s.id_item("id", z.name)
            parents = ""
            for parent in z.dnssec.ksk_sbm_check:
                if parents:
                    parents += ", "
                parents += parent.name
            if parents != "":
                s.item("parent", "[%s]" % parents)
            self._str(s, "check-interval", z.dnssec.ksk_sbm_check_interval)
            if z.dnssec.ksk_sbm_timeout is not None:
                self._str(s, "timeout", z.dnssec.ksk_sbm_timeout)
        if have_sbm:
            s.end()

        have_policy = False
        for zone in sorted(self.zones):
            z = self.zones[zone]
            if not z.dnssec.enable:
                continue

            if (z.dnssec.shared_policy_with or z.name) != z.name:
                continue

            if not have_policy:
                s.begin("policy")
                have_policy = True
            s.id_item("id", z.name)
            self._bool(s, "manual", z.dnssec.manual)
            self._bool(s, "single-type-signing", z.dnssec.single_type_signing)
            self._str(s, "algorithm", z.dnssec.alg)
            self._str(s, "ksk_size", z.dnssec.ksk_size)
            self._str(s, "zsk_size", z.dnssec.zsk_size)
            self._str(s, "dnskey-ttl", z.dnssec.dnskey_ttl)
            self._str(s, "zone-max-ttl", z.dnssec.zone_max_ttl)
            self._str(s, "ksk-lifetime", z.dnssec.ksk_lifetime)
            self._str(s, "zsk-lifetime", z.dnssec.zsk_lifetime)
            self._str(s, "delete-delay", z.dnssec.delete_delay)
            self._str(s, "propagation-delay", z.dnssec.propagation_delay)
            self._str(s, "rrsig-lifetime", z.dnssec.rrsig_lifetime)
            self._str(s, "rrsig-refresh", z.dnssec.rrsig_refresh)
            self._str(s, "rrsig-pre-refresh", z.dnssec.rrsig_prerefresh)
            self._str(s, "reproducible-signing", z.dnssec.repro_sign)
            self._bool(s, "nsec3", z.dnssec.nsec3)
            self._str(s, "nsec3-iterations", z.dnssec.nsec3_iters)
            self._bool(s, "nsec3-opt-out", z.dnssec.nsec3_opt_out)
            self._str(s, "nsec3-salt-lifetime", z.dnssec.nsec3_salt_lifetime)
            self._str(s, "nsec3-salt-length", z.dnssec.nsec3_salt_len)
            if len(z.dnssec.ksk_sbm_check) > 0 or z.dnssec.ksk_sbm_timeout is not None:
                s.item("ksk-submission", z.name)
            if z.dnssec.ds_push:
                self._str(s, "ds-push", z.dnssec.ds_push.name)
            self._bool(s, "ksk-shared", z.dnssec.ksk_shared)
            self._str(s, "cds-cdnskey-publish", z.dnssec.cds_publish)
            if z.dnssec.cds_digesttype:
                self._str(s, "cds-digest-type", z.dnssec.cds_digesttype)
            self._str(s, "offline-ksk", z.dnssec.offline_ksk)
            self._str(s, "signing-threads", str(random.randint(1,4)))
        if have_policy:
            s.end()

        s.begin("database")
        s.item_str("storage", self.dir)
        s.item_str("kasp-db", self.keydir)
        s.item_str("kasp-db-max-size", self.kasp_db_size)
        s.item_str("journal-db-max-size", self.journal_db_size)
        s.item_str("timer-db-max-size", self.timer_db_size)
        s.item_str("catalog-db-max-size", self.catalog_db_size)
        s.end()

        s.begin("template")
        s.id_item("id", "default")
        s.item_str("storage", self.dir)
        s.item_str("zonefile-sync", self.zonefile_sync)
        if self.zonemd_verify:
            s.item_str("zonemd-verify", "on")
        if self.zonemd_generate is not None:
            s.item_str("zonemd-generate", self.zonemd_generate)
        s.item_str("journal-max-usage", self.journal_max_usage)
        s.item_str("adjust-threads", str(random.randint(1,4)))
        s.item_str("semantic-checks", "on" if self.semantic_check else "off")
        if len(self.modules) > 0:
            modules = ""
            for module in self.modules:
                if modules:
                    modules += ", "
                modules += module.get_conf_ref()
            s.item("global-module", "[%s]" % modules)
        if self.zone_size_limit:
            s.item("zone-max-size", self.zone_size_limit)

        have_catalog = None
        for zone in self.zones:
            z = self.zones[zone]
            if z.catalog:
                have_catalog = z
        if have_catalog is not None:
            s.id_item("id", "catalog-default")
            s.item_str("file", self.dir + "/master/%s.zone")
            s.item_str("zonefile-load", "difference")
            s.item_str("journal-content", z.journal_content)

            # this is weird but for the sake of testing, the cataloged zones inherit dnssec policy from catalog zone
            if z.dnssec.enable:
                s.item_str("dnssec-signing", "off" if z.dnssec.disable else "on")
                s.item_str("dnssec-policy", z.name)
            for module in z.modules:
                if module.conf_name == "mod-onlinesign":
                    s.item("module", "[%s]" % module.get_conf_ref())

            self.config_xfr(z, s)

            s.id_item("id", "catalog-signed")
            s.item_str("file", self.dir + "/master/%s.zone")
            s.item_str("journal-content", z.journal_content)
            s.item_str("dnssec-signing", "on")
            self.config_xfr(z, s)

            s.id_item("id", "catalog-unsigned")
            s.item_str("file", self.dir + "/master/%s.zone")
            s.item_str("journal-content", z.journal_content)
            self.config_xfr(z, s)

        s.end()

        s.begin("zone")
        for zone in sorted(self.zones):
            z = self.zones[zone]
            s.id_item("domain", z.name)
            s.item_str("file", z.zfile.path)

            self.config_xfr(z, s)

            if self.serial_policy is not None:
                s.item_str("serial-policy", self.serial_policy)

            s.item_str("journal-content", z.journal_content)

            if self.zonefile_load is not None:
                s.item_str("zonefile-load", self.zonefile_load)
            elif z.ixfr:
                s.item_str("zonefile-load", "difference")

            if z.catalog_zone == z:
                s.item_str("catalog-role", "generate")
            elif z.catalog_zone is not None:
                s.item_str("catalog-role", "member")
                s.item_str("catalog-zone", z.catalog_zone.name)

            if z.dnssec.enable:
                s.item_str("dnssec-signing", "off" if z.dnssec.disable else "on")
                s.item_str("dnssec-policy", z.dnssec.shared_policy_with or z.name)

            if z.catalog:
                s.item_str("catalog-role", "interpret")
                s.item("catalog-template", "[ catalog-default, catalog-signed, catalog-unsigned ]")

            if z.catalog_group is not None:
                s.item_str("catalog-group", z.catalog_group)

            if z.dnssec.validate:
                s.item_str("dnssec-validation", "on")

            if len(z.modules) > 0:
                modules = ""
                for module in z.modules:
                    if modules:
                        modules += ", "
                    modules += module.get_conf_ref()
                s.item("module", "[%s]" % modules)
        s.end()

        s.begin("log")
        s.id_item("target", "stdout")
        s.item_str("any", "debug")
        s.end()

        self.start_params = ["-c", self.confile]
        self.ctl_params = ["-c", self.confile, "-t", "15"]
        if self.ctl_params_append != None:
            self.ctl_params += self.ctl_params_append

        return s.conf

class Dummy(Server):
    ''' Dummy name server. '''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.daemon_bin = None
        self.control_bin = None
        self.control_wait = []
        self.binding_fail = "There won't be such a message"
        self.pidfile = None

    def get_config(self):
        return ''

    def start(self, clean=None):
        return True

    def listening(self):
        return True # Fake listening

    def wait_function(self, wait=False):
        pass

    def running(self):
        return True # Fake running
