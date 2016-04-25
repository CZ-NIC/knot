#!/usr/bin/env python3

import glob
import inspect
import psutil
import re
import random
import shutil
import socket
import time
import dns.message
import dns.query
import dns.update
from subprocess import Popen, PIPE, check_call, CalledProcessError
from dnstest.utils import *
import dnstest.inquirer
import dnstest.params as params
import dnstest.keys
import dnstest.response
import dnstest.update

def zone_arg_check(zone):
    # Convert one item list to single object.
    if isinstance(zone, list):
        if len(zone) != 1:
            raise Failed("One zone required")
        return zone[0]
    return zone

class KnotConf(object):
    '''Knot server config generator'''

    def __init__(self):
        self.conf = ""
        self.indent = ""

    def sub(self):
        self.indent += "\t"

    def unsub(self):
        self.indent = self.indent[:-1]

    def begin(self, name):
        self.conf += "%s%s {\n" % (self.indent, name)
        self.sub()

    def end(self):
        self.unsub()
        self.conf += "%s}\n" % (self.indent)
        if not self.indent:
            self.conf += "\n"

    def item(self, name, value):
        self.conf += "%s%s %s;\n" % (self.indent, name, value)

    def item_str(self, name, value):
        self.conf += "%s%s \"%s\";\n" % (self.indent, name, value)

class BindConf(object):
    '''Bind server config generator'''

    def __init__(self):
        self.conf = ""
        self.indent = ""

    def sub(self):
        self.indent += "\t"

    def unsub(self):
        self.indent = self.indent[:-1]

    def begin(self, name, string=None):
        if string:
            self.conf += "%s%s \"%s\" {\n" % (self.indent, name, string)
        else:
            self.conf += "%s%s {\n" % (self.indent, name)
        self.sub()

    def end(self):
        self.unsub()
        self.conf += "%s};\n" % (self.indent)
        if not self.indent:
            self.conf += "\n"

    def item(self, name, value=None):
        if value:
            self.conf += "%s%s %s;\n" % (self.indent, name, value)
        else:
            self.conf += "%s%s;\n" % (self.indent, name)

    def item_str(self, name, value):
        self.conf += "%s%s \"%s\";\n" % (self.indent, name, value)

class Zone(object):
    '''DNS zone description'''

    def __init__(self, zone_file, ddns=False, ixfr=False):
        self.zfile = zone_file
        self.masters = set()
        self.slaves = set()
        self.ddns = ddns
        # ixfr from differences
        self.ixfr = ixfr
        # modules
        self.query_modules = []

    @property
    def name(self):
        return self.zfile.name

    def add_query_module(self, module, param):
        self.query_modules.append((module, param))

    def disable_master(self, new_zone_file):
        self.zfile.remove()
        self.zfile = new_zone_file
        self.ixfr = False

class Server(object):
    '''Specification of DNS server'''

    START_WAIT = 2
    START_WAIT_VALGRIND = 5
    STOP_TIMEOUT = 30
    COMPILE_TIMEOUT = 60
    DIG_TIMEOUT = 5

    # Instance counter.
    count = 0

    def __init__(self):
        self.proc = None
        self.valgrind = []
        self.start_params = None
        self.reload_params = None
        self.flush_params = None
        self.compile_params = None

        self.data_dir = None

        self.dnssec_enable = None

        self.nsid = None
        self.ident = None
        self.version = None

        self.ip = None
        self.addr = None
        self.port = None
        self.ctlport = None
        self.ctlkey = None
        self.ctlkeyfile = None
        self.tsig = None
        self.tsig_test = None

        self.zones = dict()

        self.ratelimit = None
        self.disable_any = None
        self.disable_notify = None
        self.max_conn_idle = None
        self.zonefile_sync = None
        self.ixfr_fslimit = None

        self.inquirer = None

        # Working directory.
        self.dir = None
        # Name of server instance.
        self.name = None
        self.fout = None
        self.ferr = None
        self.conffile = None

    def _check_socket(self, proto, port):
        if self.ip == 4:
            iface = "%i%s@%s:%i" % (self.ip, proto, self.addr, port)
        else:
            iface = "%i%s@[%s]:%i" % (self.ip, proto, self.addr, port)

        for i in range(5):
            proc = Popen(["lsof", "-t", "-i", iface],
                         stdout=PIPE, stderr=PIPE, universal_newlines=True)
            (out, err) = proc.communicate()

            # Create list of pids excluding last empty line.
            pids = list(filter(None, out.split("\n")))

            # Check for successful bind.
            if len(pids) == 1 and str(self.proc.pid) in pids:
                return True

            time.sleep(1)

        return False

    def set_master(self, zone, slave=None, ddns=False, ixfr=False):
        '''Set the server as a master for the zone'''

        if zone.name not in self.zones:
            master_file = zone.clone(self.dir + "/master")
            z = Zone(master_file, ddns, ixfr)
            self.zones[zone.name] = z
        else:
            z = self.zones[zone.name]

        if slave:
            z.slaves.add(slave)

    def set_slave(self, zone, master, ddns=False, ixfr=False):
        '''Set the server as a slave for the zone'''

        slave_file = zone.clone(self.dir + "/slave", exists=False)

        if zone.name not in self.zones:
            z = Zone(slave_file, ddns, ixfr)
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

    def start(self, clean=False):
        mode = "w" if clean else "a"

        try:
            if self.compile_params:
                self.compile()

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
        if params.test.stress and self.inquirer:
            self.inquirer.start(self)

    def reload(self):
        try:
            check_call([self.control_bin] + self.reload_params,
                       stdout=open(self.dir + "/call.out", mode="a"),
                       stderr=open(self.dir + "/call.err", mode="a"))
            time.sleep(Server.START_WAIT)
        except CalledProcessError as e:
            self.backtrace()
            raise Failed("Can't reload server='%s', ret='%i'" %
                         (self.name, e.returncode))

    def flush(self):
        try:
            check_call([self.control_bin] + self.flush_params,
                       stdout=open(self.dir + "/call.out", mode="a"),
                       stderr=open(self.dir + "/call.err", mode="a"))
            time.sleep(Server.START_WAIT)
        except CalledProcessError as e:
            self.backtrace()
            raise Failed("Can't flush server='%s', ret='%i'" %
                         (self.name, e.returncode))

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
            f = open(self.ferr, "r")
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

                    if lost > 0 or reachable > 960 or errcount > 0:
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

        if self.inquirer:
            self.inquirer.stop()

    def kill(self):
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

        if self.inquirer:
            self.inquirer.stop()

    def gen_confile(self):
        f = open(self.confile, mode="w")
        f.write(self.get_config())
        f.close()

    def dig(self, rname, rtype, rclass="IN", udp=None, serial=None,
            timeout=None, tries=3, flags="", bufsize=None, edns=None,
            nsid=False, dnssec=False, log_no_sep=False):
        key_params = self.tsig_test.key_params if self.tsig_test else dict()

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

        # Set EDNS.
        if edns != None or bufsize or nsid:
            class NsidFix(object):
                '''Current pythondns doesn't implement NSID option.'''
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
                payload = 1280
            dig_flags += " +bufsize=%i" % payload

            if nsid:
                options = [NsidFix()]
                dig_flags += " +nsid"
            else:
                options = None

            query.use_edns(edns=edns, payload=payload, options=options)

        # Set DO flag.
        if dnssec:
            query.want_dnssec()
            dig_flags += " +dnssec +bufsize=%i" % query.payload

        # Store function arguments for possible comparation.
        args = dict()
        params = inspect.getargvalues(inspect.currentframe())
        for param in params.args:
            if param != "self":
                args[param] = params.locals[param]

        check_log("DIG %s %s %s @%s -p %i %s" %
                  (rname, rtype_str, rclass, self.addr, self.port, dig_flags))
        if key_params:
            detail_log("%s:%s:%s" %
                (self.tsig_test.alg, self.tsig_test.name, self.tsig_test.key))

        for t in range(tries):
            try:
                if rtype.upper() == "AXFR":
                    resp = dns.query.xfr(self.addr, rname, rtype, rclass,
                                         port=self.port, lifetime=timeout,
                                         use_udp=udp, **key_params)
                elif rtype.upper() == "IXFR":
                    resp = dns.query.xfr(self.addr, rname, rtype, rclass,
                                         port=self.port, lifetime=timeout,
                                         use_udp=udp, serial=int(serial),
                                         **key_params)
                elif udp:
                    resp = dns.query.udp(query, self.addr, port=self.port,
                                         timeout=timeout)
                else:
                    resp = dns.query.tcp(query, self.addr, port=self.port,
                                         timeout=timeout)

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
        if self.ip == 6:
            family = socket.AF_INET6
        return socket.socket(family, socket_type)

    def send_raw(self, data, sock=None):
        if sock is None:
            sock = self.create_sock(socket.SOCK_DGRAM)
        sent = sock.sendto(bytes(data, 'utf-8'), (self.addr, self.port))
        if sent != len(data):
            raise Failed("Can't send RAW data (%d bytes) to server='%s'" %
                         (len(data), self.name))

    def zone_wait(self, zone, serial=None):
        '''Try to get SOA record with serial higher then specified'''

        zone = zone_arg_check(zone)

        _serial = 0

        check_log("ZONE WAIT %s: %s" % (self.name, zone.name))

        for t in range(60):
            try:
                resp = self.dig(zone.name, "SOA", udp=True, tries=1,
                                timeout=2, log_no_sep=True)
            except:
                pass
            else:
                if resp.resp.rcode() == 0:
                    if not resp.resp.answer:
                        raise Failed("No SOA in ANSWER, zone='%s', server='%s'" %
                                     (zone.name, self.name))

                    soa = str((resp.resp.answer[0]).to_rdataset())
                    _serial = int(soa.split()[5])

                    if serial:
                        if serial < _serial:
                            break
                    else:
                        break
            time.sleep(2)
        else:
            self.backtrace()
            raise Failed("Can't get SOA%s, zone='%s', server='%s'" %
                         (" serial > %i" % serial if serial else "",
                          zone.name, self.name))

        detail_log(SEP)

        return _serial

    def zones_wait(self, zone_list, serials=None):
        new_serials = dict()

        for zone in zone_list:
            old_serial = serials[zone.name] if serials else None
            new_serial = self.zone_wait(zone, serial=old_serial)
            new_serials[zone.name] = new_serial

        return new_serials

    def zone_verify(self, zone):
        zone = zone_arg_check(zone)

        self.zones[zone.name].zfile.dnssec_verify()

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

        prepare_dir(self.keydir)
        key = dnstest.keys.Key(self.keydir, zone.name, **args)
        key.generate()

        return key

    def use_keys(self, zone):
        zone = zone_arg_check(zone)

        # Copy generated keys to server key directory.
        prepare_dir(self.keydir)

        src_files = os.listdir(zone.key_dir)
        for file_name in src_files:
            if (zone.name[:-1]).lower() in file_name:
                full_file_name = os.path.join(zone.key_dir, file_name)
                if (os.path.isfile(full_file_name)):
                    shutil.copy(full_file_name, self.keydir)

    def enable_nsec3(self, zone, **args):
        zone = zone_arg_check(zone)

        self.zones[zone.name].zfile.enable_nsec3(**args)

    def disable_nsec3(self, zone):
        zone = zone_arg_check(zone)

        self.zones[zone.name].zfile.disable_nsec3()

    def backup_zone(self, zone):
        zone = zone_arg_check(zone)

        self.zones[zone.name].zfile.backup()

    def update_zonefile(self, zone, version=None, random=False):
        zone = zone_arg_check(zone)

        if random:
            self.zones[zone.name].zfile.update_rnd()
        else:
            self.zones[zone.name].zfile.upd_file(storage=self.data_dir,
                                                 version=version)

    def add_query_module(self, zone, module, param):
        # Convert one item list to single object.
        if isinstance(zone, list):
            if len(zone) != 1:
                raise Failed("One zone required")
            zone = zone[0]

        self.zones[zone.name].add_query_module(module, param)

class Bind(Server):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not params.bind_bin:
            raise Skip("No Bind")
        self.daemon_bin = params.bind_bin
        self.control_bin = params.bind_ctl
        self.ctlkey = dnstest.keys.Tsig(alg="hmac-md5")

    def listening(self):
        tcp = super()._check_socket("tcp", self.port)
        udp = super()._check_socket("udp", self.port)
        ctltcp = super()._check_socket("tcp", self.ctlport)
        return (tcp and udp and ctltcp)

    def _str(self, conf, name, value):
        if value and value != True:
            conf.item_str(name, value)

    def get_config(self):
        s = BindConf()
        s.begin("options")
        self._str(s, "server-id", self.ident)
        self._str(s, "version", self.version)
        s.item_str("directory", self.dir)
        s.item_str("key-directory", self.dir)
        s.item_str("managed-keys-directory", self.dir)
        s.item_str("session-keyfile", self.dir + "/session.key")
        s.item_str("pid-file", "bind.pid")
        if self.ip == 4:
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
        s.end()

        s.begin("key", self.ctlkey.name)
        s.item("algorithm", self.ctlkey.alg)
        s.item_str("secret", self.ctlkey.key)
        s.end()

        s.begin("controls")
        s.item("inet %s port %i allow { %s; } keys { %s; }"
               % (self.addr, self.ctlport, self.addr, self.ctlkey.name))
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
                        masters_notify += "key %s; " % master.tsig.name
                        masters += "%s port %i key %s; " \
                                   % (master.addr, master.port, master.tsig.name)
                    else:
                        masters_notify += "%s; " % master.addr
                        masters += "%s port %i; " \
                                   % (master.addr, master.port)
                s.item("allow-notify", "{ %s}" % masters_notify)
                s.item("masters", "{ %s}" % masters)
            else:
                s.item("type", "master")
                s.item("notify", "explicit")

            if z.ixfr and not z.masters:
                s.item("ixfr-from-differences", "yes")

            if z.slaves:
                slaves = ""
                for slave in z.slaves:
                    if self.tsig:
                        slaves += "%s port %i key %s; " \
                                  % (slave.addr, slave.port, self.tsig.name)
                    else:
                        slaves += "%s port %i; " % (slave.addr, slave.port)
                s.item("also-notify", "{ %s}" % slaves)

            if z.ddns:
                if self.tsig:
                    upd = "key %s; " % self.tsig_test.name
                else:
                    upd = "%s; " % self.addr

                if z.masters:
                    s.item("allow-update-forwarding", "{ %s}" % upd)
                else:
                    s.item("allow-update", "{ %s}" % upd)

            if self.tsig:
                s.item("allow-transfer", "{ key %s; key %s; }" %
                       (self.tsig.name, self.tsig_test.name))
            else:
                s.item("allow-transfer", "{ %s; }" % self.addr)
            s.end()

        self.start_params = ["-c", self.confile, "-g"]
        self.reload_params = ["-s", self.addr, "-p", str(self.ctlport), \
                              "-k", self.ctlkeyfile, "reload"]
        self.flush_params = ["-s", self.addr, "-p", str(self.ctlport), \
                             "-k", self.ctlkeyfile, "flush"]

        return s.conf

class Knot(Server):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not params.knot_bin:
            raise Skip("No Knot")
        self.daemon_bin = params.knot_bin
        self.control_bin = params.knot_ctl
        self.inquirer = dnstest.inquirer.Inquirer()
        self.timer_db = None

    @property
    def keydir(self):
        return os.path.join(self.dir, "keys")

    def listening(self):
        tcp = super()._check_socket("tcp", self.port)
        udp = super()._check_socket("udp", self.port)
        return (tcp and udp)

    def _on_str_hex(self, conf, name, value):
        if value == True:
            conf.item(name, "on")
        elif value == False:
            conf.item(name, "off")
        elif value:
            if isinstance(value, int) or value[:2] == "0x":
                conf.item(name, value)
            else:
                conf.item_str(name, value)

    def get_config(self):
        s = KnotConf()
        s.begin("system")
        self._on_str_hex(s, "identity", self.ident)
        self._on_str_hex(s, "version", self.version)
        self._on_str_hex(s, "nsid", self.nsid)
        self._on_str_hex(s, "rate-limit", self.ratelimit)
        s.item_str("rundir", self.dir)
        if (self.max_conn_idle):
            s.item("max-conn-idle", self.max_conn_idle)
        s.end()

        s.begin("control")
        s.item_str("listen-on", "knot.sock")
        s.end()

        s.begin("interfaces")
        if self.ip == 4:
            s.begin("ipv4")
        else:
            s.begin("ipv6")
        s.item("address", self.addr)
        s.item("port", self.port)
        s.end()
        s.end()

        if self.tsig:
            s.begin("keys")
            t = self.tsig
            s.item_str("\"%s\" %s" % (t.name, t.alg), t.key)
            t = self.tsig_test
            s.item_str("\"%s\" %s" % (t.name, t.alg), t.key)

            keys = set() # Duplicy check.
            for zone in sorted(self.zones):
                z = self.zones[zone]
                for master in z.masters:
                    if master.tsig.name not in keys:
                        t = master.tsig
                        s.item_str("\"%s\" %s" % (t.name, t.alg), t.key)
                        keys.add(t.name)
                for slave in z.slaves:
                    if slave.tsig and slave.tsig.name not in keys:
                        t = slave.tsig
                        s.item_str("\"%s\" %s" % (t.name, t.alg), t.key)
                        keys.add(t.name)
            s.end()

        s.begin("remotes")
        s.begin("local")
        s.item("address", self.addr)
        if self.tsig:
            s.item_str("key", self.tsig.name)
        s.end()
        s.begin("test")
        s.item("address", self.addr)
        if self.tsig_test:
            s.item_str("key", self.tsig_test.name)
        s.end()

        servers = set() # Duplicity check.
        for zone in sorted(self.zones):
            z = self.zones[zone]
            for master in z.masters:
                if master.name not in servers:
                    s.begin(master.name)
                    s.item("address", master.addr)
                    s.item("port", master.port)
                    if master.tsig:
                        s.item_str("key", master.tsig.name)
                    s.end()
                    servers.add(master.name)
            for slave in z.slaves:
                if slave.name not in servers:
                    s.begin(slave.name)
                    s.item("address", slave.addr)
                    s.item("port", slave.port)
                    if slave.tsig:
                        s.item_str("key", self.tsig.name)
                    s.end()
                    servers.add(slave.name)
        s.end()

        s.begin("zones")
        s.item_str("storage", self.dir)
        if self.timer_db:
            s.item_str("timer-db", self.timer_db)
        if self.zonefile_sync:
            s.item("zonefile-sync", self.zonefile_sync)
        else:
            s.item("zonefile-sync", "1d")
        if self.ixfr_fslimit:
            s.item("ixfr-fslimit", self.ixfr_fslimit)
        s.item("notify-timeout", "5")
        s.item("notify-retries", "5")
        s.item("semantic-checks", "on")
        if self.disable_any:
            s.item("disable-any", "on")
        if self.dnssec_enable:
            s.item_str("dnssec-keydir", self.keydir)
            s.item("dnssec-enable", "on")
        for zone in sorted(self.zones):
            z = self.zones[zone]
            s.begin(z.name)
            s.item_str("file", z.zfile.path)

            if z.masters:
                masters = ""
                for master in z.masters:
                    if masters:
                        masters += ", "
                    masters += master.name
                if not self.disable_notify:
                    s.item("notify-in", masters)
                s.item("xfr-in", masters)

            if z.slaves:
                slaves = ""
                for slave in z.slaves:
                    if slaves:
                        slaves += ", "
                    slaves += slave.name
                s.item("notify-out", slaves)

            s.item("xfr-out", "local, test")

            if z.ddns:
                s.item("update-in", "test")

            if z.ixfr and not z.masters:
                s.item("ixfr-from-differences", "on")

            if len(z.query_modules) > 0:
                s.begin("query_module")
                for query_module in z.query_modules:
                    s.item(query_module[0], '"' + query_module[1] + '"')
                s.end()
            s.end()
        s.end()

        s.begin("log")
        s.begin("stdout")
        s.item("any", "debug")
        s.end()
        s.begin("stderr")
        s.end()
        s.begin("syslog")
        s.end()
        s.end()

        self.start_params = ["-c", self.confile]
        self.reload_params = ["-c", self.confile, "reload"]
        self.flush_params = ["-c", self.confile, "flush"]

        return s.conf

    def ctl(self, params):
        try:
            check_call([self.control_bin] + self.start_params + params.split(),
                       stdout=open(self.dir + "/call.out", mode="a"),
                       stderr=open(self.dir + "/call.err", mode="a"))
            time.sleep(Server.START_WAIT)
        except CalledProcessError as e:
            self.backtrace()
            raise Failed("Can't control='%s' server='%s', ret='%i'" %
                         (params, self.name, e.returncode))

class Nsd(Server):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not params.nsd_bin:
            raise Skip("No NSD")
        self.daemon_bin = params.nsd_bin
        self.control_bin = params.nsd_ctl

    def get_config(self):
        self.start_params = ["-c", self.confile, "-d"]
        self.compile_params = ["-c", self.confile, "rebuild"]

class Dummy(Server):
    ''' Dummy name server. '''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.daemon_bin = None
        self.control_bin = None

    def get_config(self):
        return ''

    def start(self, clean=None):
        return True

    def listening(self):
        return True # Fake listening

    def running(self):
        return True # Fake running
