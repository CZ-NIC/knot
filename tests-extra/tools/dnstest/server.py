#!/usr/bin/env python3

import inspect
import re
import random
import shutil
import socket
import time
import dns.message
import dns.query
import dns.update
from subprocess import Popen, PIPE, DEVNULL, check_call
from dnstest.utils import *
import dnstest.params as params
import dnstest.keys
import dnstest.response
import dnstest.update

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

    def __init__(self, zone_file=None, ddns=False):
        self.zfile = zone_file
        self.master = None
        self.slaves = set()
        # True: DDNS, False on master: ixfrFromDiff, False on slave: empty
        self.ddns = ddns

    @property
    def name(self):
        return self.zfile.name

class Server(object):
    '''Specification of DNS server'''

    START_WAIT = 2
    START_WAIT_VALGRIND = 5
    STOP_TIMEOUT = 60
    COMPILE_TIMEOUT = 60
    DIG_TIMEOUT = 15

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

        self.ratelimit = None

        self.ip = None
        self.addr = None
        self.port = None
        self.ctlport = None
        self.ctlkey = None
        self.ctlkeyfile = None
        self.tsig = None

        self.zones = dict()

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

        proc = Popen(["lsof", "-t", "-i", iface],
                     stdout=PIPE, stderr=PIPE, universal_newlines=True)
        (out, err) = proc.communicate()

        # Create list of pids excluding last empty line.
        pids = list(filter(None, out.split("\n")))

        # Check for successful bind.
        if str(self.proc.pid) not in pids:
            return False

        # More binded processes is not acceptable too.
        if len(pids) > 1:
            return False

        return True

    def set_master(self, zone, slave=None, ddns=False):
        '''Set the server as a master for the zone'''

        if zone.name not in self.zones:
            master_file = zone.clone(self.dir + "/master")
            z = Zone(master_file, ddns)
            self.zones[zone.name] = z
        else:
            z = self.zones[zone.name]

        if slave:
            z.slaves.add(slave)

    def set_slave(self, zone, master, ddns=False):
        '''Set the server as a slave for the zone'''

        if zone.name in self.zones:
            raise Exception("Can't set zone %s as a slave" % name)

        slave_file = zone.clone(self.dir + "/slave", exists=False)
        z = Zone(slave_file, ddns)
        z.master = master
        self.zones[zone.name] = z

    def compile(self):
        try:
            p = Popen([self.control_bin] + self.compile_params,
                      stdout=self.fout, stderr=self.ferr)
            p.communicate(timeout=Server.COMPILE_TIMEOUT)
        except:
            err("Compile error")

    def start(self):
        try:
            fout = open(self.fout, mode="w")
            ferr = open(self.ferr, mode="w")

            if self.compile_params:
                self.compile()

            if self.daemon_bin != None:
                self.proc = Popen(self.valgrind + [self.daemon_bin] + \
                                  self.start_params, stdout=fout, stderr=ferr)

            if self.valgrind:
                time.sleep(Server.START_WAIT_VALGRIND)
            else:
                time.sleep(Server.START_WAIT)
        except OSError:
            err("Server %s start error" % self.name)

    def reload(self):
        try:
            check_call([self.control_bin] + self.reload_params, \
                       stdout=DEVNULL, stderr=DEVNULL)
            time.sleep(Server.START_WAIT)
        except OSError:
            err("Server %s reload error" % self.name)

    def flush(self):
        try:
            if self.flush_params:
                check_call([self.control_bin] + self.flush_params, \
                           stdout=DEVNULL, stderr=DEVNULL)
                time.sleep(Server.START_WAIT)
        except OSError:
            err("Server %s flush error" % self.name)

    def _valgrind_check(self):
        if not self.valgrind:
            return

        errcount = 0
        reachable = -32
        lost = 0

        f = open(self.ferr, "r")
        for line in f:
            if re.search("Process terminating", line) or \
               re.search("Invalid read", line) or \
               re.search("Invalid write", line) or \
               re.search("Assertion", line):
                  errcount += 1

            lost_line = re.search("lost:", line)
            if lost_line:
                lost += int(line[lost_line.end():].lstrip(). \
                            split(" ")[0].replace(",", ""))

            reach_line = re.search("reachable:", line)
            if reach_line:
                reachable += int(line[reach_line.end():].lstrip(). \
                                 split(" ")[0].replace(",", ""))
        f.close()

        if errcount > 0 or reachable > 0 or lost > 0:
            err("%s memcheck: lost(%i B), reachable(%i B), errcount(%i)" \
                % (self.name, lost, reachable, errcount))
            set_err("VALGRIND")

    def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(Server.STOP_TIMEOUT)
            except ProcessLookupError:
                pass
            except:
                err("killing")
                self.proc.kill()

    def gen_confile(self):
        f = open(self.confile, mode="w")
        f.write(self.get_config())
        f.close

    def dig(self, rname, rtype, rclass="IN", udp=None, serial=None, \
            timeout=None, tries=3, recursion=False, bufsize=None, \
            nsid=False, dnssec=False):
        key_params = self.tsig.key_params if self.tsig else dict()

        # Convert one item zone list to zone name.
        if isinstance(rname, list):
            if len(rname) != 1:
                raise Exception("One zone required.")
            rname = rname[0].name

        if timeout is None:
            timeout = self.DIG_TIMEOUT
        if rtype.upper() == "AXFR":
            # Always use TCP.
            udp = False
        elif rtype.upper() == "IXFR":
            # Use TCP if not specified.
            udp = udp if udp != None else False
        else:
            # Use TCP or UDP at random if not specified.
            udp = udp if udp != None else random.choice([True, False])

        # Store function arguments for possible comparation.
        args = dict()
        params = inspect.getargvalues(inspect.currentframe())
        for param in params.args:
            if param != "self":
                args[param] = params.locals[param]

        check_log("DIG %s %s %s @%s -p %i %s" % \
                  (rname, rtype, rclass, self.addr, self.port, \
                  "+notcp" if udp else "+tcp"))

        for t in range(tries):
            try:
                if rtype.upper() == "AXFR":
                    resp = dns.query.xfr(self.addr, rname, rtype, rclass, \
                                         port=self.port, lifetime=timeout, \
                                         use_udp=udp, **key_params)
                elif rtype.upper() == "IXFR":
                    resp = dns.query.xfr(self.addr, rname, rtype, rclass, \
                                         port=self.port, lifetime=timeout, \
                                         use_udp=udp, serial=int(serial), \
                                         **key_params)
                else:
                    query = dns.message.make_query(rname, rtype, rclass)

                    # Set query.
                    if not recursion:
                        # Remove RD bit which is a default.
                        query.flags &= ~dns.flags.RD
                    if nsid or bufsize:
                        class NsidFix(object):
                            '''Current pythondns doesn't implement this'''
                            def __init__(self):
                                self.otype = dns.edns.NSID
                            def to_wire(self, file=None):
                                pass

                        payload = int(bufsize) if bufsize else 1280
                        options = [NsidFix()] if nsid else None
                        query.use_edns(edns=0, payload=payload, options=options)
                    if dnssec:
                        query.want_dnssec()

                    # Send query.
                    if udp:
                        resp = dns.query.udp(query, self.addr, port=self.port, \
                                             timeout=timeout)
                    else:
                        resp = dns.query.tcp(query, self.addr, port=self.port, \
                                             timeout=timeout)

                detail_log(SEP)
                return dnstest.response.Response(self, resp, args)
            except:
                time.sleep(timeout)

        raise Exception("Can't query %s for %s %s %s." % \
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
            raise Exception("Can't send RAW data (%d bytes) to %s." % \
                            (len(data), self.name))

    def zone_wait(self, zone, serial=None):
        '''Try to get SOA record with serial higher then specified'''

        # Convert one item list to single object.
        if isinstance(zone, list):
            if len(zone) != 1:
                raise Exception("One zone required.")
            zone = zone[0]

        _serial = 0

        for t in range(20):
            resp = self.dig(zone.name, "SOA", udp=True, tries=1)
            if resp.resp.rcode() == 0:
                soa = str((resp.resp.answer[0]).to_rdataset())
                _serial = int(soa.split()[5])
                if serial:
                    if serial < _serial:
                        break
                else:
                    break
            time.sleep(2)
        else:
            raise Exception("Can't get %s SOA%s from %s." % (zone.name,
                            ">%i" % serial if serial else "", self.name))

        return _serial

    def zones_wait(self, zone_list):
        for zone in zone_list:
            self.zone_wait(zone)

    def zone_verify(self, zone):
        # Convert one item list to single object.
        if isinstance(zone, list):
            if len(zone) != 1:
                raise Exception("One zone required.")
            zone = zone[0]

        self.zones[zone.name].zfile.dnssec_verify()

    def update(self, zone):
        # Convert one item list to single object.
        if isinstance(zone, list):
            if len(zone) != 1:
                raise Exception("One zone required.")
            zone = zone[0]

        key_params = self.tsig.key_params if self.tsig else dict()

        return dnstest.update.Update(self, dns.update.Update(zone.name,
                                                             **key_params))

    def gen_key(self, zone, **args):
        # Convert one item list to single object.
        if isinstance(zone, list):
            if len(zone) != 1:
                raise Exception("One zone required.")
            zone = zone[0]

        try:
            os.makedirs(self.keydir)
        except OSError:
            if not os.path.isdir(self.keydir):
                raise Exception("Can't create key directory %s" % self.keydir)

        key = dnstest.keys.Key(self.keydir, zone.name, **args)
        key.generate()

        return key

    def enable_nsec3(self, zone, **args):
        # Convert one item list to single object.
        if isinstance(zone, list):
            if len(zone) != 1:
                raise Exception("One zone required.")
            zone = zone[0]

        self.zones[zone.name].zfile.enable_nsec3(**args)

    def disable_nsec3(self, zone):
        # Convert one item list to single object.
        if isinstance(zone, list):
            if len(zone) != 1:
                raise Exception("One zone required.")
            zone = zone[0]

        self.zones[zone.name].zfile.disable_nsec3()

class Bind(Server):

    def __init__(self):
        super().__init__()
        if not params.bind_bin:
            raise Skip("No Bind")
        self.daemon_bin = params.bind_bin
        self.control_bin = params.bind_ctl
        self.ctlkey = dnstest.keys.Tsig(alg="hmac-md5")

    def running(self):
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

            keys = set() # Duplicy check.
            for zone in sorted(self.zones):
                z = self.zones[zone]
                if z.master and z.master.tsig.name not in keys:
                    t = z.master.tsig
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
            if z.master:
                s.item("type", "slave")

                if self.tsig:
                    s.item("allow-notify", "{ key %s; }" % z.master.tsig.name)
                    s.item("masters", "{ %s port %i key %s; }" \
                           % (z.master.addr, z.master.port, z.master.tsig.name))
                else:
                    s.item("allow-notify", "{ %s; }" % z.master.addr)
                    s.item("masters", "{ %s port %i; }" \
                           % (z.master.addr, z.master.port))
            else:
                s.item("type", "master")
                s.item("notify", "explicit")

                if not z.ddns:
                    s.item("ixfr-from-differences", "yes")

            # Init update list with the default local server.
            slaves_upd = ""
            if self.tsig:
                slaves_upd += "key %s; " % self.tsig.name
            else:
                slaves_upd += "%s; " % self.addr

            if z.slaves:
                slaves = ""
                for slave in z.slaves:
                    if self.tsig:
                        slaves += "%s port %i key %s; " \
                                  % (slave.addr, slave.port, slave.tsig.name)
                        slaves_upd += "key %s; " % slave.tsig.name
                    else:
                        slaves += "%s port %i; " % (slave.addr, slave.port)
                        slaves_upd += "%s; " % slave.addr
                s.item("also-notify", "{ %s}" % slaves)

            if z.ddns:
                if z.master:
                    s.item("allow-update-forwarding", "{ %s}" % slaves_upd)
                else:
                    s.item("allow-update", "{ %s}" % slaves_upd)

            if self.tsig:
                s.item("allow-transfer", "{ key %s; }" % self.tsig.name)
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

    def __init__(self):
        super().__init__()
        if not params.knot_bin:
            raise Skip("No Knot")
        self.daemon_bin = params.knot_bin
        self.control_bin = params.knot_ctl

    @property
    def keydir(self):
        return os.path.join(self.dir, "keys")

    def running(self):
        tcp = super()._check_socket("tcp", self.port)
        udp = super()._check_socket("udp", self.port)
        return (tcp and udp)

    def _on_str_hex(self, conf, name, value):
        if value == True:
            conf.item(name, "on")
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

            keys = set() # Duplicy check.
            for zone in sorted(self.zones):
                z = self.zones[zone]
                if z.master and z.master.tsig.name not in keys:
                    t = z.master.tsig
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

        servers = set() # Duplicity check.
        for zone in sorted(self.zones):
            z = self.zones[zone]
            if z.master and z.master.name not in servers:
                s.begin(z.master.name)
                s.item("address", z.master.addr)
                s.item("port", z.master.port)
                if z.master.tsig:
                    s.item_str("key", z.master.tsig.name)
                s.end()
                servers.add(z.master.name)
            for slave in z.slaves:
                if slave.name not in servers:
                    s.begin(slave.name)
                    s.item("address", slave.addr)
                    s.item("port", slave.port)
                    if slave.tsig:
                        s.item_str("key", slave.tsig.name)
                    s.end()
                    servers.add(slave.name)
        s.end()

        s.begin("zones")
        s.item_str("storage", self.dir)
        s.item("zonefile-sync", "5s")
        s.item("notify-timeout", "5")
        s.item("notify-retries", "5")
        if self.dnssec_enable:
            s.item_str("dnssec-keydir", self.keydir)
            s.item("dnssec-enable", "on")
        for zone in sorted(self.zones):
            z = self.zones[zone]
            s.begin(z.name)
            s.item_str("file", z.zfile.path)

            if z.master:
                s.item("notify-in", z.master.name)
                s.item("xfr-in", z.master.name)

            slaves = ""
            if z.slaves:
                for slave in z.slaves:
                    if slaves:
                        slaves += ", "
                    slaves += slave.name
                s.item("notify-out", slaves)

            s.item("xfr-out", "local")

            if z.ddns:
                all_slaves = "local" if not slaves else slaves + ", local"
                s.item("update-in", all_slaves)
            elif not z.master:
                s.item("ixfr-from-differences", "on")
            s.end()
        s.end()

        s.begin("log")
        s.begin("stdout")
        s.item("any", "all")
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

class Nsd(Server):

    def __init__(self):
        super().__init__()
        if not params.nsd_bin:
            raise Skip("No NSD")
        self.daemon_bin = params.nsd_bin
        self.control_bin = params.nsd_ctl

    def get_config(self):
        self.start_params = ["-c", self.confile, "-d"]
        self.compile_params = ["-c", self.confile, "rebuild"]

class Dummy(Server):
    ''' Dummy name server. '''

    def __init__(self):
        super().__init__()
        self.daemon_bin = None
        self.control_bin = None

    def get_config(self):
        return ''

    def start(self):
        return True

    def running(self):
        return True # Fake running
