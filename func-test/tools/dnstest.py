#!/usr/bin/env python3

import base64
import os
import random
import shutil
import socket
import string
import sys
import time
from subprocess import Popen, PIPE

knot_vars = [
    ["KNOT_TEST_KNOT",  "knotd"],
    ["KNOT_TEST_KNOTC", "knotc"]
]
bind_vars = [
    ["KNOT_TEST_BIND",  "named"],
    ["KNOT_TEST_BINDC", "rndc"]
]
nsd_vars = [
    ["KNOT_TEST_NSD",  "nsd"],
    ["KNOT_TEST_NSDC", "nsdc"]
]

class Tsig(object):
    '''TSIG key generator'''

    algs = {
        "hmac-md5":    16,
        "hmac-sha1":   20,
        "hmac-sha224": 28,
        "hmac-sha256": 32,
        "hmac-sha384": 48,
        "hmac-sha512": 64
    }

    vocabulary = string.ascii_uppercase + string.ascii_lowercase + \
                 string.digits

    def __init__(self):
        nlabels = random.randint(1, 10)

        self.name = ""
        for i in range(nlabels):
            label_len = random.randint(1, 63)

            # Check for maximal dname length (255 B = max fqdn in wire).
            # 255 = 1 leading byte + 253 + 1 trailing byte.
            if len(self.name) + 1 + label_len > 253:
                break

            # Add label separator.
            if i > 0:
                self.name += "."

            self.name += "".join(random.choice(Tsig.vocabulary)
                         for x in range(label_len))

        self.alg = random.choice(list(Tsig.algs.keys()))

        self.key = base64.b64encode(os.urandom(Tsig.algs[self.alg])).decode('ascii')

        self.tsig = self.alg + ":" + self.name + ":" + self.key

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
    ''' DNS zone description'''

    def __init__(self, name, filename, ddns=None):
        self.name = name
        self.filename = filename
        self.master = None
        self.slaves = set()
        # ddns: True - ddns, False - ixfrFromDiff, None - empty
        self.ddns = ddns

class DnsServer(object):
    '''Specification of DNS server'''

    START_WAIT = 2
    STOP_TIMEOUT = 10
    COMPILE_TIMEOUT = 60

    # Instance counter.
    count = 0

    def __init__(self):
        self.proc = None
        self.valgrind = []
        self.start_params = None
        self.compile_params = None

        self.nsid = None
        self.ident = None
        self.version = None

        self.ip = None
        self.addr = None
        self.port = None
        self.ctlport = None
        self.ctlkey = None
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

    def zone_master(self, name, file, slave=None, ddns=False):
        if name in self.zones:
            if slave:
                self.zones[name].slaves.add(slave)
        else:
            z = Zone(name, file, ddns)
            if slave:
                z.slaves.add(slave)
            self.zones[name] = z

    def zone_slave(self, name, file, master):
        if name in self.zones:
            raise Exception("Can't set zone %s as a slave" % name)
        else:
            slave_file = self.dir + "/" + name + "slave"
            z = Zone(name, slave_file, ddns=None)
            z.master = master
            self.zones[name] = z

    def find_binary(self, desc):
        explicit = os.environ.get(desc[0])
        if explicit:
            path = shutil.which(explicit)
        else:
            path = shutil.which(desc[1])

        if not path:
            raise Exception("No binary found")

        return path

    def set_paths(self, vars):
        self.daemon_bin = self.find_binary(vars[0])
        self.control_bin = self.find_binary(vars[1])

    def compile(self):
        try:
            p = Popen([self.control_bin] + self.compile_params,
                      stdout=self.fout, stderr=self.ferr)
            p.communicate(timeout=DnsServer.COMPILE_TIMEOUT)
        except:
            print("Compile error")

    def start(self):
        try:
            fout = open(self.fout, mode="w")
            ferr = open(self.ferr, mode="w")

            if self.compile_params:
                self.compile()

            self.proc = Popen(self.valgrind + [self.daemon_bin] + self.start_params,
                              stdout=fout, stderr=ferr)

            time.sleep(DnsServer.START_WAIT)
        except OSError:
            print("Server %s start error", self.name)

    def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(DnsServer.STOP_TIMEOUT)
            except TimeoutError:
                print("killing")
                self.proc.kill()

    def gen_confile(self):
        f = open(self.confile, "w")
        f.write(self.get_config())
        f.close

class Bind(DnsServer):

    def __init__(self):
        super().__init__()
        super().set_paths(bind_vars)

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
            for zone in self.zones:
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

        for zone in self.zones:
            z = self.zones[zone]
            s.begin("zone", z.name)
            s.item_str("file", z.filename)
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
                if z.ddns == True:
                    if self.tsig:
                        s.item("allow-update", "{ key %s; }" % self.tsig.name)
                    else:
                        s.item("allow-update", "{ %s; }" % self.addr)
                elif z.ddns == False:
                    s.item("ixfr-from-differences", "yes")

            if z.slaves:
                slaves = ""
                for slave in z.slaves:
                    if self.tsig:
                        slaves += "%s port %i key %s; " \
                                  % (slave.addr, slave.port, slave.tsig.name)
                    else:
                        slaves += "%s port %i; " % (slave.addr, slave.port)
                s.item("also-notify", "{ %s}" % slaves)

            if self.tsig:
                s.item("allow-transfer", "{ key %s; }" % self.tsig.name)
            else:
                s.item("allow-transfer", "{ %s; }" % self.addr)
            s.end()

        self.start_params = ["-c", self.confile, "-g"]

        return s.conf

class Knot(DnsServer):

    def __init__(self):
        super().__init__()
        super().set_paths(knot_vars)

    def running(self):
        tcp = super()._check_socket("tcp", self.port)
        udp = super()._check_socket("udp", self.port)
        return (tcp and udp)

    def _on_str_hex(self, conf, name, value):
        if value == True:
            conf.item(name, "on")
        elif value:
            if value[:2] == "0x":
                conf.item(name, value)
            else:
                conf.item_str(name, value)

    def get_config(self):
        s = KnotConf()
        s.begin("system")
        self._on_str_hex(s, "identity", self.ident)
        self._on_str_hex(s, "version", self.version)
        self._on_str_hex(s, "nsid", self.nsid)
        s.item_str("storage", self.dir)
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
            s.item_str("%s %s" % (t.name, t.alg), t.key)

            keys = set() # Duplicy check.
            for zone in self.zones:
                z = self.zones[zone]
                if z.master and z.master.tsig.name not in keys:
                    t = z.master.tsig
                    s.item_str("%s %s" % (t.name, t.alg), t.key)
                    keys.add(t.name)
                for slave in z.slaves:
                    if slave.tsig and slave.tsig.name not in keys:
                        t = slave.tsig
                        s.item_str("%s %s" % (t.name, t.alg), t.key)
                        keys.add(t.name)
            s.end()

        s.begin("remotes")
        s.begin("local")
        s.item("address", self.addr)
        if self.tsig:
            s.item("key", self.tsig.name)
        s.end()

        servers = set() # Duplicity check.
        for zone in self.zones:
            z = self.zones[zone]
            if z.master and z.master.name not in servers:
                s.begin(z.master.name)
                s.item("address", z.master.addr)
                s.item("port", z.master.port)
                if z.master.tsig:
                    s.item("key", z.master.tsig.name)
                s.end()
                servers.add(z.master.name)
            for slave in z.slaves:
                if slave.name not in servers:
                    s.begin(slave.name)
                    s.item("address", slave.addr)
                    s.item("port", slave.port)
                    if slave.tsig:
                        s.item("key", slave.tsig.name)
                    s.end()
                    servers.add(slave.name)
        s.end()

        s.begin("zones")
        s.item("zonefile-sync", "5s")
        s.item("notify-timeout", "5")
        s.item("notify-retries", "5")
        for zone in self.zones:
            z = self.zones[zone]
            s.begin(z.name)
            s.item_str("file", z.filename)

            if z.master:
                s.item("notify-in", z.master.name)
                s.item("xfr-in", z.master.name)

            if z.slaves:
                slaves = ""
                for slave in z.slaves:
                    slaves += slave.name + " "
                s.item("notify-out", slaves.strip())

            s.item("xfr-out", "local")

            if z.ddns == True:
                s.item("update-in", "local")
            elif z.ddns == False:
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

        return s.conf

class Nsd(DnsServer):

    def __init__(self):
        super().__init__()
        super().set_paths(nsd_vars)

    def get_config(self):
        self.start_params = ["-c", self.confile, "-d"]
        self.compile_params = ["-c", self.confile, "rebuild"]

class DnsTest(object):
    '''Specification of DNS test topology'''

    MAX_START_TRIES = 20
    LOCAL_ADDR = {4: "127.0.0.1", 6: "::1"}
    VALGRIND_CMD = ["valgrind", "--leak-check=full"]

    # Value of the last generated port.
    last_port = None

    # Number of unsuccessful starts of servers. Recursion protection.
    start_tries = 0

    def __init__(self, test_dir, out_dir, ip=None, tsig=None):
        if not os.path.exists(out_dir):
            raise Exception("Output directory doesn't exist")

        self.out_dir = str(out_dir)
        self.data_dir = str(test_dir) + "/data/"
        self.zones_dir = self.out_dir + "/zones/"
        try:
            os.mkdir(self.zones_dir)
        except:
            raise Exception("Can't create directory %s" % self.zones_dir)

        self.ip = ip if ip else random.choice([4, 6])
        if self.ip not in [4, 6]:
            raise Exception("Invalid IP version")

        self.tsig = bool(tsig) if tsig != None else random.choice([True, False])

        self.servers = set()

    def _check_port(self, port):
        if not port:
            return False

        proto = socket.AF_INET if self.ip == 4 else socket.AF_INET6

        try:
            s = socket.socket(proto, socket.SOCK_DGRAM)
            s.bind((DnsTest.LOCAL_ADDR[self.ip], port))
            s.close
            s = socket.socket(proto, socket.SOCK_STREAM)
            s.bind((DnsTest.LOCAL_ADDR[self.ip], port))
            s.close
        except:
            return False

        return True

    def _gen_port(self):
        min_port = 10000
        max_port = 50000

        port = DnsTest.last_port
        if port:
            port = port + 1 if port < max_port else min_port

        while not self._check_port(port):
            port = random.randint(min_port, max_port)

        DnsTest.last_port = port
        return port

    def server(self, server, nsid=None, ident=None, version=None, valgrind=None):
        if server == "knot":
            srv = Knot()
        elif server == "bind":
            srv = Bind()
        elif server == "nsd":
            srv = Nsd()
        else:
            raise Exception("Usupported server %s" % server)

        type(srv).count += 1

        if valgrind or (valgrind == None and server == "knot"):
            srv.valgrind = DnsTest.VALGRIND_CMD

        srv.nsid = nsid
        srv.ident = ident
        srv.version = version

        srv.ip = self.ip
        srv.addr = DnsTest.LOCAL_ADDR[self.ip]
        srv.port = self._gen_port()
        srv.ctlport = self._gen_port()
        srv.ctlkey = Tsig()
        srv.tsig = Tsig() if self.tsig else None

        srv.name = "%s%s" % (server, srv.count)
        srv.dir = self.out_dir + "/" + srv.name
        srv.fout = srv.dir + "/stdout"
        srv.ferr = srv.dir + "/stderr"
        srv.confile = srv.dir + "/%s.conf" % srv.name

        try:
            os.mkdir(srv.dir)
        except:
            raise Exception("Can't create directory %s" % srv.dir)

        self.servers.add(srv)
        return srv

    def _generate_conf(self):
        for server in self.servers:
            server.gen_confile()

    def start(self):
        if self.start_tries > DnsTest.MAX_START_TRIES:
            raise Exception("Can't start all servers")

        self.start_tries += 1

        self._generate_conf()

        def srv_sort(server):
            masters = 0
            for z in server.zones:
                if server.zones[z].master: masters += 1
            return masters

        # Sort server list by number of masters. I.e. masters are prefered.
        for server in sorted(self.servers, key=srv_sort):
            server.start()
            if not server.running():
                self.stop()
                self.start()

    def stop(self):
        for server in self.servers:
            server.stop()

    def end(self):
        self.stop()
        pass

    def zone(self, name, filename):
        try:
            src_file = self.data_dir + filename
            dst_file = self.zones_dir + filename
            shutil.copyfile(src_file, dst_file)
        except:
            raise Exception("Can't use zone file %s" % filename)

        zone_name = name
        if zone_name[-1] != ".":
            zone_name += "."

        return {zone_name: dst_file}

    '''
    def zone_rnd(self, number):
        zone_generate.main()
        try:
            file_path = str(self.data_dir + filename)
            with open(file_path):
                pass
        except:
            raise Exception("Invalid zone file %s" % file_path)

        zone_name = name
        if zone_name[-1] != ".":
            zone_name += "."

        return {zone_name: file_path}
    '''

    def link(self, zones, master, slave=None, ddns=False):
        for zone in zones:
            if master not in self.servers:
                raise Exception("Uncovered server in test")
            master.zone_master(zone, zones[zone], slave, ddns)

            if slave:
                if slave not in self.servers:
                    raise Exception("Uncovered server in test")
                slave.zone_slave(zone, zones[zone], master)

