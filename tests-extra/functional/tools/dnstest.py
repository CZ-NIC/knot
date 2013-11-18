#!/usr/bin/env python3

import base64
import binascii
import inspect
import re
import os
import random
import shutil
import socket
import string
import sys
import time
import dns.message
import dns.query
import dns.tsigkeyring
import dns.update
import dns.zone
from subprocess import Popen, PIPE, DEVNULL, check_call
import zone_generate, params

SEP = "------------------------------------"

class Skip(Exception):
    """Exception for skipping current case."""
    pass

def test_info():
    '''Get current test case name'''

    info = ""
    frames = inspect.getouterframes(inspect.currentframe())
    for frame in frames:
        if params.test_dir == os.path.dirname(frame[1]):
            info = "%s#%i" % (params.test_dir, frame[2])
            break
    parts = info.split("/")

    if len(parts) > 1:
        return parts[-2] + "/" + parts[-1]
    else:
        return "dnstest"

def check_log(text, stdout=False):
    '''Log message header'''

    msg = "%s (%s)" % (str(text), test_info())
    params.case_log.write(msg + "\n")
    if stdout and params.debug:
        print(msg)

def detail_log(text, stdout=False):
    '''Log message body'''

    msg = str(text)
    params.case_log.write(msg + "\n")
    if stdout and params.debug:
        print(msg)

def err(text):
    '''Log error'''

    check_log("ERROR", True)
    detail_log(text, True)
    detail_log(SEP, True)

def set_err(msg):
    '''Set error state'''

    params.err = True
    if not params.err_msg:
        params.err_msg = msg

def isset(value, name):
    '''Check if value is True'''

    if not value:
        set_err("IS SET " + name)
        check_log("IS SET " + name, True)
        detail_log("  False", True)
        detail_log(SEP, True)

def compare(value, expected, name):
    '''Compare two values'''

    if value != expected:
        set_err("COMPARE " + name)
        check_log("COMPARE " + name, True)
        detail_log("  (" + str(value) + ") != (" + str(expected) + ")", True)
        detail_log(SEP, True)

def compare_sections(section1, section2, name):
    '''Compare two message sections'''

    if section1 == section2:
        return

    set_err("COMPARE section " + name)
    detail_log("COMPARE %s SECTIONS" % name, True)

    for rrset in section1:
        if rrset not in section2:
            detail_log("Section1 difference:" % rrset, True)
            detail_log("  %s" % rrset, True)

    for rrset in section2:
        if rrset not in section1:
            detail_log("Section2 difference:" % rrset, True)
            detail_log("  %s" % rrset, True)

    detail_log(SEP, True)

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

    def __init__(self, alg=None):
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

        if alg and alg not in Tsig.algs:
            raise Exception("Unsupported TSIG algorithm %s" % alg)

        self.alg = alg if alg else random.choice(list(Tsig.algs.keys()))

        self.key = base64.b64encode(os.urandom(Tsig.algs[self.alg])). \
                   decode('ascii')

        # TSIG preparation for pythondns utils.
        if self.alg == "hmac-md5":
            alg = "hmac-md5.sig-alg.reg.int"
        else:
            alg = self.alg

        key = dns.tsigkeyring.from_text({
            self.name: self.key
        })
        self.key_params = dict(keyname=self.name, keyalgorithm=alg, keyring=key)

    def dump(self, filename):
        s = BindConf()

        s.begin("key", self.name)
        s.item("algorithm", self.alg)
        s.item_str("secret", self.key)
        s.end()

        file = open(filename, mode="w")
        file.write(s.conf)
        file.close()

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

    def __init__(self, name, filename, ddns=False):
        self.name = name
        self.filename = filename
        self.master = None
        self.slaves = set()
        # ddns: True - ddns, False(master) - ixfrFromDiff, False(slave) - empty
        self.ddns = ddns

class Response(object):
    '''Dig output context'''

    def __init__(self, response, args):
        self.resp = response
        self.args = args

        self.rname = dns.name.from_text(self.args["rname"])

        if type(self.args["rtype"]) is str:
            self.rtype = dns.rdatatype.from_text(self.args["rtype"])
        else:
            self.rtype = self.args["rtype"]

        if type(self.args["rclass"]) is str:
            self.rclass = dns.rdataclass.from_text(self.args["rclass"])
        else:
            self.rclass = self.args["rclass"]

    def _check_question(self):
        question = self.resp.question.pop()
        compare(question.name, self.rname, "question.name")
        compare(question.rdclass, self.rclass, "question.class")
        compare(question.rdtype, self.rtype, "question.type")

    def _check_flags(self, flags, noflags):
        flag_names = flags.split()
        for flag in flag_names:
            flag_val = dns.flags.from_text(flag)
            isset(self.resp.flags & flag_val, "%s flag" % flag)

        flag_names = noflags.split()
        for flag in flag_names:
            flag_val = dns.flags.from_text(flag)
            isset(not(self.resp.flags & flag_val), "no %s flag" % flag)

    def check(self, rdata=None, ttl=None, rcode="NOERROR", flags="", \
              noflags=""):
        '''Flags are text strings separated by whitespace character'''

        self._check_flags(flags, noflags)
        self._check_question()

        # Check rcode.
        if type(rcode) is str:
            rc = dns.rcode.from_text(rcode)
        else:
            rc = rcode
        compare(self.resp.rcode(), rc, "RCODE")

        # Check rdata only if NOERROR.
        if rc != 0 or rdata == None:
            return

        # We work with just one rdata with TTL=0 (this TTL is not used).
        ref = list(dns.rdataset.from_text(self.rclass, self.rtype, 0, rdata))[0]

        # Check answer section if contains reference rdata.
        for data in self.resp.answer:
            for rdata in data.to_rdataset():
                # Compare Rdataset instances.
                if rdata == ref:
                    # Check CLASS.
                    compare(data.rdclass, self.rclass, "CLASS")
                    # Check TYPE.
                    compare(data.rdtype, self.rtype, "TYPE")
                    # Check TTL if specified.
                    if ttl != None:
                        compare(data.ttl, int(ttl), "TTL")
                    return
        else:
            err("RDATA (" + str(rdata) + ") not in ANSWER section")
            set_err("CHECK rdata")

    def check_edns(self, nsid=None, buff_size=None):
        compare(self.resp.edns, 0, "EDNS version")

        options = 1 if nsid != None else 0
        compare(len(self.resp.options), options, "number of EDNS0 options")

        if options > 0:
            option = list(self.resp.options)[0]
            compare(option.otype, dns.edns.NSID, "option type")
            if nsid[:2] == "0x":
                compare(binascii.hexlify(option.data).decode('ascii'), \
                        nsid[2:], "hex NSID")
            else:
                compare(option.data.decode('ascii'), nsid, "txt NSID")

    def diff(self, resp, flags=True, answer=True, authority=True, \
             additional=False):
        '''Compares specified response sections against another response'''

        if flags:
            compare(dns.flags.to_text(self.resp.flags), \
                    dns.flags.to_text(resp.resp.flags), "FLAGS")
            compare(dns.flags.edns_to_text(self.resp.ednsflags), \
                    dns.flags.edns_to_text(resp.resp.ednsflags), "EDNS FLAGS")
        if answer:
            compare_sections(self.resp.answer, resp.resp.answer, \
                             "ANSWER")
        if authority:
            compare_sections(self.resp.authority, resp.resp.authority, \
                             "AUTHORITY")
        if additional:
            compare_sections(self.resp.additional, resp.resp.additional, \
                             "ADDITIONAL")

    def cmp(self, server, flags=True, answer=True, authority=True, \
            additional=False):
        '''Asks server for the same question an compares specified sections'''

        resp = server.dig(**self.args)
        self.diff(resp, flags, answer, authority, additional)

class Update(object):
    '''DNS update context'''

    def __init__(self, server, upd):
        self.server = server
        self.upd = upd

    def add(self, owner, ttl, rtype, rdata):
        self.upd.add(owner, ttl, rtype, rdata)

    def delete(self, owner, *args):
        self.upd.delete(owner, *args)

    def prereq_yx(self, owner, *args):
        self.upd.present(owner, *args)

    def prereq_nx(self, owner, rtype=None):
        self.upd.absent(owner, rtype)

    def send(self, rcode="NOERROR"):
        if type(rcode) is str:
            rc = dns.rcode.from_text(rcode)
        else:
            rc = rcode

        check_log("UPDATE")
        detail_log(str(self.upd))
        detail_log(SEP)

        resp = dns.query.tcp(self.upd, self.server.addr, port=self.server.port)
        compare(resp.rcode(), rc, "update rcode")

class DnsServer(object):
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

    def zone_master(self, name, file, slave=None, ddns=False):
        if name in self.zones:
            if slave:
                self.zones[name].slaves.add(slave)
        else:
            z = Zone(name, file, ddns)
            if slave:
                z.slaves.add(slave)
            self.zones[name] = z

    def zone_slave(self, name, file, master, ddns=False):
        if name in self.zones:
            raise Exception("Can't set zone %s as a slave" % name)
        else:
            slave_file = self.dir + "/__" + name + "slave"
            z = Zone(name, slave_file, ddns)
            z.master = master
            self.zones[name] = z

    def compile(self):
        try:
            p = Popen([self.control_bin] + self.compile_params,
                      stdout=self.fout, stderr=self.ferr)
            p.communicate(timeout=DnsServer.COMPILE_TIMEOUT)
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
                time.sleep(DnsServer.START_WAIT_VALGRIND)
            else:
                time.sleep(DnsServer.START_WAIT)
        except OSError:
            err("Server %s start error" % self.name)

    def reload(self):
        try:
            check_call([self.control_bin] + self.reload_params, \
                       stdout=DEVNULL, stderr=DEVNULL)
            time.sleep(DnsServer.START_WAIT)
        except OSError:
            err("Server %s reload error" % self.name)

    def flush(self):
        try:
            if self.flush_params:
                check_call([self.control_bin] + self.flush_params, \
                           stdout=DEVNULL, stderr=DEVNULL)
                time.sleep(DnsServer.START_WAIT)
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
                self.proc.wait(DnsServer.STOP_TIMEOUT)
            except:
                err("killing")
                self.proc.kill()

    def gen_confile(self):
        f = open(self.confile, mode="w")
        f.write(self.get_config())
        f.close

    def dig(self, rname, rtype, rclass="IN", udp=None, serial=None, \
            timeout=DIG_TIMEOUT, tries=3, recursion=False, bufsize=None, \
            nsid=False, dnssec=False):
        key_params = self.tsig.key_params if self.tsig else dict()

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
                return Response(resp, args)
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

        _serial = 0

        for t in range(20):
            resp = self.dig(zone, "SOA", udp=True, tries=1)
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
            raise Exception("Can't get %s SOA%s from %s." % \
                            (zone, ">%i" % serial if serial else "", self.name))

        return _serial

    def zones_wait(self, zones):
        for zone in zones:
            self.zone_wait(zone)

    def update(self, zone):
        if len(zone) != 1:
            raise Exception("One zone required.")
        zname = list(zone.keys())[0]

        key_params = self.tsig.key_params if self.tsig else dict()

        return Update(self, dns.update.Update(zname, **key_params))

    def zone_update(self, zone_name, file_name):
        # Add trailing dot if missing.
        if zone_name[-1] != ".":
            zone_name += "."

        src_file = self.data_dir + file_name
        dst_file = self.zones[zone_name].filename

        try:
            shutil.copyfile(src_file, dst_file)
        except:
            raise Exception("Can't use zone file %s" % src_file)

class Bind(DnsServer):

    def __init__(self):
        super().__init__()
        if not params.bind_bin:
            raise Skip("No Bind")
        self.daemon_bin = params.bind_bin
        self.control_bin = params.bind_ctl
        self.ctlkey = Tsig(alg="hmac-md5")

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

class Knot(DnsServer):

    def __init__(self):
        super().__init__()
        if not params.knot_bin:
            raise Skip("No Knot")
        self.daemon_bin = params.knot_bin
        self.control_bin = params.knot_ctl

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
            s.item_str("\"%s\" %s" % (t.name, t.alg), t.key)

            keys = set() # Duplicy check.
            for zone in self.zones:
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
        for zone in self.zones:
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

class Nsd(DnsServer):

    def __init__(self):
        super().__init__()
        if not params.nsd_bin:
            raise Skip("No NSD")
        self.daemon_bin = params.nsd_bin
        self.control_bin = params.nsd_ctl

    def get_config(self):
        self.start_params = ["-c", self.confile, "-d"]
        self.compile_params = ["-c", self.confile, "rebuild"]

class Dummy(DnsServer):
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

class DnsTest(object):
    '''Specification of DNS test topology'''

    MAX_START_TRIES = 10
    LOCAL_ADDR = {4: "127.0.0.1", 6: "::1"}

    # Value of the last generated port.
    last_port = None

    # Number of unsuccessful starts of servers. Recursion protection.
    start_tries = 0

    def __init__(self, ip=None, tsig=None):
        if not os.path.exists(params.out_dir):
            raise Exception("Output directory doesn't exist")

        self.out_dir = params.out_dir
        self.data_dir = params.test_dir + "/data/"
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

        Knot.count = 0
        Bind.count = 0
        Nsd.count = 0
        Dummy.count = 0

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

    def server(self, server, nsid=None, ident=None, version=None, \
               valgrind=None):
        if server == "knot":
            srv = Knot()
        elif server == "bind":
            srv = Bind()
        elif server == "nsd":
            srv = Nsd()
        elif server == "dummy":
            srv = Dummy()
        else:
            raise Exception("Usupported server %s" % server)

        type(srv).count += 1

        if params.valgrind_bin and \
           (valgrind or (valgrind == None and server == "knot")):
            srv.valgrind = [params.valgrind_bin, params.valgrind_flags]

        srv.data_dir = self.data_dir

        srv.nsid = nsid
        srv.ident = ident
        srv.version = version

        srv.ip = self.ip
        srv.addr = DnsTest.LOCAL_ADDR[self.ip]
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

        if srv.ctlkey:
            srv.ctlkeyfile = srv.dir + "/%s.ctlkey" % srv.name
            srv.ctlkey.dump(srv.ctlkeyfile)

        self.servers.add(srv)
        return srv

    def _generate_conf(self):
        # Next two loops can't be merged!
        for server in self.servers:
            server.port = self._gen_port()
            server.ctlport = self._gen_port()

        for server in self.servers:
            server.gen_confile()

    def start(self):
        '''Start all test servers'''

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

        params.test = self
        self.start_tries = 0

    def stop(self):
        '''Stop all servers'''

        for server in self.servers:
            server.stop()
        params.test = None

    def end(self):
        '''Finish testing'''

        self.stop()
        for server in self.servers:
            server._valgrind_check()

    def sleep(self, seconds):
        time.sleep(seconds)

    def zone(self, zone_name, file_name=None, exists=True):
        # Add trailing dot if missing.
        if zone_name[-1] != ".":
            zone_name += "."

        if file_name:
            src_file = self.data_dir + file_name
            dst_file = self.zones_dir + file_name
        else:
            if zone_name == ".":
                file_name = "rootzone.zone"
            else:
                file_name = zone_name + "zone"

            src_file = params.common_data_dir + file_name
            dst_file = self.zones_dir + file_name

        try:
            if exists is True:
                shutil.copyfile(src_file, dst_file)
        except:
            raise Exception("Can't use zone file %s" % src_file)

        return {zone_name: dst_file}

    def zone_rnd(self, number, dnssec=None, records=None):
        zones = dict()

        names = zone_generate.main(["-n", number]).split()
        for name in names:
            if dnssec == None:
                sign = random.choice([True, False])
            else:
                sign = True if dnssec else False
            serial = random.randint(1, 4294967295)
            items = records if records else random.randint(1, 1000)
            filename = self.zones_dir + name + ".rndzone"

            try:
                params = ["-i", serial, "-o", filename, name, items]
                if sign:
                    params = ["-s"] + params

                zone = zone_generate.main(params)
            except OSError:
                err("Can't create zone file %s" % filename)

            zones[name + "."] = filename

        return zones

    def link(self, zones, master, slave=None, ddns=False):
        for zone in zones:
            if master not in self.servers:
                raise Exception("Uncovered server in test")
            master.zone_master(zone, zones[zone], slave, ddns)

            if slave:
                if slave not in self.servers:
                    raise Exception("Uncovered server in test")
                slave.zone_slave(zone, zones[zone], master, ddns)

    def xfr_diff(self, server1, server2, zones):
        check_log("CHECK AXFR DIFF")
        for zone in zones:
            detail_log("Zone %s %s-%s:" % (zone, server1.name, server2.name))
            z1 = dns.zone.from_xfr(server1.dig(zone, "AXFR").resp)
            z2 = dns.zone.from_xfr(server2.dig(zone, "AXFR").resp)

            z1_keys = set(z1.nodes.keys())
            z2_keys = set(z2.nodes.keys())

            z1_diff = sorted(list(z1_keys - z2_keys))
            z2_diff = sorted(list(z2_keys - z1_keys))
            z_keys = sorted(list(z1_keys & z2_keys))

            if z1_diff:
                set_err("XFR DIFF")
                detail_log("Extra records in %s:" % server1.name, True)
                for key in z1_diff:
                    for record in z1.nodes[key]:
                        detail_log("  %s %s" % (key, str(record)), True)

            if z2_diff:
                set_err("XFR DIFF")
                detail_log("Extra records in %s:" % server2.name, True)
                for key in z2_diff:
                    for record in z2.nodes[key]:
                        detail_log("  %s %s" % (key, str(record)), True)

            if not z_keys:
                return

            for key in z_keys:
                if z1.nodes[key] != z2.nodes[key]:
                    set_err("XFR DIFF")
                    detail_log("Different nodes:", True)
                    detail_log("%s:" % server1.name, True)
                    for record in z1.nodes[key]:
                        detail_log("  " + str(record), True)
                    detail_log("%s:" % server2.name, True)
                    for record in z2.nodes[key]:
                        detail_log("  " + str(record), True)

            detail_log(SEP)
