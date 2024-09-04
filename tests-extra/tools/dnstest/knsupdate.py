#!/usr/bin/env python3

import dns
from re import search, findall
from subprocess import Popen, PIPE

from dnstest.context import Context
from dnstest.utils import *
import dnstest.params as params

# Use one instance per zone, don't combine multiple zone updates (could cause UB).
class Knsupdate:
    def __init__(self, zone, tsig=None):
        self.zone = zone
        self.tsig = tsig
        self.output = ""

    @property
    def origin(self):
        return dns.name.Name(self.zone)

    def add(self, owner, ttl, rtype, rdata):
        self.output += f"update add {owner}"
        if ttl:
            self.output += f" {ttl}"
        self.output += f" {rtype} {rdata}\n"

    def delete(self, owner, *args):
        self.output += f"update delete {owner}"
        if len(args) >= 1:
            rtype = args[0]
            if rtype != 'ANY':
                self.output += f" {rtype}"
                if len(args) >= 2:
                    rdata = args[1]
                    self.output += f" {rdata}"
        self.output += "\n"

    def present(self, owner, *args):
        if len(args) >= 1:
            self.output += f"prereq yxrrset {owner}"
            rtype = args[0]
            self.output += f" {rtype}"
            if len(args) >= 2:
                rdata = args[1]
                self.output += f" {rdata}"
        else:
            self.output += f"prereq yxdomain {owner}"
        self.output += "\n"

    def absent(self, owner, *args):
        if len(args) >= 1:
            self.output += f"prereq nxrrset {owner}"
            rtype = args[0]
            self.output += f" {rtype}"
        else:
            self.output += f"prereq nxdomain {owner}"
        self.output += "\n"

    def send(self, addr, port, proto):
        # Binary with arguments
        cmdline = [params.knsupdate_bin]

        if proto is Proto.TCP:
            cmdline += ["-T"]
        elif proto is Proto.TLS:
            cmdline += ["-S"]
        elif proto is Proto.QUIC:
            cmdline += ["-Q"]

        if self.tsig:
            cmdline += ["-y", f"{self.tsig.alg}:{self.tsig.name}:{self.tsig.key}"]

        # Mandatory header
        header = f"server {addr} {port}\n"
        header += f"zone {self.zone}\n"
        header += f"origin {self.zone}\n"
        whole_cmd = header + self.output + "show\nsend\nanswer\nexit\n"
        detail_log(whole_cmd)

        # Run process
        cmd = Popen(cmdline, stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        (stdout, stderr) = cmd.communicate(whole_cmd)

        with open(Context().out_dir + "/knsupdate.out", "a") as outf:
            outf.write(' '.join(cmdline))
            outf.write("\n" + stdout + "\n")
        with open(Context().out_dir + "/knsupdate.err", "a") as errf:
            errf.write(stderr)

        # Parse RCODE
        rcodes = findall(r"status: ([A-Z]+)", stdout)
        if len(rcodes) != 2:
            raise Failed("Failed to parse RCODE")

        rcv_ercode = rcodes[1]

        if rcv_ercode != "SERVFAIL" and rcv_ercode != "NOTAUTH" and "reply verification" in stderr:
            raise Failed("TSIG issues in DDNS")

        self.output = ""
        return rcv_ercode
