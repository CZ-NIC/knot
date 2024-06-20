#!/usr/bin/env python3

from re import search
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
            cmdline += ["-v"]
        elif proto is Proto.TLS:
            cmdline += ["-T"]
        elif proto is Proto.QUIC:
            cmdline += ["-q"]

        if self.tsig:
            cmdline += ["-y", f"{self.tsig.alg}:{self.tsig.name}:{self.tsig.key}"]

        # Mandatory header
        header = f"server {addr} {port}\n"
        header += f"zone {self.zone}\n"

        # Run process
        cmd = Popen(cmdline, stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        (stdout, stderr) = cmd.communicate(header + self.output + "show\nsend\nanswer\nexit\n")

        with open(Context().out_dir + "/keymgr.out", "a") as outf:
            outf.write(' '.join(cmdline))
            outf.write("\n" + stdout + "\n")
        with open(Context().out_dir + "/keymgr.err", "a") as errf:
            errf.write(stderr)

        # Parse RCODE
        if stderr and stderr != '':
            rcv_match = search(r"'([A-Z]+)'", stderr)
            if not rcv_match:
                raise Failed("Failed to parse RCODE")
            rcv_ercode = rcv_match.group(1)
        else:
            rcv_ercode = 'NOERROR'
        self.output = ""
        return rcv_ercode
