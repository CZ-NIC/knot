from __future__ import annotations

from dnstest.utils import *
import dnstest.params as params
import os
import shutil
import subprocess
import time

class Redis(object):
    def __init__(self, addr, wrk_dir, redis_bin, redis_cli, knotso):
        self.addr = addr
        self.port = None
        self.tls_port = None
        self.pin = None
        self.wrk_dir = wrk_dir
        self.redis_bin = redis_bin
        self.redis_cli = redis_cli
        self.knotso = knotso
        self.proc = None
        self.monitor = None
        self.monitor_log = None
        self.slave_of = None

        if not os.path.exists(self.wrk_dir):
            os.makedirs(self.wrk_dir)

    def wrk_file(self, filename):
        return os.path.join(self.wrk_dir, filename)

    def conf_file(self):
        return self.wrk_file(f'redis.conf')

    def gen_confile(self):
        with open(self.conf_file(), "w") as cf:
            cf.write("dir " + self.wrk_dir + os.linesep)
            cf.write("logfile " + self.wrk_file("redis.log") + os.linesep)
            cf.write("loadmodule " + self.knotso + os.linesep)
            cf.write("bind " + self.addr + os.linesep)
            cf.write("port " + str(self.port) + os.linesep)
            cf.write("tls-port " + str(self.tls_port) + os.linesep)
            cf.write("tls-protocols \"TLSv1.3\"" + os.linesep)
            cf.write("tls-auth-clients no" + os.linesep)
            cf.write("tls-key-file key.pem" + os.linesep)
            cf.write("tls-cert-file cert.pem" + os.linesep)
            if self.addr != "127.0.0.1" and self.addr != "::1":
                cf.write("protected-mode no " + os.linesep)
            if self.slave_of != None:
                cf.write(f"slaveof {self.slave_of.addr} {self.slave_of.port}")

            shutil.copy(os.path.join(params.common_data_dir, "cert", "cert.pem"), self.wrk_dir)
            shutil.copy(os.path.join(params.common_data_dir, "cert", "key.pem"), self.wrk_dir)
            keyfile = os.path.join(self.wrk_dir, "key.pem")
            out = subprocess.check_output(["certtool", "--infile=" + keyfile, "-k"]).rstrip().decode('ascii')
            self.pin = ssearch(out, r'pin-sha256:([^\n]*)')

    def start(self):
        self.proc = subprocess.Popen([ self.redis_bin, self.conf_file() ])
        time.sleep(0.3)
        monitor_cmd = [ self.redis_cli, "-h", self.addr, "-p", str(self.port), "monitor" ]
        self.monitor_log = open(os.path.join(self.wrk_dir, "monitor.log"), "a")
        self.monitor = subprocess.Popen(monitor_cmd, stdout=self.monitor_log, stderr=self.monitor_log)

    def stop(self):
        if self.monitor:
            self.monitor.terminate()
        if self.monitor_log:
            self.monitor_log.close()
        if self.proc:
            self.proc.terminate()

    def cli(self, *params):
        cmd = [ self.redis_cli, "-h", self.addr, "-p", str(self.port) ] + list(params)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = p.communicate()
        return out.decode().strip()

    def slaveOf(self, master : Redis):
        self.slave_of = master