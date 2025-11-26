from dnstest.utils import *
import dnstest.params as params
import datetime
import os
import shutil
import subprocess
import time

class Redis(object):
    counter = 0
    def __init__(self, addr, wrk_dir, redis_bin, redis_cli, knotso, tls=False):
        self.addr = addr
        self.port = None
        self.tls = tls
        self.tls_port = None
        self.pin = None
        Redis.counter += 1
        self.wrk_dir = os.path.join(wrk_dir, str(Redis.counter))
        self.redis_bin = redis_bin
        self.redis_cli = redis_cli
        self.knotso = knotso
        self.proc = None
        self.monitor = None
        self.monitor_log = None

        self._master = None
        self._sentinel_of = dict()

        if not os.path.exists(self.wrk_dir):
            os.makedirs(self.wrk_dir)

    def wrk_file(self, filename):
        return os.path.join(self.wrk_dir, filename)

    def conf_file(self):
        return self.wrk_file("redis.conf")

    def gen_confile(self):
        with open(self.conf_file(), "w") as cf:
            cf.write("dir " + self.wrk_dir + os.linesep)
            cf.write("logfile " + self.wrk_file("redis.log") + os.linesep)
            if len(self._sentinel_of) == 0:
                cf.write("loadmodule " + self.knotso + os.linesep)
            cf.write("bind " + self.addr + os.linesep)
            cf.write("port " + str(self.port) + os.linesep)
            cf.write("tls-port " + str(self.tls_port) + os.linesep)
            cf.write("tls-protocols \"TLSv1.3\"" + os.linesep)
            cf.write("tls-auth-clients no" + os.linesep)
            cf.write("tls-ca-cert-file cert.pem" + os.linesep)
            cf.write("tls-key-file key.pem" + os.linesep)
            cf.write("tls-cert-file cert.pem" + os.linesep)
            cf.write("enable-debug-command yes" + os.linesep)
            cf.write("repl-ping-replica-period 1" + os.linesep)
            if self.addr != "127.0.0.1" and self.addr != "::1":
                cf.write("protected-mode no " + os.linesep)
            if self._master != None:
                port = self._master.tls_port if self._master.tls else self._master.port
                cf.write(f"replicaof {self._master.addr} {port}" + os.linesep)
            if self.tls:
                cf.write("tls-replication yes" + os.linesep)
            if not self._sentinel_of.items():
                cf.write("appendonly yes" + os.linesep)

            server_idx = 0
            for server, quorum in self._sentinel_of.items():
                port = server.tls_port if server.tls else server.port
                cf.write(f"sentinel monitor master-{server_idx} {server.addr} {port} {quorum}" + os.linesep)
                cf.write(f"sentinel down-after-milliseconds master-{server_idx} 1000" + os.linesep)
                cf.write(f"sentinel failover-timeout master-{server_idx} 6000" + os.linesep)
                server_idx += 1

            shutil.copy(os.path.join(params.common_data_dir, "cert", "cert.pem"), self.wrk_dir)
            shutil.copy(os.path.join(params.common_data_dir, "cert", "key.pem"), self.wrk_dir)
            keyfile = os.path.join(self.wrk_dir, "key.pem")
            out = subprocess.check_output(["certtool", "--infile=" + keyfile, "-k"]).rstrip().decode('ascii')
            self.pin = ssearch(out, r'pin-sha256:([^\n]*)')

    def get_prio(self):
        if len(self._sentinel_of) > 0:
            return 2
        elif self._master != None:
            return 1
        else:
            return 0

    # Pass just master Redis, slaves are auto-discovered while starting server
    def sentinel_of(self, master, quorum=1):
        if self._master is not None:
            raise AssertionError("can't be sentinel and db at once")
        self._sentinel_of[master] = quorum

    def slave_of(self, master):
        if len(self._sentinel_of) != 0:
            raise AssertionError("can't be sentinel and db at once")
        self._master = master

    def start(self):
        prog = [self.redis_bin, self.conf_file()]
        is_sentinel = len(self._sentinel_of) > 0
        if is_sentinel:
            prog.append('--sentinel')
        self.proc = subprocess.Popen(prog)

        time.sleep(0.3)
        self.run_monitor()

    def run_monitor(self):
        is_sentinel = len(self._sentinel_of) > 0
        if not is_sentinel and (not self.monitor or self.monitor.poll() is not None):
            if self.monitor_log:
                self.monitor_log.close()

            monitor_cmd = [ self.redis_cli, "-h", self.addr, "-p", str(self.port), "monitor" ]
            self.monitor_log = open(os.path.join(self.wrk_dir, "monitor.log"), "a")
            self.monitor = subprocess.Popen(monitor_cmd, stdout=self.monitor_log, stderr=self.monitor_log)

    def stop(self, kill=False):
        if self.monitor:
            self.monitor.terminate()
            self.monitor = None
        if self.monitor_log:
            self.monitor_log.close()
            self.monitor_log = None
        if self.proc:
            if kill:
                self.proc.kill()
            else:
                self.proc.terminate()

    def freeze(self, seconds):
        cmd = [ self.redis_cli, "-h", self.addr, "-p", str(self.port), "DEBUG", "sleep", str(seconds) ]
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def cli(self, *params):
        cmd = [ self.redis_cli, "-h", self.addr, "-p", str(self.port) ] + list(params)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = p.communicate()
        txt = out.decode().strip()
        outf = open(os.path.join(self.wrk_dir, "cli.log"), "a")
        outf.write("%s CLI %s\n" % (str(datetime.datetime.now()), str(list(params))))
        outf.write(txt)
        outf.write("\n--------\n")
        return txt
