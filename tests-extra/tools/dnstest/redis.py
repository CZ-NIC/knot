import os
import subprocess

class Redis(object):
    def __init__(self, addr, wrk_dir, redis_bin, redis_cli, knotso):
        self.addr = addr
        self.port = None
        self.wrk_dir = wrk_dir
        self.redis_bin = redis_bin
        self.redis_cli = redis_cli
        self.knotso = knotso
        self.proc = None

        if not os.path.exists(wrk_dir):
            os.makedirs(wrk_dir)

    def wrk_file(self, filename):
        return os.path.join(self.wrk_dir, filename)

    def conf_file(self):
        return self.wrk_file("redis.conf")

    def gen_confile(self):
        with open(self.conf_file(), "w") as cf:
            cf.write("bind " + self.addr + os.linesep)
            cf.write("port " + str(self.port) + os.linesep)
            cf.write("logfile " + self.wrk_file("redis.log") + os.linesep)
            cf.write("loadmodule " + self.knotso + os.linesep)
            cf.write("dir " + self.wrk_dir + os.linesep)

    def start(self):
        self.proc = subprocess.Popen([ self.redis_bin, self.conf_file() ])

    def stop(self):
        if self.proc:
            self.proc.terminate()

    def cli(self, *params):
        cmd = [ self.redis_cli, "-h", self.addr, "-p", str(self.port) ] + list(params)
        p = subprocess.Popen(cmd)
        p.communicate()
