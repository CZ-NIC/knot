#!/usr/bin/env python3

import os
import random
import shutil
import zone_generate
from subprocess import DEVNULL, PIPE, Popen
from dnstest.utils import *

class ZoneFile(object):
    '''A zone file handler.'''

    def __init__(self, file_dir):
        try:
            os.makedirs(file_dir)
        except OSError:
            if not os.path.isdir(file_dir):
                raise Exception("Can't use zone file directory %s" % file_dir)

        self.file_dir = file_dir
        self.file_name = ""
        self.name = ""
        self.serial = None
        self.dnssec = None

    @property
    def path(self):
        '''Get absolute path of the zone file.'''

        return os.path.join(self.file_dir, self.file_name)

    def set_name(self, name=None):
        '''Set specified or generate zone name.'''

        if name:
            self.name = name
            if self.name[-1] != ".":
                self.name += "."
        else:
            self.name = zone_generate.main(["-n", 1]).strip()

    def set_file(self, file_name=None, storage=None, dnssec=None, serial=None,
                 exists=True):
        '''Make a copy of an existing zone file. If no file name is specified,
           the file name is constructed from the zone name (zname.zone).
           The storage is a directory containg the zone file.'''

        if not file_name:
            file_name = self.name + "zone"

        self.file_name = os.path.basename(file_name)
        if os.path.isabs(file_name):
            src_file = file_name
        else:
            src_file = os.path.join(storage, self.file_name)

        if not exists:
            return

        try:
            shutil.copyfile(src_file, self.path)
        except:
            raise Exception("Can't use zone file %s" % src_file)

        if dnssec is not None:
            self.dnssec = dnssec
        if serial:
            self.serial = int(serial)

    def upd_file(self, file_name=None, storage=None, dnssec=None, serial=None):
        '''Replace zone file with a different one.'''

        self.set_file(file_name=file_name, storage=storage, dnssec=dnssec,
                      serial=serial)

    def gen_file(self, dnssec=None, records=None, serial=None):
        '''Generate zone file.'''

        if dnssec == None:
            dnssec = random.choice([True, False])
        if not records:
            records = random.randint(1, 1000)
        if not serial:
            serial = random.randint(1, 4294967295)

        self.file_name = self.name + "rndzone"
        self.serial = int(serial)
        self.dnssec = dnssec

        try:
            params = ["-i", self.serial, "-o", self.path, self.name, records]
            if self.dnssec:
                params = ["-s"] + params
            zone_generate.main(params)
        except OSError:
            err("Can't create zone file %s" % self.path)

    def dnssec_verify(self):
        '''Call dnssec-verify on the zone file.'''

        check_log("DNSSEC VERIFY for %s (%s)" % (self.name, self.path))

        cmd = Popen(["dnssec-verify", "-o", self.name, self.path],
                    stdout=PIPE, stderr=PIPE, universal_newlines=True)
        (out, err) = cmd.communicate()

        if cmd.returncode != 0:
            set_err("DNSSEC VERIFY")
            detail_log(err.strip())

        detail_log(SEP)

    def clone(self, file_dir, exists=True):
        '''Make a copy of the zone file.'''

        new = ZoneFile(file_dir)
        new.set_name(self.name)
        new.set_file(file_name=self.path, dnssec=self.dnssec,
                     serial=self.serial,
                     exists=exists and os.path.isfile(self.path))
        return new

    def enable_nsec3(self, salt="abcdef", iters=2):
        '''Insert NSEC3PARAM record to the zone file.'''

        with open(self.path, "a") as file:
            file.write("@ 0 NSEC3PARAM 1 0 %i %s" % (iters, salt))

    def disable_nsec3(self):
        '''Remove NSEC3PARAM record if any.'''

        old_name = self.path + ".old"
        os.rename(self.path, old_name)

        with open(old_name) as old_file, open(self.path, 'w') as new_file:
            for line in old_file:
                if not "NSEC3PARAM" in line:
                    new_file.write(line)

