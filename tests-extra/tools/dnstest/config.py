#!/usr/bin/env python3

class KnotConf(object):
    '''Knot server config generator'''

    def __init__(self):
        self.conf = ""
        self.first_item = True

    def include(self, path):
        self.conf += "include: %s\n" % (path)

    def begin(self, name):
        self.conf += "%s:\n" % name
        self.first_item = True

    def end(self):
        self.conf += "\n"

    def item(self, name, value):
        self.conf += "        %s: %s\n" % (name, value)

    def item_str(self, name, value):
        self.conf += "        %s: \"%s\"\n" % (name, value)

    def item_list(self, name, values):
        self.conf += "        %s: [" % name
        self.conf += ', '.join(str(value) for value in values)
        self.conf += "]\n"

    def id_item(self, name, value):
        if not self.first_item:
            self.conf += "\n"
        else:
            self.first_item = False
        self.conf += "      - %s: \"%s\"\n" % (name, value)

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
