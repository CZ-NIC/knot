#!/usr/bin/env python3

'''Validate configuration JSON schema exported from knotc'''

import os
import yaml

from dnstest.test import Test
from dnstest.utils import Failed
from json import load, JSONDecodeError
from jsonschema import validate, ValidationError
from yaml.parser import ParserError

VALID = [ 'complete.yaml']
INVALID = [ 'undefined.yaml', 'base64.yaml', 'enum.yaml' ]
FALSE_VALID = [ 'dname.yaml' ]
FALSE_INVALID = [ 'ipv6-array.yaml' ]

def validate_file(conf_path):
        try:
                with open(conf_path, 'r') as conf_file:
                        conf = yaml.safe_load(conf_file)
                        validate(conf, schema)
        except Exception:
                raise

t = Test()
knot = t.server("knot")
t.start()

schema_path = os.path.join(t.out_dir, "configuration.schema.json")
knot.ctl("conf-export +schema %s" % schema_path)
schema_file = open(schema_path)
try:
        schema = load(schema_file)
except JSONDecodeError:
        raise Failed("Not valid JSON scheme")
except:
        raise

for conf_name in VALID:
        try:
                validate_file(os.path.join(t.data_dir, conf_name))
        except Exception:
                raise Failed("Failed to validate %s" % conf_name)

for conf_name in INVALID:
        try:                        
                validate_file(os.path.join(t.data_dir, conf_name))
                raise Failed("Validation of invalid configuration '%s' failed" % conf_name)
        except ValidationError:
                pass
        except:
                raise Failed("Failed to validate %s" % conf_name)

for conf_name in FALSE_VALID:
        try:                        
                validate_file(os.path.join(t.data_dir, conf_name))
        except Exception:
                raise Failed("False valid configuration %s was fixed" % conf_name)

for conf_name in FALSE_INVALID:
        try:                        
                validate_file(os.path.join(t.data_dir, conf_name))
                raise Failed("False invalid configuration %s was fixed" % conf_name)
        except ParserError:
                pass
        except Exception:
                raise Failed("Failed to validate %s" % conf_name)

t.end()
