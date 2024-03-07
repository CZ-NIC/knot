#!/usr/bin/env python3

'''Validate configuration JSON schema exported from knotc'''

import os
import yaml

from json import load, JSONDecodeError
from jsonschema import validate, ValidationError

from dnstest.test import Test
from dnstest.utils import Failed
from kyaml import KnotYAMLLoader

def make_abs(conf_name):
    if not os.path.isabs(conf_name):
        conf_name = os.path.join(t.data_dir, conf_name)
    return conf_name

def validate_file(conf_path):
    with open(conf_path, 'r') as conf_file:
        conf = yaml.load(conf_file, KnotYAMLLoader)
        validate(conf, schema)

t = Test()
knot = t.server("knot")

VALID = [ knot.confile, 'complete.yaml' ]
INVALID = [ 'undefined.yaml', 'base64.yaml', 'enum.yaml', 'dname.yaml' ]

t.start()

schema_path = os.path.join(t.out_dir, "configuration.schema.json")
knot.ctl("conf-export +schema %s" % schema_path)
schema_file = open(schema_path)
try:
    schema = load(schema_file)
except JSONDecodeError as e:
    raise Failed("Not valid JSON scheme")
except:
    raise

for conf_name in map(make_abs, VALID):
    try:
        validate_file(conf_name)
    except Exception as e:
        raise Failed("Failed to validate %s" % conf_name)

for conf_name in map(make_abs, INVALID):
    try:
        validate_file(conf_name)
        raise Failed("Validation of invalid configuration '%s' failed" % conf_name)
    except ValidationError:
        pass
    except:
        raise Failed("Failed to validate %s" % conf_name)

t.end()
