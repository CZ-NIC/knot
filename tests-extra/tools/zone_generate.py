#!/usr/bin/env python3

'''
Usage: zone_generate.py [parameters] origin
Parameters:
    -h, --help         This help.
    -s, --sign         Sign the zone with dnssec-signzone.
    -3, --nsec3=y|n    Use/don't use NSEC3. If not specified choose randomly.
    -i, --serial=num   Specify SOA serial.
    -u, --update=file  Update zone file (no extra SOA).
    -n, --names=num    Generate unique zone names.
    -t, --ttl=sec      Specify default TTL.
    -o, --outfile=file Specify output file name.
    -k, --keydir=dir   Specify output key directory.
    -c, --count=num    RR count
'''

import binascii
import getopt
import string
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import dns
import dns.rdataclass
import dns.rdatatype
import dns.rdata

class Context(object):
    # Zone name
    ORIGIN = 'com'
    # Domain for reverse zones
    RORIGIN = None
    # Zone is RPREFIX classless-type
    RPREFIX = None
    # 0.0 - 1.0, chance of dname bing a subdomain
    SUB_CHANCE = 0.0
    # 0.0 - 1.0, percentage of mangled words
    WORD_MRATE = 1.0
    # 0.0 - 1.0, chance for FQDN
    FQDN_CHANCE = 0.5

ctx = Context()

RRTYPES = [ \
#   [ typename, generator, probability, typeid ]
    [ 'A',        'g_a',        1.00,   1 ], \
    [ 'NS',       'g_dname',    0.25,   2 ], \
    [ 'CNAME',    'g_dname',    0.25,   5 ], \
#   [ 'PTR',      'g_ptr',      0.50,  12 ], \
    [ 'HINFO',    'g_hinfo',    0.05,  13 ], \
    [ 'MX',       'g_mx',       0.25,  15 ], \
    [ 'TXT',      'g_txt',      0.15,  16 ], \
    [ 'RP',       'g_rp',       0.02,  17 ], \
    [ 'AFSDB',    'g_mx',       0.02,  18 ], \
    [ 'RT',       'g_mx',       0.02,  21 ], \
    [ 'AAAA',     'g_aaaa',     1.00,  28 ], \
    [ 'LOC',      'g_loc',      0.15,  29 ], \
    [ 'SRV',      'g_srv',      0.25,  33 ], \
    [ 'KX',       'g_mx',       0.02,  36 ], \
    [ 'CERT',     'g_cert',     0.05,  37 ], \
    [ 'DNAME',    'g_dname',    0.25,  39 ], \
    [ 'APL',      'g_apl',      0.05,  42 ], \
    [ 'SSHFP',    'g_sshfp',    0.10,  44 ], \
    [ 'IPSECKEY', 'g_ipseckey', 0.05,  45 ], \
    [ 'DNSKEY',   'g_key',      0.01,  48 ], \
    [ 'DHCID',    'g_dhcid',    0.01,  49 ], \
    [ 'SPF',      'g_spf',      0.15,  99 ], \
    [ 'CUSTOM',   'g_customrr', 0.03,   0 ]  \
]

WORDS = [
"citadel", "virmire", "feros", "noveria", "geth", "reapers", "normandy", "cerberus",
"aperture","weight","companion","science","cube","enrichment","glados","center",
"harbinger", "collector", "assuming-control", "intervention", "necessary",
"test","dev","ads","adserver","adsl","agent","channel","dmz","sz","client","imap","http",
"argos", "kepler", "armstrong", "nebula", "artemis", "hades", "nexus", "hawking", "titan",
"aldrinlabs", "devlon", "elanus", "elkoss", "hahnekedar", "haliat", "rosenkov", "sirta",
"triumph","cake","party","portal","gun","fault","alive","environment","advice",
"work","day","person","material","emancipation","grid","subject","test","mass","velocity",
"linux","windows","log","install","blog","host","printer","public","sql","mysql","router",
"protocol","area","fabric","term","case","fluid","catalyst","unit","maintenance","android",
"cisco","switch","telnet","voip","webmin","ssh","delevlop","pub","user","xml",
"telnet","extern","intranet","extranet","testing","default","gateway","radius","noc",
"mobile","customer","siprouter","sip","office","voice","support",
"spare","owa","exchange" ]

# Replace some words with random ones
for i, word in enumerate(WORDS):
    if random.choice([True, False]):
        size = random.randint(2, 20)
        WORDS[i] = ''.join(random.choice(string.hexdigits) for _ in range(size))

# For unique CNAMES/DNAMES
CNAME_EXIST = set([])
# For unique names
NAME_EXIST = set([])

# For A/AAAA names
A_NAMES = []
AAAA_NAMES = []

# Generate random number
def rnd(a, b):
    return random.randint(a, b)

def rnd_fl(a, b):
    return random.uniform(a, b)

def choice(items):
    return random.choice(items)

def rnd_hex(l):
    return '%x' % random.randrange(256**(l/2))

def rnd_str():
    i = rnd(0, len(WORDS)-1)
    word = WORDS[i]
    if rnd_fl(0, 1) < ctx.WORD_MRATE:
        i = rnd(1, len(word))
        word = word[0:i] + rnd_hex(rnd(2,8))
    return word

def rnd_dname(enable_sub = 1):
    dname = rnd_str()
    # Chance for subdomain
    if enable_sub == 1 and rnd_fl(0, 1) < ctx.SUB_CHANCE:
        dname += '.%s' % rnd_dnl(0) # DNAME must not have children
    # Chance for FQDN
    if rnd_fl(0, 1) < ctx.FQDN_CHANCE:
        dname = g_fqdn(dname)
    return dname

def rnd_dnl(enable_sub = 1):
    dn = rnd_dname(enable_sub)
    fqdn = g_fqdn(dn)
    while fqdn.lower() in CNAME_EXIST:
        dn = rnd_dname(enable_sub)
        fqdn = g_fqdn(dn)
    NAME_EXIST.add(fqdn.lower())
    return dn

def rnd_dnr():
    src = choice([A_NAMES, AAAA_NAMES])
    if len(src) == 0:
        if len(A_NAMES) > 0:
            src = A_NAMES
        else:
            src = AAAA_NAMES
    if src:
        return choice(src)
    else :
        return rnd_dname()

def rnd_ip4():
    return '%d.%d.%d.%d' % (rnd(0,255), rnd(0,255), rnd(0,255), rnd(0,255))

def rnd_ip6():
    # Private address range
    addr = 'fd9c:20c0:91fc:cb36'
    for _ in range(0,4):
        addr += ':' + rnd_hex(4)
    return addr

def rnd_srv():
    return random.choice(['sip', 'xmpp', 'ldap'])

def rnd_proto():
    return random.choice(['udp', 'tcp'])

def shuffle_str(s):
    s = list(s)
    random.shuffle(s)
    return ''.join(s)

def g_rdbin(data):
    dl = len(data)
    hs = binascii.hexlify(data).decode('ascii')
    return '\\# %d %s' % (dl, hs)

def g_rdata(rt, data, chance=30):
    if rnd(0, 100) < chance:
        cls = dns.rdataclass.IN
        tpe = dns.rdatatype.from_text(rt[0])
        rd = dns.rdata.from_text(cls, tpe, data)
        return g_rdbin(rd.to_digestable(dns.name.from_text(ctx.ORIGIN))) + ' ;rdata=' + data
    return data

def g_rtype(rt):
    if rnd_fl(0, 100) < 70: # 70%
        return rt[0]
    return "TYPE%d" % rt[3]

def g_fqdn(dn):
    if not dn.endswith('.'):
        if ctx.ORIGIN == ".":
            dn += '.'
        else:
            dn += '.%s.' % ctx.ORIGIN
    return dn

def g_customrr(rt):
    bin = rnd_hex(rnd(10,50)).encode()
    return '%s TYPE%d %s' % (rnd_dnl(), rnd(300,32767), g_rdbin(bin))

# RR Generators

def g_a(rt):
    dn = rnd_dnl(0)
    A_NAMES.append(dn)
    return '%s A %s' % (dn, rnd_ip4())

def g_aaaa(rt):
    dn = rnd_dnl(0)
    AAAA_NAMES.append(dn)
    return '%s AAAA %s' % (dn, rnd_ip6())

def g_srv(rt):
    name = '_%s._%s.%s' % (rnd_srv(), rnd_proto(), rnd_dnl())
    rdt = g_rdata(rt, '%d %d %d %s' % (rnd(1, 50), rnd(1, 50), rnd(1024, 65535), rnd_dnr()))
    return '%s %s %s' % (name, g_rtype(rt), rdt)

def g_dname(rt):
    # Ensure unique owners for CNAME/DNAME
    dn = rnd_dname()
    fqdn = g_fqdn(dn)
    while (fqdn.lower() in CNAME_EXIST) or \
          (fqdn.lower() in NAME_EXIST):
        dn = rnd_dname()
        fqdn = g_fqdn(dn)
    CNAME_EXIST.add(fqdn.lower())
    # Value (domain-name)
    rd = rnd_dnr()
    CNAME_EXIST.add(g_fqdn(rd).lower())
    return '%s %s %s' % (dn, g_rtype(rt), rd)

def g_mx(rt):
    rd = rnd_dnr()
    return '%s %s %d %s' % (rnd_dnl(), g_rtype(rt), rnd(1, 20), rd)

def g_txt(rt):
    sentences = ""
    for _ in range(1, 32):
        sentences += ' "%s"' % (' '.join(random.sample(WORDS, rnd(1, 5))))
    return '%s %s %s' % (rnd_dnl(), g_rtype(rt), g_rdata(rt, sentences, 10))

def g_loc(rt):
    rd = g_rdata(rt, '%d %d %.03f %s %d %d %.03f %s %d' % \
            ( rnd(0, 89), rnd(0, 59), rnd_fl(0, 59.99), random.choice('NS'), \
        rnd(0, 89), rnd(0, 59), rnd_fl(0, 59.99), random.choice('EW'), \
        rnd(-100, 4000)))
    return '%s %s %s' % (rnd_dnl(), g_rtype(rt), rd)

def g_spf(rt):
    choices = [ 'ip4:%s' % rnd_ip4(), 'ip6:%s' % rnd_ip6(), \
                '%s:%s' % (random.choice(['a','mx']), rnd_dname()) ]
    rd = g_rdata(rt, '"v=spf1 %s -all"' % random.choice(choices))
    return '@ IN %s %s' % (g_rtype(rt), rd)

def g_ptr(rt):
    return '%s %s %s' % (rnd_ip4(), g_rtype(rt), rnd_dname())

def g_hinfo(rt):
    pf = '%s-%dmhz' % (random.choice(['PC-Intel','ARM','PPC']), rnd(500,700))
    os = '%s %d.%d' % (random.choice(['Linux', 'BSD']), rnd(1,9), rnd(1,9))
    return '%s %s %s "%s"' % (rnd_dnl(), g_rtype(rt), pf, os)

def g_rp(rt):
    # name ttl class rr email-addr
    return '%s %s %s %s' % \
           (rnd_dnl(), g_rtype(rt), g_fqdn('admin.'+rnd_str()), g_fqdn('sysadmins.'+rnd_str()))

def g_nsap(rt):
    # name ttl class rr nsap-address
    # TODO: Dynamic address
    return '%s %s %s' % (rnd_dnl(), g_rtype(rt), \
           g_rdata(rt, '0x%s' % '47.0005.80.005a00.0000.0001.e133.ffffff000161.00'))

def g_dhcid(rt):
    # TODO: bogus data, described in RFC4701 as DNS Binary RR format
    return '%s %s %s' % \
           (rnd_dnl(), g_rtype(rt), g_rdata(rt, 'VGhpcyBzaG9ydCBzbmlwcGV0IG9mIHRleHQgaXMgc2FkIGFuZCBtZWFuaW5nbGVzcy4K'))

def g_cert(rt):
    # name ttl class rr type key-tag algorithm cert-crl
    # TODO: dnssec-keygen generated values (slow?)
    # TODO: values from book Pro DNS and BIND 10
    rd = g_rdata(rt, '%d 12179 3 %s' % \
           (rnd(1,8), 'VGhpcyBzaG9ydCBzbmlwcGV0IG9mIHRleHQgaXMgc2FkIGFuZCBtZWFuaW5nbGVzcy4K'))
    return '%s %s %s' % (rnd_dnl(), g_rtype(rt), rd)

def g_key(rt):
    # name ttl class rr flags proto algorithm key-data
    # TODO: values from book Pro DNS and BIND 10
    rd = g_rdata(rt, '%d 3 %d %s' % \
           (256, rnd(1,5), 'VGhpcyBzaG9ydCBzbmlwcGV0IG9mIHRleHQgaXMgc2FkIGFuZCBtZWFuaW5nbGVzcy4K'))
    return '%s %s %s' % (rnd_dnl(), g_rtype(rt), rd)

def g_sshfp(rt):
    key = shuffle_str('123456789abcdef67890123456789abcdef67890')
    rd = g_rdata(rt, '%d %d %s' % (choice([1,2]), 1, key))
    return '%s %s %s' % (rnd_dnl(), g_rtype(rt), rd)

def g_ipseckey(rt):
    # precedence gw-type algorithm gw pubkey
    # TODO: Doesn't make much sense in non-reverse zones
    dn = rnd_ip4()
    NAME_EXIST.add(dn.lower())
    prec = rnd(1,20)
    gwtype = 3 #rnd(1, 3) # TODO: fix, 1,2 needs valid IPs as dnames in zone
    algo = rnd(1, 2)
    gw = ''
    if gwtype == 1:
        gw = rnd_ip4()
    elif gwtype == 2:
        gw = rnd_ip6()
    else:
        gw = rnd_dnl()
    pkey = 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ=='
    rd = g_rdata(rt, '%d %d %d %s %s' % (prec, gwtype, algo, gw, pkey))
    return '%s IN %s %s' % (dn, g_rtype(rt), rd)

def g_apl(rt):
    data = ''
    dcount = rnd(1,3)
    for _ in range(0, dcount):
        afi = choice([1, 2])
        ip = ''
        if afi == 1:
            ip = rnd_ip4()
        else:
            ip = rnd_ip6()
        data += '%s%d:%s/%d ' % (choice(['!','']), afi, ip, rnd(2,32))
    return '%s %s %s' % (rnd_dnl(), g_rtype(rt), g_rdata(rt, data))

# Generate RR
def gen_rr():
    rd = random.choice(RRTYPES)
    if rnd_fl(0,1) < rd[2]:
        f = globals()[rd[1]]
        if f is None:
            return None
        return '%s' % (f(rd))
    else:
        return None

# Generate reverse RR
# @TODO non-RFC2317 reverse zones
def gen_rr_rev(dn):
    return '%s\tPTR\t%s' % (dn, g_fqdn(rnd_dnl()))

# Generate SOA
def gen_soa(origin, serial, ttl, auth = None):
    refresh = 3600
    if origin != '.':
        origin += '.'
    soa =  ''
    soa += '$TTL %d\n' % ttl
    s = '@ IN SOA %s %s' % (g_fqdn('ns'), g_fqdn('username'))
    s += ' %s %d %d %s %s\n' % (serial, refresh, refresh / 3, '4w', ttl )
    if auth != None:
        if auth != '.':
            auth += '.'
        soa += '$ORIGIN %s\n' % auth
        soa += s
        soa += '@ NS ns.%s\n' % origin
        soa += '@ NS ns2.%s\n' % origin
        soa += '; END OF SOA\n'
    else:
        soa += '$ORIGIN %s\n' % origin
        soa += s
        soa += '@ NS ns\n'
        soa += '@ NS ns2\n'
        soa += 'ns A %s\n' % rnd_ip4()
        soa += 'ns2 A %s\n' % rnd_ip4()
        soa += '; END OF SOA\n'
    return soa

# Generate unique zone names
GENERATED = set([])
def g_unique():
    dn = rnd_dnl()
    while dn.lower() in GENERATED:
        dn = rnd_dnl()
    GENERATED.add(dn.lower())
    return dn

def g_unique_names(count):
    ctx.FQDN_CHANCE = 0.0
    ctx.SUB_CHANCE = 0
    ctx.ORIGIN = g_unique()
    ctx.SUB_CHANCE = 0.2
    ctx.WORD_MRATE = 0.3
    o = ''
    for _ in range(0, count):
        if rnd(0,1) < ctx.SUB_CHANCE:
            ctx.ORIGIN = rnd_dnl()
        o += g_unique() + ' '

    if __name__ == "__main__":
        print(o)
        return 0
    else:
        return o

def main(args):
    serial = '2020091813'
    ttl = random.randint(1800, 18000)
    count = 100
    UPDATE = None
    sign = 0
    nsec3 = random.choice([True, 0, False])
    out_fname = None
    key_dir = None

    # Parse parameters
    try:
        opts, args = getopt.getopt(args, 'hs3:i:u:n:t:o:k:c:', ['help', 'sign',
                                   'nsec3=', 'serial=', 'update=', 'names=',
                                   'ttl=', 'outfile=', 'keydir=', 'count='])
    except getopt.error as msg:
        print(msg)
        print('for help use --help')
        sys.exit(2)

    for o, a in opts:
        if o in ('-h', '--help'):
            print(__doc__)
            sys.exit(0)
        if o in ('-s', '--sign'):
            sign = 1
        if o in ('-3', '--nsec3'):
            if a == 'y':
                nsec3 = True
            elif str(a) == "0":
                nsec3 = 0
            else:
                nsec3 = False
        if o in ('-i', '--serial') and a != None:
            serial = a
        if o in ('-u', '--update') and a != None:
            UPDATE = a
        if o in ('-n', '--names') and a != None:
            return g_unique_names(int(a))
        if o in ('-t', '--ttl') and a != None:
            ttl = int(a)
        if o in ('-o', '--outfile') and a != None:
            out_fname = a
        if o in ('-k', '--keydir') and a != None:
            key_dir = a
        if o in ('-c', '--count') and a != None:
            count = int(a)

    # Check arguments
    if len(args) > 1:
        print('Too many arguments.')
        print(__doc__)
        sys.exit(2)

    # Parse non-option arguments
    if args:
        a = args[0]
        if a != '.':
            a = a.rstrip('.')
        ctx.ORIGIN = a

    # Check values
    if not out_fname:
        out_fname = UPDATE if UPDATE else ctx.ORIGIN + '.zone'

    # Reverse zones
    if ctx.ORIGIN.find('in-addr') > 0:
        ctx.RORIGIN = ctx.ORIGIN
        ctx.ORIGIN = rnd_str()
        pp = ctx.RORIGIN.find('/')
        if pp > 0:
            ctx.RPREFIX = int(ctx.RORIGIN[0:pp])

    tmp_dir = tempfile.mkdtemp()
    in_fname = tmp_dir + '/zfile'

    # Open zone file
    if UPDATE:
        shutil.copyfile(UPDATE, in_fname)

        # Disable additional CNAME generation
        for idx, val in enumerate(RRTYPES):
            if val[0] == 'CNAME':
                RRTYPES[idx][2] = 0

    outf = open(in_fname, "a")

    if not UPDATE:
        outf.write(gen_soa(ctx.ORIGIN, serial, ttl, ctx.RORIGIN))

    # Check if prefix exists
    if ctx.RPREFIX != None and count > ctx.RPREFIX:
        count = ctx.RPREFIX - 1  # <1,RPREFIX)

    # @TODO update reverse zone
    if UPDATE and ctx.RPREFIX != None:
        count = 0

    # Now generate RRs
    a_pool = count / 10
    if a_pool > 1000:
        a_pool = 1000
    for i in range(0, count):
        # Make a batch of A/AAAAs at start
        rr = None
        if ctx.RORIGIN != None: # Reverse zone records
            rr = gen_rr_rev(i + 1)
        elif i < a_pool:
            if rnd(0,1.0) < 0.5:
                rr = g_a('A')
            else:
                rr = g_aaaa('AAAA')
        else:
            # Select until it generates valid RR
            # This crudely implements weighted distribution
            while rr is None:
                rr = gen_rr()
        outf.write(rr + '\n')

    # Return if no signing is required
    if sign == 0:
        outf.close()
        shutil.copyfile(in_fname, out_fname)
        shutil.rmtree(tmp_dir)
        return 0

    # Now sign if requested
    if not key_dir:
        key_dir = tmp_dir

    ret = 1
    try:
        # Generate keys
        ps = [ 'dnssec-keygen', '-n', 'ZONE', '-a', 'RSASHA256', '-b', '1024', '-K', key_dir ]
        if nsec3 is not False:
            ps += ['-3']
        k1 = subprocess.check_output(ps + [ctx.ORIGIN], stderr=subprocess.DEVNULL)
        k2 = subprocess.check_output(ps + ["-f", "KSK"] + [ctx.ORIGIN], stderr=subprocess.DEVNULL)
        k1 = key_dir + '/' + k1.rstrip().decode('ascii')
        k2 = key_dir + '/' + k2.rstrip().decode('ascii')

        # Append to zone
        kf = open(k1 + '.key', 'r')
        outf.write(kf.read() + '\n')
        kf.close()
        kf = open(k2 + '.key', 'r')
        outf.write(kf.read() + '\n')
        kf.close()

        outf.close()

        if nsec3 is False:
            nsec3_params = []
        elif nsec3 == 0:
            nsec3_params = ['-3', '-']
        else:
            nsec3_params = ['-3', binascii.hexlify(os.urandom(random.randint(1, 30))).decode('ascii')]

        subprocess.check_output(["dnssec-signzone", "-d", tmp_dir, "-P", "-u", \
                                 "-k", k2, "-x", "-o", ctx.ORIGIN, \
                                 "-O", "full"] + nsec3_params + [in_fname, k1 + ".key"],
                                 stderr=subprocess.DEVNULL)
        shutil.copyfile(in_fname + '.signed', out_fname)
        ret = 0
    except:
        pass
    else:
        shutil.rmtree(tmp_dir)

    return ret

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
