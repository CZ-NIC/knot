#!/usr/bin/env python3

'''
Usage: zone_generate.py [parameters] origin [rr_count]
Parameters:
    -h, --help         This help.
    -s, --sign         Generate zone signed with dnssec-signzone.
    -i, --serial=num   Specify SOA serial.
    -u, --update=file  Update zone file (no extra SOA).
    -n, --names=num    Generate unique zone names.
    -t, --ttl=sec      Specify default TTL.
    -o, --outfile=file Specify output file name.
'''

import random
import getopt
import sys
import re
import tempfile
import subprocess
import shutil
import binascii
import dns
import dns.rdataclass
import dns.rdatatype
import dns.rdata

# Word databases
ORIGIN = '' # Zone origin (default=com)
RORIGIN = None # Domain for reverse zones
RPREFIX = None # Zone is RPREFIX classless-type
WORD_MRATE = 1.0 # 0.0 - 1.0, percentage of mangled words
RR_EXISTS = 1.0 # 0.0 - 1.0, percentage of CNAME/DNAME... pointing to existing name
SUB_CHANCE = 0.0 # 0.0 - 1.0, chance of dname bing a subdomain
FQDN_CHANCE = 0.5 # 0.0 - 1.0, chance for FQDN
WILD_IN_SUB = 0.0 # 0.0 - 1.0, chance of wildcard in case of subdomain
ENABLE_BINRTYPE = True # Enable RR type format as 'TYPEXXXX'
ENABLE_BINRR = True # Enable RR data in binary format
TTL = random.randint(1800, 18000)

# Defaults
SERIAL = '2007120713'
SERVICES = [ 'sip', 'xmpp', 'ldap' ]
PROTOCOLS = [ 'udp', 'tcp' ]

RRTYPES = [ \
#   [ typename, generator, probability, typeid ]
    [ 'A',        'g_a',        1.00,   1 ], \
    [ 'NS',       'g_dname',    0.25,   2 ], \
    [ 'CNAME',    'g_dname',    0.25,   5 ], \
    [ 'PTR',      'g_ptr',      0.50,  12 ], \
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
    if rnd_fl(0, 1) < WORD_MRATE:
        i = rnd(1, len(word))
        word = word[0:i] + rnd_hex(rnd(2,8))
    return word

def rnd_dname(enable_sub = 1):
    dname = rnd_str()
    # Chance for subdomain
    if enable_sub == 1 and rnd_fl(0, 1) < SUB_CHANCE:
        dname += '.%s' % rnd_dnl(0) # DNAME must not have children
    # Chance for FQDN
    if rnd_fl(0, 1) < FQDN_CHANCE:
        dname = g_fqdn(dname)
    return dname

def rnd_dnl(enable_sub = 1):
    dn = rnd_dname(enable_sub)
    fqdn = g_fqdn(dn)
    while fqdn in CNAME_EXIST:
        dn = rnd_dname(enable_sub)
        fqdn = g_fqdn(dn)
    NAME_EXIST.add(fqdn)
    return dn

def rnd_dnr():
    src = choice([A_NAMES, AAAA_NAMES])
    if len(src) == 0:
        if len(A_NAMES) > 0:
            src = A_NAMES
        else:
            src = AAAA_NAMES
    if src and (rnd_fl(0.0, 1.0) <= RR_EXISTS):
        return choice(src)
    else :
        return rnd_dname()

def rnd_ip4():
    return '%d.%d.%d.%d' % (rnd(0,255), rnd(0,255), rnd(0,255), rnd(0,255))

def rnd_ip6():
    # Private address range
    addr = 'fd9c:20c0:91fc:cb36'
    for i in range(0,4):
        addr += ':' + rnd_hex(4)
    return addr

def rnd_srv():
    return random.choice(SERVICES)

def rnd_proto():
    return random.choice(PROTOCOLS)

def shuffle_str(s):
    s = list(s)
    random.shuffle(s)
    return ''.join(s)

def g_rdbin(data):
    dl = len(data)
    hs = binascii.hexlify(data).decode('ascii')
    return '\\# %d %s' % (dl, hs)

def g_rdata(rt, data, chance=30):
    if ENABLE_BINRR and rnd(0, 100) < chance:
        cls = dns.rdataclass.IN
        tpe = dns.rdatatype.from_text(rt[0])
        rd = dns.rdata.from_text(cls, tpe, data)
        return g_rdbin(rd.to_digestable(dns.name.from_text(ORIGIN))) + ' ;rdata=' + data
    return data

def g_rtype(rt):
    if rnd_fl(0, 100) < 70: # 30%
        return rt[0]
    return "TYPE%d" % rt[3]

def g_fqdn(dn):
    if not dn.endswith('.'):
        if ORIGIN == ".":
            dn += '.'
        else:
            dn += '.%s.' % ORIGIN
    return dn

def g_customrr(rt):
    bin = rnd_hex(rnd(10,50)).encode()
    return '%s TYPE%d %s' % (rnd_dnl(), rnd(258,32767), g_rdbin(bin))

# RR Generators

def g_a(rt):
    dn = rnd_dnl(0)
    # Chance for wildcard
    if rnd_fl(0.0, 1.0) < WILD_IN_SUB:
        # Append some valid names
        for i in range(1, rnd(2,5)):
            A_NAMES.append(g_fqdn(rnd_str() + '.' + dn))
        NAME_EXIST.add(g_fqdn(dn))
        dn = '*.%s' % dn
    else:
        A_NAMES.append(dn)
    return '%s A %s' % (dn, rnd_ip4())

def g_aaaa(rt):
    dn = rnd_dnl(0)
    # Chance for wildcard
    if rnd_fl(0.0, 1.0) < WILD_IN_SUB:
        # Append some valid names
        for i in range(1, rnd(2,5)):
            AAAA_NAMES.append(g_fqdn(rnd_str() + '.' + dn))
        NAME_EXIST.add(g_fqdn(dn))
        dn = '*.%s' % dn
    else:
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
    while (fqdn in CNAME_EXIST) or (fqdn in NAME_EXIST):
        dn = rnd_dname()
        fqdn = g_fqdn(dn)
    CNAME_EXIST.add(fqdn)
    # Value (domain-name)
    rd = rnd_dnr()
    CNAME_EXIST.add(g_fqdn(rd))
    return '%s %s %s' % (dn, g_rtype(rt), rd)

def g_mx(rt):
    rd = rnd_dnr()
    return '%s %s %d %s' % (rnd_dnl(), g_rtype(rt), rnd(1, 20), rd)

def g_txt(rt):
    sentences = ""
    for i in range(1, 32):
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
    NAME_EXIST.add(dn)
    prec = rnd(1,20)
    gwtype = 3 #rnd(1, 3) # TODO: fix, 1,2 needs valid IPs as dnames in zone
    algo = rnd(1, 2)
    gw = ''
    if gwtype is 1:
        gw = rnd_ip4()
    elif gwtype is 2:
        gw = rnd_ip6()
    else:
        gw = rnd_dnl()
    pkey = 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ=='
    rd = g_rdata(rt, '%d %d %d %s %s' % (prec, gwtype, algo, gw, pkey))
    return '%s IN %s %s' % (dn, g_rtype(rt), rd)

def g_apl(rt):
    data = ''
    dcount = rnd(1,3)
    for i in range(0, dcount):
        afi = choice([1, 2])
        ip = ''
        if afi is 1:
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
def gen_soa(origin, serial, auth = None):
    refresh = 10
    if origin != '.':
        origin += '.'
    soa =  ''
    soa += '$TTL %d\n' % TTL
    s = '@ IN SOA %s %s' % (g_fqdn('ns'), g_fqdn('username'))
    s += '( %s %d %d %s %s )\n' % (serial, refresh, refresh * 3, '4w', '1h' )
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
    while dn in GENERATED:
        dn = rnd_dnl()
    GENERATED.add(dn)
    return dn

def g_unique_names(count):
    global SUB_CHANCE
    global WORD_MRATE
    global ORIGIN
    global FQDN_CHANCE
    global TTL
    FQDN_CHANCE = 0.0
    SUB_CHANCE = 0
    ORIGIN = g_unique()
    SUB_CHANCE = 0.2
    WORD_MRATE = 0.3
    o = ''
    for i in range(0, count):
        if rnd(0,1) < SUB_CHANCE:
            ORIGIN = rnd_dnl()
        o += g_unique() + ' '

    if __name__ == "__main__":
        print(o)
        return 0
    else:
        return o

def main(args):
    global ORIGIN
    global SERIAL
    global TTL
    global RORIGIN
    global RPREFIX
    UPDATE = None
    sign = 0
    count = 0
    outfile = None

    # Parse parameters
    try:
        opts, args = getopt.getopt(args, 'hsi:u:n:t:o:', ['help', 'sign', 'serial=',
                                   'update=', 'names=', 'ttl=', 'outfile='])
    except getopt.error as msg:
        print(msg)
        print('for help use --help')
        sys.exit(2)

    for o, a in opts:
        if o in ('-h', '--help'):
            print(__doc__)
            sys.exit(0)
        if o in ('-s', '--sign'):
            sign=1
        if o in ('-i', '--serial') and a != None:
            SERIAL = a
        if o in ('-u', '--update') and a != None:
            UPDATE = a
        if o in ('-n', '--names') and a != None:
            return g_unique_names(int(a))
        if o in ('-t', '--ttl') and a != None:
            TTL = int(a)
        if o in ('-o', '--outfile') and a != None:
            outfile = a

    ORIGIN = ""
    # Arguments
    if len(args) > 2:
        print('Too many arguments.')
        print(__doc__)
        sys.exit(2)
    for a in args:
        if len(ORIGIN) == 0:
            if a != '.':
                a = a.rstrip('.')
            ORIGIN = a
        else:
            count = int(a)
    # Check values
    if count == 0:
        count = 100 # (default)
    if len(ORIGIN) == 0:
        ORIGIN = 'com'

    # Reverse zones
    if ORIGIN.find('in-addr') > 0:
        RORIGIN = ORIGIN
        ORIGIN = rnd_str()
        pp = RORIGIN.find('/')
        if pp > 0:
            RPREFIX = int(RORIGIN[0:pp])

    # Load DB if updating
    soa = None
    outf = open(outfile, "w") if outfile else sys.stdout
    if UPDATE != None:
        outf = open(UPDATE, 'r+')
        NAME_EXIST.add(g_fqdn(ORIGIN))

        # Load DB
        for l in outf:
            l = l.replace('\t', ' ').strip().split()
            if len(l) < 2:
                continue
            if len(l) > 4:
                l = l[0:4] + [ '' ]
            # Remove lines without starting dname
            l[0] = l[0].strip()
            if l[0].startswith('@') or l[0].startswith('$') or l[0].startswith(';'):
                continue

            # Enroll dname as existing
            NAME_EXIST.add(g_fqdn(l[0]))

            # Shift class,ttl fields
            rt = ''
            for i in range(1, len(l)-1):
                l[1] = l[1].strip()
                if l[1].lower() != 'in' and (l[1].isalpha() or l[1].startswith('TYPE')) and l[1].isupper():
                    rt = l[1]
            if len(rt) == 0:
                continue

            # Add names
            names = []
            if l[0].startswith('*'):
                NAME_EXIST.add(g_fqdn(l[0][2:]))
                for i in range(2,6):
                    names.append('%s%s' % (rnd_str(), l[0][1:]))
            else:
                names.append(l[0])
            for n in names:
                if rt == 'A':
                    A_NAMES.append(g_fqdn(n))
                if rt == 'AAAA':
                    AAAA_NAMES.append(g_fqdn(n))
                if rt == 'CNAME' or rt == 'DNAME':
                    CNAME_EXIST.add(g_fqdn(n))
                if rt == 'TYPE5' or rt == 'TYPE39':
                    CNAME_EXIST.add(g_fqdn(n))

        # Seek END
        outf.seek(0, 2)
    else:
        # Generate SOA RR
        soa = gen_soa(ORIGIN, SERIAL, RORIGIN)

    # Signed zone workarounds
    sign_dir = None
    tmp_zfile = None
    if sign != 0:
        sign_dir = tempfile.mkdtemp()
        if UPDATE == None:
            tmp_zfile = open(sign_dir + "/zfile", 'w')
        else:
            tmp_zfile = outf
        if soa != None:
            tmp_zfile.write(soa)
    else:
        if soa != None:
            outf.write(soa)

    # Check if prefix exists
    if RPREFIX != None and count > RPREFIX:
        count = RPREFIX - 1  # <1,RPREFIX)

    # @TODO update reverse zone
    if UPDATE and RPREFIX != None:
        count = 0

    # Now generate RRs
    a_pool = count / 10
    if a_pool > 1000:
        a_pool = 1000
    for i in range(0, count):
        # Make a batch of A/AAAAs at start
        rr = None
        if RORIGIN != None: # Reverse zone records
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
        if sign != 0:
            tmp_zfile.write(rr + '\n')
        else:
            outf.write(rr + '\n')

    # Return if no signing is required
    if sign == 0:
        outf.write('\n');
        if outf != sys.stdout:
            outf.close()
        return 0

    # Now sign if requested
    ret = 1
    zfname = tmp_zfile.name
    try:
        # Generate keys
        nf = open('/dev/null', 'w')
        ps = [ 'dnssec-keygen', '-r', '/dev/urandom', '-3', '-n', 'ZONE', '-K', sign_dir ]
        k1 = subprocess.check_output(ps + [ORIGIN], stderr=nf)
        k2 = subprocess.check_output(ps + ["-f", "KSK"] + [ORIGIN], stderr=nf)
        k1 = sign_dir + '/' + k1.rstrip().decode('ascii')
        k2 = sign_dir + '/' + k2.rstrip().decode('ascii')
        nf.close()

        # Append to zone
        kf = open(k1 + '.key', 'r')
        tmp_zfile.write(kf.read() + '\n')
        kf.close()
        kf = open(k2 + '.key', 'r')
        tmp_zfile.write(kf.read() + '\n')
        kf.close()

        # Sign zone
        if tmp_zfile != outf:
            tmp_zfile.close()
        ks = subprocess.check_output(["dnssec-signzone", "-d", "/tmp", "-P", "-p", "-u", \
                                      "-3", "deadbeef", "-k", k2, "-r", "/dev/urandom", \
                                      "-o", ORIGIN, zfname, k1 + ".key"])
        kf = open(zfname + '.signed')
        outf.write(kf.read())
        kf.close()
        if outf != sys.stdout:
            outf.close()
        ret = 0
    except:
        pass
    else:
        shutil.rmtree(sign_dir)

    return ret

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
