#!/usr/bin/python
from scapy.all import *
import sys

nstypes = { 0:"ANY", 255:"ALL",1:"A", 2:"NS", 3:"MD", 4:"MD", 5:"CNAME", 6:"SOA", 7: "MB", 8:"MG", 9:"MR",10:"NULL",11:"WKS",12:"PTR",13:"HINFO",14:"MINFO",15:"MX",16:"TXT", 17:"RP",18:"AFSDB",28:"AAAA", 33:"SRV",38:"A6",39:"DNAME"}

a=rdpcap(sys.argv[1]);

f=open(sys.argv[2], 'w');

for i in a:
  try:
    f.write(i[3].qname+' '+nstypes[i[3].qtype]+'\n')
  except:
    continue

f.close()
