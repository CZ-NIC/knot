#!/usr/bin/python
from scapy.all import *
from binascii import *
import base64
import sys
import dns.rdata
import dns.rrset
from struct import *

fr = open(sys.argv[1] + ".raw_data", 'wb')
fp = open(sys.argv[1] + ".parsed_data", 'wb')

def chop_and_write_rr_query(rr):
	name = dns.name.from_text(rr.qname)
#	print rr.qname

	wire = name.to_wire()
	fp.write(pack('B', len(wire)))
#	print len(wire)
	fp.write(wire)
	fp.write(pack('H', rr.qtype))
	fp.write(pack('H', rr.qclass))

def chop_and_write_rr_response(rr):
	name = dns.name.from_text(rr.rrname)
#	print rr.rrname

	wire = name.to_wire()
	fp.write(pack('B', len(wire)))
	fp.write(wire)
	fp.write(pack('H', rr.type))
	fp.write(pack('H', rr.rclass))
	fp.write(pack('L', rr.ttl))

	try:
		rdata = dns.rdata.from_wire(rr.rclass, rr.type, rr.rdata, 0, len(rr.rdata))
		fp.write(pack('H', len(rr.rdata)))
#		print "type ", rr.type, "length ", len(rr.rdata)
#		OPT has length 0 - it should have no rdata
		rdata.to_wire(fp)
	except:

		try:
#			if rr.rdata[0] != '\#':
			rdata = dns.rdata.from_text(rr.rclass, rr.type, rr.rdata)
			try:
				fp.write(pack('H', len(rdata)))
			except:
				# no length - no way to know wire length
				try:
#					print "unknown length for type", rr.type
#						if rr.type == 2:
#							fp.seek(1, 1)
#							old = fp.tell()
#							rdata.to_wire(fp)
#							size = fp.tell() - old
#							fp.seek(-(size + 1), 1)
#							fp.write(pack('B', size))
#							fp.seek(0, 2)
#						else:
					rdata.to_wire(fp)
				except Exception as e:
					print 'Error, exiting: ', e
					sys.exit(-1)
		except Exception as e:
			print 'Error,', e
			print 'could not parse rdata type: ', rr.type
			print 'dumping directly (hopefully it is SOA)'
# i need to do some kind of rollback here...
			fp.write(pack('H', len(rr.rdata)))
			fp.write(rr.rdata)

	
	if rr.type == 50:
		f = open('nsec3debug', 'wb')
		rdata.to_wire(f)
		f.close()

def chop_and_write_section_response(section):
	if section == None:
		return
	i = 0
	rr = section.getlayer(i);
	while rr != None:
		chop_and_write_rr_response(rr)
		i += 1
		rr = section.getlayer(i)

def chop_and_write_section_query(section):
	if section == None:
		return
	i = 0
	rr = section.getlayer(i);
	while rr != None:
		chop_and_write_rr_query(rr)
		i += 1
		rr = section.getlayer(i)

def chop_and_write_packet(packet):
	fp.write(pack('H', packet.id))
#	fp.write(pack('H', packet.qr))
#	fp.write(pack('H', packet.opcode))
#	fp.write(pack('H', packet.aa)) #TODO these are not uint16_t
#	fp.write(pack('H', packet.rcode)) 
	fp.write(pack('H', packet.qdcount))
	fp.write(pack('H', packet.ancount))
	fp.write(pack('H', packet.nscount))
	fp.write(pack('H', packet.arcount))
	
#write query flag
	fp.write(pack('H', packet.qr))

	chop_and_write_section_query(packet.qd)
	chop_and_write_section_response(packet.an)
	chop_and_write_section_response(packet.ns)
	chop_and_write_section_response(packet.ar)

packets = rdpcap(sys.argv[1])

total_length = len(packets)

fr.write(pack('L', total_length))
fp.write(pack('L', total_length))

for packet in packets:
	try:
		data = a2b_hex(str(packet['DNS']).encode('hex'))
		fr.write(pack('H', packet.qr))
		fr.write(pack('H', len(data)))
		fr.write(data)
		chop_and_write_packet(packet['DNS'])
	except IndexError:
		print 'non-DNS packet'
		total_length -= 1

fr.seek(0)
fp.seek(0)

fr.write(pack('L', total_length))
fp.write(pack('L', total_length))

print 'written ', total_length, 'packets'

fr.close()
fp.close()
