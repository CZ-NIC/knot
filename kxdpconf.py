#!/usr/bin/env python3

# Dependencies:
#   pip install argparse enum
#   sudo apt install python3-bpfcc

from argparse import ArgumentParser, ArgumentTypeError
from bcc import BPF
from enum import IntFlag

class Flags(IntFlag):
	ENABLED = 1 << 0
	UDP  = 1 << 1
	TCP  = 1 << 2
	QUIC = 1 << 3

bpf_template = r'''
	struct knot_xdp_opts {
		u16 flags;
		u16 udp_port;
		u16 quic_port;
	} __attribute__((packed));
	BPF_TABLE_PINNED("array", u32, struct knot_xdp_opts, opts_map, 256, "/sys/fs/bpf/knot/opts_%s");
'''
# Parse arguments
def parse_u16(value):
	try:
		unsigned_short_value = int(value)
		if 0 <= unsigned_short_value <= 65535:
			return unsigned_short_value
		else:
			raise ArgumentTypeError("Value must be an unsigned short (0 to 65535)")
	except ValueError:
		raise ArgumentTypeError("Invalid unsigned short value")

def parse_on_off(value):
    if value.lower() == 'on':
        return True
    elif value.lower() == 'off':
        return False
    else:
        raise ArgumentTypeError("Invalid value for --udp. Use 'on', 'off', or leave it unspecified.")

parser = ArgumentParser(description="Your script description.")
parser.add_argument("interfaces", nargs="+", help="List of interfaces")
parser.add_argument("-u", "--udp", type=parse_on_off, default=None, choices=["on", "off"], help="Enable/disable UDP")
parser.add_argument("-t", "--tcp", type=parse_on_off, default=None, choices=["on", "off"], help="Enable/disable TCP")
parser.add_argument("-q", "--quic", type=parse_on_off, default=None, choices=["on", "off"], help="Enable/disable QUIC")
parser.add_argument("-p", "--port", type=parse_u16, default=None, help="Specify UDP/TCP port")
parser.add_argument("-Q", "--quic_port", type=parse_u16, default=None, help="Specify QUIC port")
parser.add_argument("-V", "--version", action="version", version="Your Script Version 0.0.1")
args = parser.parse_args()

# For each interface
for iface in args.interfaces:
	# Compile BPF filter
	bpf = bpf_template % iface
	try:
		xdp_stats_map = BPF(text=bpf, cflags=['-w']).get_table('opts_map')
	except Exception as e:
		print(f"Error: Unable to locate 'opts_map' related to '%s'. Is server running?" % iface)
		continue

	# For each key-value pair in 'opts_map'
	for k, v in xdp_stats_map.items():
		if (not v.flags & Flags.ENABLED):
			continue

		if args.udp is True:
			v.flags |= Flags.UDP
		elif args.udp is False:
			v.flags ^= Flags.UDP

		if args.tcp is True:
			v.flags |= Flags.TCP
		elif args.tcp is False:
			v.flags ^= Flags.TCP

		if args.quic is True:
			v.flags |= Flags.QUIC
		elif args.quic is False:
			v.flags ^= Flags.QUIC

		if args.port is not None:
			v.udp_port = args.port

		if args.quic_port is not None:
			v.quic_port = args.quic_port

		xdp_stats_map[k] = v