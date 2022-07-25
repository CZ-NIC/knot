#!/usr/bin/env python3
#
# A simple Knot DNS probe client
#

import argparse
import libknot
import libknot.probe
import sys


def probe_loop(args):
    try:
        libknot.Knot(args.libknot_path)
    except:
        print("Cannot find shared library libknot.so")
        sys.exit(1)

    probe = libknot.probe.KnotProbe(args.probe_dir, args.channel)
    data = libknot.probe.KnotProbeDataArray(8)

    try:
        while (True):
            if probe.consume(data, 1000) > 0:
                for item in data:
                    print(item.str(color=not args.no_color, timestamp=not args.no_timestamp))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class = argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-l", "--libknot-path",
        help="path to the libknot shared library"
    )
    parser.add_argument(
        "-d", "--probe-dir",
        default="/run/knot",
        help="path to the probe directory"
    )
    parser.add_argument(
        "-c", "--channel",
        type=int,
        default=1,
        help="the probe channel"
    )
    parser.add_argument(
        "--no-color",
        action='store_true',
        help="don't colorize the output"
    )
    parser.add_argument(
        "--no-timestamp",
        action='store_true',
        help="don't print the current timestamp"
    )
    args = parser.parse_args()

    probe_loop(args)
