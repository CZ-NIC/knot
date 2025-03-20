#!/usr/bin/env python3

import os
import re
import argparse

def replace_license_header(directory):
    old_license_pattern = re.compile(r"""/\*\s*(Copyright \(C\) \d{4} .*?\n\s*)+\n\s*This program is free software: you can redistribute it and/or modify\n\s*it under the terms of the GNU General Public License as published by\n\s*the Free Software Foundation, either version 3 of the License, or\n\s*\(at your option\) any later version\.\n\n\s*This program is distributed in the hope that it will be useful,\n\s*but WITHOUT ANY WARRANTY; without even the implied warranty of\n\s*MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE\.  See the\n\s*GNU General Public License for more details\.\n\n\s*You should have received a copy of the GNU General Public License\n\s*along with this program\.  If not, see <https://www\.gnu\.org/licenses/>\.\n\s*\*/""", re.MULTILINE)

    new_license = """/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */"""

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.c', '.h', '.rl', '.h.in')):  # Process C and header files
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                new_content = old_license_pattern.sub(new_license, content)

                if new_content != content:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    print(f"Updated license in: {file_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replace license headers in C and header files.")
    parser.add_argument("directory", type=str, help="Target directory to scan for files.")
    args = parser.parse_args()

    replace_license_header(args.directory)
