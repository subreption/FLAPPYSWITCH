#!/usr/bin/env python3
# Copyright (C) 2025 ff794e44ea1c2b5211a3b07c57b5a3813f87f53ac10d78e56b16b79db6ff9615
#                    b726ae7cf45cc4dfa8de359caffb893209bca614d9387a7666b106052fba3e50
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.
#
# DMCA Security Research Exemption:
# Good faith security research conducted consistent with 17 U.S.C. §1201(j) and
# 37 CFR §201.40(b)(7) is explicitly permitted.
#
# This software is intended solely for educational, forensic, and lawful
# security research purposes. Any use of this software for offensive or harmful
# purposes is expressly prohibited.
#
# DISCLAIMER:
# The author disclaims any responsibility or liability for any direct, indirect,
# incidental, or consequential damages or losses resulting from the use or
# misuse of this software. Users bear full responsibility for compliance with
# applicable laws and regulations.
#
# Use, modification, or distribution constitutes explicit agreement to all terms
# above.

import sys
import os
import struct
import zlib

"""
Creates a FUNK-format file with:

Global Header (268 bytes total):
  0..3    : b'FUNK' (magic)
  4..7    : total_length (uint32, LE) = size of entire file (header + all TLVs)
  8..11   : header_checksum (uint32, LE) [CRC32 of the 268 bytes except these 4]
  12..267 : key buffer (256 bytes)

TLVs (repeated):
  - Type (4 bytes, LE)
  - Length (4 bytes, LE) [of payload]
  - Payload (variable)
  - CRC32 (4 bytes, LE)   [CRC of payload]

TLV Types:
  1: COMMAND -> 1024 bytes of ASCII (zero-padded), plus a 4-byte CRC
  2: FILE    -> 1024-byte destination (zero-padded or truncated) + file_data, plus a 4-byte CRC

Usage Example:
  python create_funk.py output.funk \
      command "ls -al" \
      file /tmp/dest localfile.bin
"""

TLV_TYPE_COMMAND = 1
TLV_TYPE_FILE    = 2

FIXED_COMMAND_SIZE  = 1024
FIXED_DEST_SIZE     = 1024
GLOBAL_HEADER_SIZE  = 268  # 4 + 4 + 4 + 256

def build_command_payload(command_str):
    """
    Build the COMMAND payload (1024 bytes).
    If command_str is longer than 1024, it is truncated.
    Otherwise zero-padded to 1024.
    """
    cmd_bytes = command_str.encode('utf-8', errors='replace')
    cmd_bytes = cmd_bytes[:FIXED_COMMAND_SIZE]  # truncate if longer
    cmd_bytes_padded = cmd_bytes.ljust(FIXED_COMMAND_SIZE, b'\x00')
    return cmd_bytes_padded

def build_file_payload(destination, local_filepath):
    """
    Build the FILE payload:
      First 1024 bytes -> destination (ASCII), truncated or zero-padded if needed.
      After that -> raw contents of local_filepath.
    """
    # 1) Prepare destination buffer of exactly 1024 bytes
    dest_bytes = destination.encode('utf-8', errors='replace')
    dest_bytes = dest_bytes[:FIXED_DEST_SIZE]  # truncate if longer
    dest_padded = dest_bytes.ljust(FIXED_DEST_SIZE, b'\x00')

    # 2) Read file data
    with open(local_filepath, 'rb') as f:
        file_data = f.read()

    # 3) Concatenate
    payload = dest_padded + file_data
    return payload

def compute_crc32(data: bytes) -> int:
    """
    Compute standard CRC-32 (polynomial 0xEDB88320).
    """
    # Python's zlib.crc32() does exactly this, returns signed int in Py2 but
    # we mask with 0xFFFFFFFF to keep it in 32-bit unsigned range.
    return zlib.crc32(data) & 0xFFFFFFFF

def write_tlv(tlv_type, payload, out_fh):
    """
    Write a TLV (type, length, payload, CRC) to the output file.
    """
    length = len(payload)
    crc_val = compute_crc32(payload)

    # Write Type (4 bytes, LE)
    out_fh.write(struct.pack('<I', tlv_type))
    # Write Length (4 bytes, LE)
    out_fh.write(struct.pack('<I', length))
    # Write Payload
    out_fh.write(payload)
    # Write Payload CRC (4 bytes, LE)
    out_fh.write(struct.pack('<I', crc_val))

def build_global_header(total_length: int, key_data: bytes = None) -> bytes:
    """
    Build a 268-byte global header, initially with header_checksum=0.
    Then compute the header checksum and place it in the buffer.

    Layout:
      [0..3]   = b'FUNK'
      [4..7]   = total_length (LE)
      [8..11]  = header_checksum (LE) [computed after build]
      [12..267]= key buffer (256 bytes)
    """
    header = bytearray(GLOBAL_HEADER_SIZE)

    # 1) Magic
    header[0:4] = b'FUNK'

    # 2) total_length
    struct.pack_into('<I', header, 4, total_length)

    # 3) header_checksum placeholder -> zero for now
    # (we'll fill after computing)

    # 4) key buffer
    if key_data:
        # Truncate or pad
        key_data = key_data[:256]
        header[12:12+len(key_data)] = key_data
    # Remainder stays zero

    # Compute header checksum
    # Zero out bytes [8..11] for the CRC calculation
    # (They are already zero, but let's be explicit.)
    # Then compute zlib.crc32, store result at [8..11].
    struct.pack_into('<I', header, 8, 0)  # ensure it's zero
    hdr_crc = compute_crc32(header)
    struct.pack_into('<I', header, 8, hdr_crc)

    return bytes(header)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} output.funk "
              f"[command \"some_cmd\"] [file /dest/path local_file.bin] ...",
              file=sys.stderr)
        sys.exit(1)

    output_file = sys.argv[1]
    args = sys.argv[2:]

    # We'll accumulate all TLVs in memory, then compute total length.
    from io import BytesIO
    tlv_buffer = BytesIO()

    i = 0
    while i < len(args):
        keyword = args[i].lower()

        if keyword == 'command':
            # Next arg: the command string
            if i + 1 >= len(args):
                print("Error: 'command' requires a string argument.", file=sys.stderr)
                sys.exit(1)
            cmd_str = args[i+1]
            i += 2

            payload = build_command_payload(cmd_str)
            write_tlv(TLV_TYPE_COMMAND, payload, tlv_buffer)
            print(f"Added COMMAND TLV: '{cmd_str}'")

        elif keyword == 'file':
            # Next 2 args: destination, local_file
            if i + 2 >= len(args):
                print("Error: 'file' requires two arguments (destination, local_file).", file=sys.stderr)
                sys.exit(1)
            dest = args[i+1]
            local_file = args[i+2]
            i += 3

            if not os.path.isfile(local_file):
                print(f"Error: local file '{local_file}' not found.", file=sys.stderr)
                sys.exit(1)

            payload = build_file_payload(dest, local_file)
            write_tlv(TLV_TYPE_FILE, payload, tlv_buffer)
            print(f"Added FILE TLV: dest='{dest}', file='{local_file}'")

        else:
            print(f"Error: Unrecognized argument '{keyword}'. Expected 'command' or 'file'.", file=sys.stderr)
            sys.exit(1)

    tlv_bytes = tlv_buffer.getvalue()

    # Total length = header size + size of TLVs
    total_length = GLOBAL_HEADER_SIZE + len(tlv_bytes)

    # Optionally load a 256-byte key from somewhere or leave as default zeros:
    # key_data = open('keyfile.bin','rb').read(256)  # example usage
    key_data = None

    global_header = build_global_header(total_length, key_data=key_data)

    with open(output_file, 'wb') as out_fh:
        out_fh.write(global_header)
        out_fh.write(tlv_bytes)

    print(f"\nFUNK file created: {output_file}")
    print(f"Total length = {total_length} bytes")


if __name__ == '__main__':
    main()
