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
import struct
import fcntl
import os
import zlib

# Linux-specific IOCTL for getting the block device's logical sector size
BLKSSZGET = 0x1268

FUNK_HEADER_SIZE = 268
TLV_TYPE_COMMAND = 1
TLV_TYPE_FILE    = 2

def get_sector_size(fileobj, fallback=512):
    """
    Attempt to retrieve the block device's logical sector size via ioctl(BLKSSZGET).
    Fallback to a default (512) if ioctl is not supported or fails.
    """
    try:
        # We pack an int (4 bytes) as the argument
        buf = struct.pack('I', 0)
        # Perform the ioctl
        result = fcntl.ioctl(fileobj.fileno(), BLKSSZGET, buf)
        # Unpack the result as an unsigned int
        sector_size = struct.unpack('I', result)[0]
        return sector_size
    except Exception:
        # If this fails (not a block device or not on Linux), return fallback
        return fallback

def compute_crc32(data: bytes) -> int:
    """
    Compute standard CRC-32 (polynomial 0xEDB88320).
    """
    return zlib.crc32(data) & 0xFFFFFFFF

def read_le32(data: bytes, offset: int) -> int:
    """
    Read a little-endian 32-bit integer from 'data' at 'offset'.
    """
    return (data[offset] |
           (data[offset+1] << 8) |
           (data[offset+2] << 16) |
           (data[offset+3] << 24))

def parse_funk(data: bytes):
    """
    Parse the FUNK format from the 'data' bytes.

    FUNK header (268 bytes):
      [0..3]   = 'FUNK'
      [4..7]   = total_length (uint32, little-endian)
      [8..11]  = header_checksum (uint32, little-endian)
      [12..267]= key buffer (256 bytes)

    Then TLVs (type [4 bytes], length [4 bytes], payload [length bytes], CRC32 [4 bytes]).
    Print a summary of each TLV.
    """
    if len(data) < FUNK_HEADER_SIZE:
        print("Data is smaller than FUNK header (268 bytes).")
        return

    # 1) Check magic
    magic = data[0:4]
    if magic != b'FUNK':
        print("Invalid FUNK magic signature.")
        return

    # 2) Read total_length
    total_length = read_le32(data, 4)
    if total_length > len(data):
        print(f"FUNK total_length={total_length} but we only have {len(data)} bytes.")
        return

    # 3) Read stored header CRC
    stored_header_crc = read_le32(data, 8)

    # 4) Compute header CRC ourselves, zeroing out bytes [8..11]
    header_copy = bytearray(data[0:FUNK_HEADER_SIZE])  # copy first 268 bytes
    header_copy[8:12] = b'\x00\x00\x00\x00'            # zero out the checksum field
    computed_header_crc = compute_crc32(header_copy)
    if computed_header_crc != stored_header_crc:
        print(f"FUNK header CRC mismatch: stored=0x{stored_header_crc:08X}, "
              f"computed=0x{computed_header_crc:08X}")
        return

    print("FUNK Header parsed:")
    print(f"  total_length = {total_length}")
    print(f"  header_crc   = 0x{stored_header_crc:08X} (OK)")

    # key buffer is data[12:268], not used here, but you can do something if you like

    # Now parse TLVs from offset 268 up to total_length
    offset = FUNK_HEADER_SIZE
    while offset + 8 <= total_length:
        # read type, length
        tlv_type = read_le32(data, offset)
        tlv_length = read_le32(data, offset + 4)
        offset += 8

        # check if we have enough space for the payload + CRC
        if offset + tlv_length + 4 > total_length:
            print(f"Truncated TLV at offset {offset-8}: type={tlv_type}, length={tlv_length}")
            return
        payload = data[offset : offset + tlv_length]
        offset += tlv_length

        stored_crc = read_le32(data, offset)
        offset += 4

        computed_crc = compute_crc32(payload)
        if computed_crc != stored_crc:
            print(f"TLV CRC mismatch: stored=0x{stored_crc:08X}, computed=0x{computed_crc:08X}")
            return

        print(f"\nTLV @ offset={offset - (tlv_length + 4 + 8)}")
        print(f"  Type   = {tlv_type}")
        print(f"  Length = {tlv_length}")
        print(f"  CRC    = 0x{stored_crc:08X} (OK)")

        if tlv_type == TLV_TYPE_COMMAND:
            print("  [COMMAND] Payload (up to first 50 bytes shown):")
            show_len = min(50, tlv_length)
            segment = payload[:show_len]
            # print as ASCII or dot for nonprintable
            text = ''.join(chr(c) if 32 <= c < 127 else '.' for c in segment)
            if tlv_length > 50:
                text += "..."
            print(f"    '{text}'")
        elif tlv_type == TLV_TYPE_FILE:
            print("  [FILE] Destination + file data")
            # The first 1024 bytes is the destination (zero-padded).
            # The rest is the file data.
            if tlv_length < 1024:
                print("    Malformed: payload < 1024 bytes for FILE TLV.")
            else:
                dest_bytes = payload[:1024]
                file_data = payload[1024:]
                # trim trailing zeros for printing
                dest_str = dest_bytes.rstrip(b'\x00')
                print(f"    Destination (up to 50 chars shown):")
                show_dest = dest_str[:50]
                txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in show_dest)
                if len(dest_str) > 50:
                    txt += "..."
                print(f"      '{txt}'")
                print(f"    File data length = {len(file_data)} bytes")
        else:
            print("  [Unknown TLV type]")

    print("\nDone parsing FUNK.")

def write_funk_image(device_fh, offset, image_path):
    """
    Writes the entire contents of `image_path` into the device at `offset`.
    """
    print(f"Writing FUNK image '{image_path}' at offset {offset}...")
    with open(image_path, 'rb') as img_fh:
        data = img_fh.read()
    device_fh.seek(offset, os.SEEK_SET)
    device_fh.write(data)
    device_fh.flush()
    print(f"Wrote {len(data)} bytes from '{image_path}' to device.\n")

def read_and_parse_funk(device_fh, offset):
    """
    Reads the FUNK header from 'offset', determines total_length,
    then reads the entire FUNK data and parses it.
    """
    # Step 1: read the 268-byte header first
    device_fh.seek(offset, os.SEEK_SET)
    header = device_fh.read(FUNK_HEADER_SIZE)
    if len(header) < FUNK_HEADER_SIZE:
        print(f"Could not read {FUNK_HEADER_SIZE} bytes for FUNK header.")
        return

    # get total_length
    total_length = read_le32(header, 4)
    if total_length < FUNK_HEADER_SIZE:
        print(f"Invalid total_length={total_length}, smaller than FUNK_HEADER_SIZE.")
        return

    # Step 2: read the entire FUNK from offset
    device_fh.seek(offset, os.SEEK_SET)
    funk_data = device_fh.read(total_length)
    if len(funk_data) < total_length:
        print(f"Incomplete read of FUNK file: expected {total_length}, got {len(funk_data)}.")
        return

    # Step 3: parse FUNK
    parse_funk(funk_data)

def read_hidden_stream(device_path, funk_image_path=None):
    """
    1) Open device in read/write mode.
    2) Read MBR, locate offset_after_last_partition.
    3) If funk_image_path is provided, write that file at the offset.
    4) Then read & parse the FUNK file from that offset.
    """
    MBR_PARTITION_TABLE_OFFSET = 0x1BE
    MBR_PARTITION_ENTRY_SIZE   = 16
    NUM_PARTITIONS             = 4

    try:
        with open(device_path, 'r+b', buffering=0) as f:
            sector_size = get_sector_size(f, fallback=512)
            print(f"Detected (or fallback) sector size: {sector_size} bytes")

            # Read the first sector (MBR)
            mbr = f.read(sector_size)
            if len(mbr) < sector_size:
                print(f"Error: Could not read first sector ({sector_size} bytes) from {device_path}.")
                return

            # Find max_end_sector
            max_end_sector = 0
            print("\nMBR partitions:")
            for i in range(NUM_PARTITIONS):
                offset = MBR_PARTITION_TABLE_OFFSET + i * MBR_PARTITION_ENTRY_SIZE
                entry_data = mbr[offset : offset + MBR_PARTITION_ENTRY_SIZE]
                (status, chs_first, partition_type, chs_last, lba_first, num_sectors) = \
                    struct.unpack('<B3sB3sII', entry_data)

                if num_sectors > 0:
                    start_sector = lba_first
                    end_sector = start_sector + num_sectors - 1
                else:
                    start_sector = 0
                    end_sector = 0

                print(f"  Partition {i+1}:")
                print(f"    Status       : 0x{status:02X}")
                print(f"    Type         : 0x{partition_type:02X}")
                print(f"    Start sector : {start_sector}")
                print(f"    End sector   : {end_sector}")
                print(f"    # sectors    : {num_sectors}")

                if end_sector > max_end_sector:
                    max_end_sector = end_sector

            offset_after_last_partition = (max_end_sector + 1) * sector_size
            print(f"\nOffset after last partition = {offset_after_last_partition}\n")

            # If we have an image to write, do so
            if funk_image_path:
                write_funk_image(f, offset_after_last_partition, funk_image_path)

            # Now read & parse the FUNK data from that offset
            print("Reading & parsing FUNK file...\n")
            read_and_parse_funk(f, offset_after_last_partition)

    except IOError as e:
        print(f"Error opening/reading/writing {device_path}: {e}")

def main():
    """
    Usage:
      - To read and parse (no write):
          python3 funk_tool.py /dev/sdX
      - To write 'funk_image.bin' at the hidden offset, then parse:
          python3 funk_tool.py /dev/sdX funk_image.bin
    """
    if len(sys.argv) < 2:
        print(f"Usage:\n  {sys.argv[0]} /dev/sdX\n"
              f"  or\n  {sys.argv[0]} /dev/sdX funk_image.bin", file=sys.stderr)
        sys.exit(1)

    device_path = sys.argv[1]
    funk_image_path = sys.argv[2] if len(sys.argv) > 2 else None

    read_hidden_stream(device_path, funk_image_path)

if __name__ == "__main__":
    main()
