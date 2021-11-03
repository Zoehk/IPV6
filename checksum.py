#!/usr/local/bin/python3
# -*- coding: utf8 -*-

import struct
SOURCE_IP = "fe80000000000000865b12fffe5e3602"
DEST_IP   = "ff020000000000000000000000000001"
TYPE_CODE = "8600"
REMAINDER = "0000400007080000ea60000027100101845b125e360205010000000005dc030440c000278d0000093a800000000020010250040165460000000000000000"
'''
030440c000278d0000093a800000000020010250040165460000000000000000
'''

def calc_checksum(packet):
    total = 0

    # Add up 16-bit words
    num_words = len(packet) // 2
    for chunk in struct.unpack("!%sH" % num_words, packet[0:num_words*2]):
        total += chunk

    # Add any left over byte
    if len(packet) % 2:
        total += ord(packet[-1]) << 8

    # Fold 32-bits into 16-bits
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return (~total + 0x10000 & 0xffff)


def build_pseudo_header(src_ip, dest_ip, payload_len):
    source_ip_bytes = bytearray.fromhex(src_ip)
    dest_ip_bytes = bytearray.fromhex(dest_ip)
    next_header = struct.pack(">I", 58)
    upper_layer_len = struct.pack(">I", payload_len)
    return source_ip_bytes + dest_ip_bytes + upper_layer_len + next_header


def build_icmpv6_chunk(type_and_code, other):
    type_code_bytes = bytearray.fromhex(type_and_code)
    checksum = struct.pack(">I", 0)
    other_bytes = bytearray.fromhex(other)
    return type_code_bytes + checksum + other_bytes


def main():
    icmpv6_chunk = build_icmpv6_chunk(TYPE_CODE, REMAINDER)
    pseudo_header = build_pseudo_header(SOURCE_IP, DEST_IP, 32)
    icmpv6_packet = pseudo_header + icmpv6_chunk
    checksum = calc_checksum(icmpv6_packet)

    print("checksum: {:#x}".format(checksum))

if __name__ == '__main__':
    main()
