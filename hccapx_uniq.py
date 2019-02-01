#!/usr/bin/env python3

import sys
import struct
import argparse
import os.path
from collections import namedtuple
from binascii import hexlify

# struct hccapx
# {
#   u32 signature;
#   u32 version;
#   u8  message_pair;
#   u8  essid_len;
#   u8  essid[32];
#   u8  keyver;
#   u8  keymic[16];
#   u8  mac_ap[6];
#   u8  nonce_ap[32];
#   u8  mac_sta[6];
#   u8  nonce_sta[32];
#   u16 eapol_len;
#   u8  eapol[256];
# 
# } __attribute__((packed));

hccapx = namedtuple('hccapx', 'signature version message_pair essid keyver '
                              'keymic mac_ap nonce_ap mac_sta nonce_sta '
                              'eapol_len eapol')
hccapx_format = struct.Struct('<IIB33pB16s6s32s6s32sH256s')
HCCAPX_SIGNATURE = 1481655112 # 'HCPX'
assert hccapx_format.size == 393


def format_mac(buf):
    mac = hexlify(buf).decode('latin-1').upper()
    return ':'.join(mac[i:i+2] for i in range(0, len(mac), 2))


def load_hccapx(buf):
    res = hccapx._make(hccapx_format.unpack(buf))
    assert res.signature == HCCAPX_SIGNATURE
    res = res._replace(mac_ap = format_mac(res.mac_ap),
                       mac_sta = format_mac(res.mac_sta))
    return res


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("input_file",
                        help="input HCCAPX file")
    parser.add_argument("output_file",
                        help="output HCCAPX file")
    parser.add_argument("-p", "--prefix",
                        help="output file prefix",
                        default="hccapx_split_")
    
    args = parser.parse_args()
    return args


def format_filename(s):
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    filename = ''.join(c for c in s if c in valid_chars)
    filename = filename.replace(' ','_') # I don't like spaces in filenames.
    return filename


def read_chunks(f, size):
    while True:
        buf = f.read(size)
        if not buf:
            break
        if len(buf) < size:
            print("WARNING: read undersized chunk. Probably file is cropped.", file=sys.stderr)
            break
        yield buf


def main():
    args = parse_args()
    seen = set()
    with open(args.input_file, 'rb') as in_file, open(args.output_file, 'wb') as out_file:
        for buf in read_chunks(in_file, hccapx_format.size):
            h = load_hccapx(buf)
            if (h.mac_ap, h.essid) in seen:
                print("Skipping: ESSID=%s MAC_AP=%s MAC_STA=%s" % (h.essid, h.mac_ap, h.mac_sta),
                      file=sys.stderr)
            else:
                print("Saving: ESSID=%s MAC_AP=%s MAC_STA=%s" % (h.essid, h.mac_ap, h.mac_sta),
                      file=sys.stderr)
                out_file.write(buf)
                seen.add((h.mac_ap, h.essid))

if __name__ == '__main__':
    main()
