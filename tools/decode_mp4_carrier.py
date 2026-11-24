#!/usr/bin/env python3
"""Static decoder for the MP4 uuid-box carrier seen in case 2026-11-16-clickfix-netsupport.

Layout inside the uuid box, after the 16-byte usertype:
  [magic FB DB 81 0D][2-byte key length][key][4-byte big-endian data length][data]
  data is XOR with the repeating key, then gzip.

Usage:
  decode_mp4_carrier.py --in 0909.mp4 --out /path/outside/repo [--uuid 0c5ae5ad-...]
  decode_mp4_carrier.py --selftest

Standard library only. Nothing is ever executed. The output is MALICIOUS SOURCE CODE.
"""
import argparse
import gzip
import hashlib
import struct
import sys
import uuid
from pathlib import Path

MAGIC = bytes.fromhex("FBDB810D")
DEFAULT_UUID = "0c5ae5ad-666d-4dbb-9723-361869c8ee54"
REPO = Path(__file__).resolve().parent.parent


def walk_boxes(buf):
    """Yield (offset, size, type, header_len) for top-level ISO BMFF boxes."""
    off = 0
    while off + 8 <= len(buf):
        size, btype = struct.unpack(">I4s", buf[off:off + 8])
        hdr = 8
        if size == 1:
            size = struct.unpack(">Q", buf[off + 8:off + 16])[0]
            hdr = 16
        elif size == 0:
            size = len(buf) - off
        if size < hdr or off + size > len(buf):
            raise ValueError(f"bad box at 0x{off:x}")
        yield off, size, btype, hdr
        off += size


def decode(buf, want_uuid):
    want = uuid.UUID(want_uuid).bytes
    for off, size, btype, hdr in walk_boxes(buf):
        if btype != b"uuid" or buf[off + hdr:off + hdr + 16] != want:
            continue
        p = off + hdr + 16
        if buf[p:p + 4] != MAGIC:
            raise ValueError(f"uuid box at 0x{off:x} lacks magic FB DB 81 0D")
        p += 4
        raw_kl = buf[p:p + 2]
        klen = struct.unpack(">H", raw_kl)[0]
        if not 0 < klen <= 1024:  # ponytail: endianness unconfirmed, fall back to little-endian
            klen = struct.unpack("<H", raw_kl)[0]
        p += 2
        key = buf[p:p + klen]
        p += klen
        dlen = struct.unpack(">I", buf[p:p + 4])[0]
        p += 4
        data = buf[p:p + dlen]
        if len(data) != dlen or not key:
            raise ValueError("truncated payload")
        plain = bytes(b ^ key[i % klen] for i, b in enumerate(data))
        return off, klen, gzip.decompress(plain)
    raise ValueError(f"no uuid box with usertype {want_uuid}")


def selftest():
    payload = b"print('selftest only')\n" * 50
    key = bytes(range(1, 21))
    enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(gzip.compress(payload)))
    body = uuid.UUID(DEFAULT_UUID).bytes + MAGIC + struct.pack(">H", 20) + key + struct.pack(">I", len(enc)) + enc
    mp4 = struct.pack(">I4s", 16, b"ftyp") + b"isom\0\0\0\0" + struct.pack(">I4s", 8 + len(body), b"uuid") + body
    off, klen, out = decode(mp4, DEFAULT_UUID)
    assert (off, klen, out) == (16, 20, payload), "selftest failed"
    print("selftest PASS")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="inp")
    ap.add_argument("--out")
    ap.add_argument("--uuid", default=DEFAULT_UUID)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.inp or not a.out:
        ap.error("--in and --out are required")
    out_dir = Path(a.out).resolve()
    if out_dir == REPO or REPO in out_dir.parents:
        sys.exit("refusing to write inside the repository, choose an output directory outside it")

    print("WARNING: the decoded output is malicious source code. Read it, never execute it.", file=sys.stderr)
    buf = Path(a.inp).read_bytes()
    off, klen, text = decode(buf, a.uuid)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / (Path(a.inp).stem + "_decoded.py.txt")
    out.write_bytes(text)
    print(f"box offset   0x{off:x}")
    print(f"key length   {klen}")
    print(f"output size  {len(text)} bytes")
    print(f"sha256       {hashlib.sha256(text).hexdigest()}")
    print(f"written to   {out}")


if __name__ == "__main__":
    main()
