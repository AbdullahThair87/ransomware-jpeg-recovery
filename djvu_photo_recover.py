#!/usr/bin/env python3
"""
Partial recovery of JPEG photos encrypted by STOP/Djvu ransomware.
Djvu encrypts only the first ~150 KB of each file. This script rebuilds a
new JPEG from the untouched remainder (the lower part of the photo).

Usage:
    python3 djvu_photo_recover.py  <encrypted_folder>  <output_folder>  [--ref original.JPG] [--quality 95] [--width PIXELS]
--ref : give one NOT-encrypted photo from the same phone -> exact original colours.
By default the colours/contrast are calibrated automatically for each photo.
Needs: pip3 install pillow numpy
"""
import sys, os, re, struct, argparse, io

ENC_END = 153605          # Djvu: bytes after this offset are not encrypted

# ---------- standard JPEG Huffman tables (Annex K) ----------
DCL_B = [0,1,5,1,1,1,1,1,1,0,0,0,0,0,0,0]; DCL_V = list(range(12))
DCC_B = [0,3,1,1,1,1,1,1,1,1,1,0,0,0,0,0]; DCC_V = list(range(12))
ACL_B = [0,2,1,3,3,2,4,3,5,5,4,4,0,0,1,0x7d]
ACL_V = list(bytes.fromhex("01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9fa"))
ACC_B = [0,2,1,2,4,4,3,4,7,5,4,4,0,1,2,0x77]
ACC_V = list(bytes.fromhex("000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9fa"))
LQ = [16,11,10,16,24,40,51,61,12,12,14,19,26,58,60,55,14,13,16,24,40,57,69,56,14,17,22,29,51,87,80,62,18,22,37,56,68,109,103,77,24,35,55,64,81,104,113,92,49,64,78,87,103,121,120,101,72,92,95,98,112,100,103,99]
CQ = [17,18,24,47,99,99,99,99,18,21,26,66,99,99,99,99,24,26,56]+[99]*5+[47,66]+[99]*38
ZZ = [0,1,8,16,9,2,3,10,17,24,32,25,18,11,4,5,12,19,26,33,40,48,41,34,27,20,13,6,7,14,21,28,35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51,58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63]

def table(bits, vals):
    t = {}; code = 0; k = 0
    for l in range(1, 17):
        for _ in range(bits[l-1]):
            t[(l, code)] = vals[k]; k += 1; code += 1
        code <<= 1
    return t
T = {n: table(b, v) for n, b, v in [("dcl",DCL_B,DCL_V),("dcc",DCC_B,DCC_V),("acl",ACL_B,ACL_V),("acc",ACC_B,ACC_V)]}

class Bits:
    def __init__(s, b):
        b = b.replace(b"\xff\x00", b"\xff"); s.v = int.from_bytes(b, "big"); s.n = len(b)*8; s.p = 0
    def bit(s):
        if s.p >= s.n: raise EOFError
        s.p += 1; return (s.v >> (s.n - s.p)) & 1
    def huff(s, t):
        c = 0
        for l in range(1, 17):
            c = (c << 1) | s.bit()
            if (l, c) in t: return t[(l, c)]
        raise ValueError
def skip_block(r, dc, ac):
    s = r.huff(dc); r.p += s; k = 1
    while k < 64:
        rs = r.huff(ac); run, size = rs >> 4, rs & 15
        if size == 0:
            if run == 15: k += 16; continue
            return
        k += run
        if k > 63: raise ValueError
        r.p += size; k += 1

def count_mcus(seg, ny):
    """Decode one restart interval; return MCU count if it decodes cleanly."""
    r = Bits(seg); n = 0
    try:
        while r.n - r.p >= 8:
            for _ in range(ny): skip_block(r, T["dcl"], T["acl"])
            for _ in range(2):  skip_block(r, T["dcc"], T["acc"])
            n += 1
    except (EOFError, ValueError):
        return None
    return n if r.p <= r.n else None

def scaled(q, quality):
    s = 5000/quality if quality < 50 else 200 - 2*quality
    return [min(255, max(1, int((v*s + 50)//100))) for v in q]

def tables(scale, dc):
    """Quant tables = standard tables * scale, with a separate DC step."""
    lq = [min(255, max(1, round(v*scale))) for v in LQ]; lq[0] = dc
    cq = [min(255, max(1, round(v*scale))) for v in CQ]; cq[0] = dc
    return lq, cq

def build_header(w, h, ny, ri, lq, cq):
    hs, vs = {4:(2,2), 2:(2,1), 1:(1,1)}[ny]
    def seg(m, body): return b"\xff" + bytes([m]) + struct.pack(">H", len(body)+2) + body
    out = b"\xff\xd8"
    out += seg(0xDB, b"\x00" + bytes(lq[i] for i in ZZ))   # DQT is stored in zigzag
    out += seg(0xDB, b"\x01" + bytes(cq[i] for i in ZZ))
    out += seg(0xC0, struct.pack(">BHHB", 8, h, w, 3) + bytes([1, hs<<4|vs, 0, 2, 0x11, 1, 3, 0x11, 1]))
    for cls_id, b, v in [(0x00,DCL_B,DCL_V),(0x10,ACL_B,ACL_V),(0x01,DCC_B,DCC_V),(0x11,ACC_B,ACC_V)]:
        out += seg(0xC4, bytes([cls_id]) + bytes(b) + bytes(v))
    out += seg(0xDD, struct.pack(">H", ri))
    out += seg(0xDA, bytes([3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]))
    return out, hs*8, vs*8

def read_reference(path):
    """Read the REAL quantization tables + size from an unencrypted photo of the same camera."""
    d = open(path, "rb").read()
    if not d.startswith(b"\xff\xd8"):
        raise ValueError("reference is not a JPEG")
    q = {}; size = None; i = 2
    while i < len(d) - 4:
        if d[i] != 0xFF: i += 1; continue
        m = d[i+1]
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7: i += 2; continue
        L = struct.unpack(">H", d[i+2:i+4])[0]; seg = d[i+4:i+2+L]
        if m == 0xDB:
            j = 0
            while j < len(seg):
                pq, tq = seg[j] >> 4, seg[j] & 15; j += 1
                n = 128 if pq else 64
                vals = seg[j:j+n]; j += n
                vals = [struct.unpack(">H", vals[k:k+2])[0] for k in range(0, 128, 2)] if pq else list(vals)
                nat = [0]*64
                for k in range(64): nat[ZZ[k]] = vals[k]
                q[tq] = nat
        elif m in (0xC0, 0xC1, 0xC2):
            h, w = struct.unpack(">HH", seg[1:5]); size = (w, h)
        elif m == 0xDA:
            break
        i += 2 + L
    if 0 not in q:
        raise ValueError("no quantization table found in reference")
    return q[0], q.get(1, q[0]), size

def blockiness(a, step=8):
    """How visible the 8x8 block edges are (1.0 = invisible)."""
    import numpy as np
    a = a.astype(float); dx = np.abs(np.diff(a, axis=1)); dy = np.abs(np.diff(a, axis=0))
    bx = dx[:, step-1::step].mean(); ix = np.delete(dx, np.s_[step-1::step], axis=1).mean()
    by = dy[step-1::step, :].mean(); iy = np.delete(dy, np.s_[step-1::step], axis=0).mean()
    return (bx + by) / (ix + iy + 1e-9)

def auto_tables(segs, ny, ri, width, mch):
    """Guess the camera's real compression settings:
       - DC step: the largest one that does not burn shadows/highlights
       - AC scale: the one that makes block edges disappear."""
    import numpy as np
    from PIL import Image
    sample = segs[:min(len(segs), 24)]
    body = bytearray()
    for i, s in enumerate(sample):
        body += s
        if i < len(sample)-1: body += bytes([0xff, 0xd0 + (i % 8)])
    rows = len(sample)*ri // (width // {4:16, 2:16, 1:8}[ny])
    def luma(scale, dc):
        lq, cq = tables(scale, dc)
        hdr, _, _ = build_header(width, rows*mch, ny, ri, lq, cq)
        im = Image.open(io.BytesIO(hdr + bytes(body) + b"\xff\xd9")); im.draft("YCbCr", im.size); im.load()
        return np.array(im)[:, :, 0] if im.mode == "YCbCr" else np.array(im.convert("YCbCr"))[:, :, 0]
    best = None
    for dc in range(1, 9):
        Y = luma(0.1*dc, dc)
        crushed, burned = np.mean(Y <= 2), np.mean(Y >= 253)
        if (crushed > 0.01 or burned > 0.10) and best is not None:
            break
        cands = [(blockiness(luma(sc, dc)), sc) for sc in np.arange(0.03*dc, 0.16*dc + 0.001, 0.01*dc)]
        b, sc = min(cands)
        best = (dc, float(sc))
    return tables(best[1], best[0]), best

def recover(path, outdir, quality, force_width, ref=None):
    d = open(path, "rb").read()
    name = os.path.basename(path)
    if not d.startswith(b"\xff\xd8"):
        return "not a JPEG (skipped)"
    end = d.rfind(b"\xff\xd9")
    if end < ENC_END:
        return "file too small - everything is encrypted"
    data = d[:end]
    rst = [m.start() for m in re.finditer(rb"\xff[\xd0-\xd7]", data) if m.start() >= ENC_END]
    if len(rst) < 3:
        return "no restart markers - this photo cannot be rebuilt with this method"
    segs = [data[rst[i]+2:rst[i+1]] for i in range(len(rst)-1)] + [data[rst[-1]+2:]]
    ny = ri = None
    for cand in (4, 2, 1):
        counts = [count_mcus(s, cand) for s in segs[:3]]
        if counts[0] and len(set(counts)) == 1:
            ny, ri = cand, counts[0]; break
    if ny is None:
        return "non-standard Huffman tables - cannot rebuild"
    # assume one restart interval = one row of blocks (true for most phones/cameras)
    mw = {4:16, 2:16, 1:8}[ny]
    width = force_width or ri*mw
    per_row = width // mw
    total = len(segs)*ri
    rows = total // per_row
    if ref and ref[2] and ref[2][0] == width:
        lq, cq = ref[0], ref[1]; info = "exact tables from reference photo"
    elif quality:
        lq, cq = scaled(LQ, quality), scaled(CQ, quality); info = f"quality {quality}"
    else:
        (lq, cq), (dc, sc) = auto_tables(segs, ny, ri, width, mch_of(ny)); info = f"auto: dc={dc} scale={sc:.2f}"
    header, mcw, mch = build_header(width, rows*mch_of(ny), ny, ri, lq, cq)
    body = bytearray()
    for i, s in enumerate(segs):
        body += s
        if i < len(segs)-1: body += bytes([0xff, 0xd0 + (i % 8)])
    jpg = header + bytes(body) + b"\xff\xd9"
    base = os.path.splitext(name)[0]
    out = os.path.join(outdir, base + "_recovered.jpg")
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(jpg)); im.load(); im.save(out, quality=95)
    except Exception:
        open(out, "wb").write(jpg)
    return f"OK -> {os.path.basename(out)}  ({width}x{rows*mch_of(ny)} px recovered, {info})"

def mch_of(ny): return {4:16, 2:8, 1:8}[ny]

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("src"); ap.add_argument("dst")
    ap.add_argument("--quality", type=int, default=0, help="force a fixed quality (90-99) instead of automatic calibration")
    ap.add_argument("--width", type=int, default=0, help="force image width in pixels if result looks slanted")
    ap.add_argument("--ref", default="", help="an UNENCRYPTED .JPG from the same phone -> exact colours")
    a = ap.parse_args()
    ref = None
    if a.ref:
        ref = read_reference(a.ref)
        print(f"Using reference {os.path.basename(a.ref)} ({ref[2][0]}x{ref[2][1]}) for photos of the same width")
    os.makedirs(a.dst, exist_ok=True)
    files = [os.path.join(a.src, f) for f in sorted(os.listdir(a.src))] if os.path.isdir(a.src) else [a.src]
    for f in files:
        if os.path.isfile(f):
            try: msg = recover(f, a.dst, a.quality, a.width, ref)
            except Exception as e: msg = f"error: {e}"
            print(f"{os.path.basename(f)}: {msg}")
