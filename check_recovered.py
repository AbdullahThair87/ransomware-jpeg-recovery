#!/usr/bin/env python3
"""
Check which photos were NOT recovered correctly.

Usage:
    python check_recovered.py  <encrypted_folder>  <recovered_folder>

Example (PyCharm Terminal):
    python check_recovered.py "my pic" recovered_auto

It prints a summary and saves a full table to  report.csv  (opens in Excel/Numbers).
Needs: pip install pillow numpy
"""
import os, sys, csv
import numpy as np
from PIL import Image

ENC_END = 153605   # Djvu encrypts only the first ~150 KB


def blockiness(a, step=8):
    a = a.astype(float)
    dx = np.abs(np.diff(a, axis=1)); dy = np.abs(np.diff(a, axis=0))
    bx = dx[:, step-1::step].mean(); ix = np.delete(dx, np.s_[step-1::step], axis=1).mean()
    by = dy[step-1::step, :].mean(); iy = np.delete(dy, np.s_[step-1::step], axis=0).mean()
    return (bx + by) / (ix + iy + 1e-9)


def check_image(path):
    """Return (status, problem, details) for one recovered image."""
    try:
        im = Image.open(path); im.load()
    except Exception as e:
        return "BAD", "cannot open the recovered file", str(e)
    w, h = im.size
    Y = np.array(im.convert("L"))
    problems = []
    if h < 64:
        problems.append("very small part recovered")
    b = blockiness(Y)
    if b > 1.6:
        problems.append(f"blocky / pixelated (score {b:.2f})")
    crushed, burned = np.mean(Y <= 3), np.mean(Y >= 252)
    if crushed > 0.15:
        problems.append(f"too dark ({crushed:.0%} black)")
    if burned > 0.40:
        problems.append(f"too bright ({burned:.0%} white)")
    if Y.std() < 18:
        problems.append("washed out / grey")
    # rows that are completely flat usually mean broken data
    flat_rows = np.mean(Y.std(axis=1) < 1.0)
    if flat_rows > 0.25:
        problems.append(f"{flat_rows:.0%} of rows are empty/grey")
    details = f"{w}x{h}px, blockiness {b:.2f}"
    if problems:
        return "CHECK", "; ".join(problems), details
    return "OK", "", details


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    enc_dir, rec_dir = sys.argv[1], sys.argv[2]
    if not os.path.isdir(rec_dir):
        print(f"Folder '{rec_dir}' does not exist yet.")
        print(f'First run:  python djvu_photo_recover.py "{enc_dir}" {rec_dir}')
        sys.exit(1)
    rows = []
    for name in sorted(os.listdir(enc_dir)):
        src = os.path.join(enc_dir, name)
        if not os.path.isfile(src) or name.startswith("."):
            continue
        size = os.path.getsize(src)
        expected_part = max(0.0, (size - ENC_END) / size)
        base = os.path.splitext(name)[0]
        out = os.path.join(rec_dir, base + "_recovered.jpg")
        if not os.path.exists(out):
            with open(src, "rb") as f:
                head = f.read(2)
            if head != b"\xff\xd8":
                why = "not a JPEG photo (PNG/HEIC/video...)"
            elif size <= ENC_END:
                why = "file too small - fully encrypted"
            else:
                why = "recovery failed (no restart markers or edited photo)"
            rows.append([name, f"{size/1024:.0f} KB", "-", "FAILED", why, ""])
            continue
        status, problem, details = check_image(out)
        rows.append([name, f"{size/1024:.0f} KB", f"{expected_part:.0%}", status, problem, details])

    with open(os.path.join(rec_dir, "report.csv"), "w", newline="", encoding="utf-8-sig") as f:
        wr = csv.writer(f)
        wr.writerow(["file", "size", "part recoverable", "status", "problem", "details"])
        wr.writerows(rows)

    total = len(rows)
    ok = sum(r[3] == "OK" for r in rows)
    check = [r for r in rows if r[3] in ("CHECK", "BAD")]
    failed = [r for r in rows if r[3] == "FAILED"]

    print("=" * 60)
    print(f"Total encrypted files : {total}")
    print(f"Recovered OK          : {ok}")
    print(f"Recovered but check   : {len(check)}")
    print(f"Not recovered         : {len(failed)}")
    print("=" * 60)
    if check:
        print("\nPhotos to look at (recovered but may look wrong):")
        for r in check:
            print(f"  - {r[0]}: {r[4]}")
    if failed:
        print("\nPhotos NOT recovered:")
        for r in failed:
            print(f"  - {r[0]}: {r[4]}")
    print(f"\nFull table saved to: {os.path.join(rec_dir, 'report.csv')}")


if __name__ == "__main__":
    main()
