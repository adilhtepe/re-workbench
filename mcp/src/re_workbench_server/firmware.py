"""Pure-Python firmware triage: no binwalk/JVM required. Signature scan for
embedded blobs plus a windowed Shannon-entropy map to spot compressed/encrypted
regions. Good enough to point a human at the interesting offsets; not a full
extractor."""

from __future__ import annotations

import math
from pathlib import Path

# (name, magic bytes). Offsets reported are where the magic starts.
_SIGNATURES: list[tuple[str, bytes]] = [
    ("gzip", b"\x1f\x8b\x08"),
    ("xz", b"\xfd7zXZ\x00"),
    ("lzma", b"\x5d\x00\x00"),
    ("bzip2", b"BZh"),
    ("zlib", b"\x78\x9c"),
    ("zip", b"PK\x03\x04"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("squashfs-le", b"hsqs"),
    ("squashfs-be", b"sqsh"),
    ("cramfs", b"\x45\x3d\xcd\x28"),
    ("jffs2-le", b"\x85\x19"),
    ("jffs2-be", b"\x19\x85"),
    ("ubifs", b"UBI#"),
    ("romfs", b"-rom1fs-"),
    ("cpio", b"070701"),
    ("ext-superblock", b"\x53\xef"),  # at offset 0x438 within a block; heuristic
    ("uImage", b"\x27\x05\x19\x56"),
    ("android-boot", b"ANDROID!"),
    ("device-tree", b"\xd0\x0d\xfe\xed"),
    ("elf", b"\x7fELF"),
    ("pe", b"MZ"),
    ("pem-private-key", b"-----BEGIN"),
    ("openssh-key", b"-----BEGIN OPENSSH"),
    ("certificate", b"-----BEGIN CERTIFICATE"),
    ("u-boot-env", b"bootcmd="),
]


def _entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    counts = [0] * 256
    for b in chunk:
        counts[b] += 1
    n = len(chunk)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h  # 0..8 bits/byte


def scan(path: str, max_hits: int = 200) -> dict:
    data = Path(path).read_bytes()
    size = len(data)

    hits = []
    for name, magic in _SIGNATURES:
        start = 0
        while len(hits) < max_hits:
            idx = data.find(magic, start)
            if idx < 0:
                break
            hits.append({"offset": idx, "hex_offset": hex(idx), "type": name})
            start = idx + 1
    hits.sort(key=lambda h: h["offset"])

    # Windowed entropy map: 4 KiB windows, report high-entropy runs.
    win = 4096
    ent = []
    for off in range(0, size, win):
        ent.append(round(_entropy(data[off : off + win]), 3))
    high = [
        {"offset": i * win, "hex_offset": hex(i * win), "entropy": e}
        for i, e in enumerate(ent)
        if e >= 7.5
    ]

    avg = round(sum(ent) / len(ent), 3) if ent else 0.0
    return {
        "path": str(Path(path).resolve()),
        "size": size,
        "average_entropy": avg,
        "likely_compressed_or_encrypted": avg >= 7.0,
        "signature_hits": hits[:max_hits],
        "high_entropy_windows": high[:max_hits],
        "note": (
            "High average entropy (>=7.0) suggests the image is compressed or "
            "encrypted as a whole. Signature hits point at embedded blobs; carve "
            "from the offset with dd and decompress to inspect."
        ),
    }


def extract_strings(
    path: str, min_len: int = 5, encoding: str = "both", limit: int = 2000
) -> dict:
    data = Path(path).read_bytes()
    out: list[dict] = []

    def _ascii():
        cur = bytearray()
        start = 0
        for i, b in enumerate(data):
            if 0x20 <= b < 0x7F:
                if not cur:
                    start = i
                cur.append(b)
            else:
                if len(cur) >= min_len:
                    out.append({"offset": start, "enc": "ascii", "s": cur.decode("ascii")})
                cur = bytearray()
        if len(cur) >= min_len:
            out.append({"offset": start, "enc": "ascii", "s": cur.decode("ascii")})

    def _utf16le():
        cur = bytearray()
        start = 0
        i = 0
        n = len(data) - 1
        while i < n:
            lo, hi = data[i], data[i + 1]
            if hi == 0 and 0x20 <= lo < 0x7F:
                if not cur:
                    start = i
                cur.append(lo)
                i += 2
            else:
                if len(cur) >= min_len:
                    out.append({"offset": start, "enc": "utf16le", "s": cur.decode("ascii")})
                cur = bytearray()
                i += 1
        if len(cur) >= min_len:
            out.append({"offset": start, "enc": "utf16le", "s": cur.decode("ascii")})

    if encoding in ("ascii", "both"):
        _ascii()
    if encoding in ("utf16le", "both"):
        _utf16le()

    out.sort(key=lambda s: s["offset"])
    return {
        "path": str(Path(path).resolve()),
        "count": len(out),
        "truncated": len(out) > limit,
        "strings": out[:limit],
    }


def _selfcheck() -> None:
    """Synthesize a blob: low-entropy header, a squashfs magic, a random
    (high-entropy) region, and a known string. Assert we detect each."""
    import os
    import tempfile

    blob = bytearray(b"\x00" * 4096)  # low-entropy header
    blob += b"hsqs" + b"\x00" * 60  # squashfs-le magic
    blob += os.urandom(8192)  # high-entropy region
    blob += b"admin:password123" + b"\x00" * 8

    f = Path(tempfile.gettempdir()) / "rewb_selfcheck.bin"
    f.write_bytes(blob)
    try:
        s = scan(str(f))
        types = {h["type"] for h in s["signature_hits"]}
        assert "squashfs-le" in types, f"squashfs not found: {types}"
        assert s["high_entropy_windows"], "high-entropy region missed"

        st = extract_strings(str(f), min_len=6)
        assert any("admin:password123" in x["s"] for x in st["strings"]), "string missed"
    finally:
        f.unlink(missing_ok=True)
    print("firmware selfcheck OK")


if __name__ == "__main__":
    _selfcheck()
