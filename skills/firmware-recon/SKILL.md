---
name: firmware-recon
description: Reconnaissance and triage of firmware images, IoT/embedded blobs, and raw dumps using the re-workbench MCP (pure-Python signature + entropy scan, string extraction). Use when the user hands over a firmware image, flash dump, .bin/.img/.rom, router/camera/IoT update file, or any unknown blob and asks what's inside, to unpack it, or to find secrets/keys. Triggers on "firmware", "unpack this image", "IoT", "flash dump", "what's in this .bin", "find hardcoded keys/passwords", "extract filesystem".
---

# Firmware Recon

Locate the interesting parts of a firmware image and pull out secrets, without
needing binwalk installed. The re-workbench MCP does signature scanning and a
windowed entropy map in pure Python; you interpret the map and guide carving.

## The workflow

1. **`scan_firmware(path)`** — get the lay of the land in one call:
   - **average_entropy**: if ~≥7.0 the whole image is compressed or encrypted.
     A uniformly high-entropy image with *no* signature hits usually means
     whole-image encryption — look for the bootloader/updater that decrypts it,
     not a filesystem inside.
   - **signature_hits**: offsets of embedded blobs — `squashfs`, `jffs2`,
     `cramfs`, `ubifs`, `cpio`, `gzip`/`xz`/`lzma`, `uImage` headers, device
     trees, and PEM keys/certs. This is your carving map.
   - **high_entropy_windows**: 4 KiB windows ≥7.5 bits/byte — compressed/packed
     regions. A low-entropy header followed by a long high-entropy run is the
     classic `[header][compressed filesystem]` layout.

2. **Read the structure.** Typical embedded layout is
   `[bootloader] [kernel (uImage + compressed)] [rootfs (squashfs)] [nvram/config]`.
   Map the signature offsets onto that mental model. A `squashfs` magic at
   offset X is where the root filesystem starts.

3. **Carve and decompress** (guide the user; these run in their shell):
   ```bash
   # carve a squashfs starting at offset 0x1a0000
   dd if=firmware.bin of=rootfs.sqsh bs=1 skip=$((0x1a0000))
   unsquashfs rootfs.sqsh        # needs squashfs-tools
   # carve + gunzip a compressed blob
   dd if=firmware.bin of=blob.gz bs=1 skip=$((0xADDR)) && gunzip blob.gz
   ```
   If `binwalk` IS available on their machine, `binwalk -e firmware.bin` is the
   faster path — recommend it. The MCP scan is the always-available fallback and
   a good cross-check.

4. **`list_strings(path)`** on the image and on carved pieces — the highest-value
   step for IoT. Hunt for:
   - Hardcoded credentials: `admin:`, `password=`, `root:`, telnet/ssh defaults
   - Keys and certs: `-----BEGIN`, private keys, API tokens
   - Endpoints: update URLs, C2/cloud hosts, IPs, MQTT brokers
   - Config: `nvram`, `u-boot` env (`bootcmd=`, `bootargs=`), version banners
   - Backdoors: hidden accounts, magic knock strings, debug shells

5. **Pull ELF binaries out of the rootfs** and hand them to the `ghidra-triage`
   skill — the busybox applets, the web server (`httpd`/`lighttpd`), and any
   vendor daemon are where the exploitable logic lives.

## Interpretation notes

- **No signature hits + high entropy** = encrypted/packed whole image. Find the
  first-stage loader (often plaintext at the start) and reverse *its* decrypt
  routine with `ghidra-triage`.
- **Entropy dips inside a high-entropy run** often mark boundaries between
  concatenated compressed sections — good carve points.
- Offsets from `scan_firmware` are byte offsets into the file; `dd skip=` with
  `bs=1` uses them directly.

## Reporting

```
# <image> — firmware recon
Size / average entropy: ... (verdict: compressed? encrypted? plaintext?)
Layout (by offset):
  0x0        <bootloader?>
  0x<off>    uImage (kernel)
  0x<off>    squashfs (rootfs)  <- carve here
Secrets found: <creds/keys/urls with offsets>
Binaries to reverse next: <paths inside rootfs>
Recommended carve commands: ...
```

## Safety and scope

For firmware you own or are authorized to assess (your device, a client
engagement, published research targets, CTF). Extracting and reading is analysis.
If you surface real secrets (live keys, credentials for someone else's fleet),
tell the user to rotate/report them — don't use them against live systems.
