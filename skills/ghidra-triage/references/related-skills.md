# Related RE skills (installed, invoke by name — not bundled)

These reverse-engineering skills are already installed and active on this machine
(from `anthropic-cybersecurity-skills` and the `reverse-engineering` plugin).
re-workbench does the Ghidra/lief tooling; reach for these for technique depth on
a specific artifact type. Invoke a skill by its name via the Skill tool.

## Malware RE
- `reverse-engineering-malware-with-ghidra` — Ghidra disassembly/decompilation workflow
- `analyzing-golang-malware-with-ghidra` — Go-specific (runtime, string recovery)
- `reverse-engineering-rust-malware` — Rust binary RE
- `reverse-engineering-dotnet-malware-with-dnspy` — .NET / IL decompilation
- `extracting-config-from-agent-tesla-rat` — RAT config recovery pattern
- `reverse-engineering-ransomware-encryption-routine` — crypto-routine RE for decryptor flaws
- `analyzing-cobalt-strike-beacon-configuration` — beacon config extraction
- `analyzing-linux-elf-malware` — ELF malware static/dynamic
- `analyzing-bootkit-and-rootkit-samples`, `analyzing-uefi-bootkit-persistence` — boot/UEFI implants
- `performing-static-malware-analysis-with-pe-studio` — PE static triage
- `performing-malware-triage-with-yara` — YARA classification

## Unpacking & deobfuscation
- `analyzing-packed-malware-with-upx-unpacker` — UPX and packing
- `deobfuscating-javascript-malware`, `deobfuscating-powershell-obfuscated-malware`
- `analyzing-macro-malware-in-office-documents`, `analyzing-pdf-malware-with-pdfid`
- `analyzing-malware-sandbox-evasion-techniques` — anti-analysis defeat
- (plugin) `anti-reversing-techniques` — anti-debug/anti-VM/obfuscation defeat

## Firmware / IoT / embedded
- `performing-firmware-extraction-with-binwalk` — when binwalk is available
- `performing-firmware-malware-analysis` — embedded backdoor RE
- `performing-plc-firmware-security-analysis` — PLC/ICS firmware
- `auditing-uefi-firmware-with-chipsec` — SPI-flash/UEFI config audit

## Mobile
- `reverse-engineering-android-malware-with-jadx`, `analyzing-android-malware-with-apktool`
- `performing-android-app-static-analysis-with-mobsf`
- `reverse-engineering-ios-app-with-frida`, `analyzing-ios-app-security-with-objection`

## Memory forensics
- `analyzing-memory-dumps-with-volatility`, `performing-memory-forensics-with-volatility3`
- `extracting-credentials-from-memory-dump`, `extracting-memory-artifacts-with-rekall`
- `analyzing-linux-kernel-rootkits`, `detecting-rootkit-activity`
- (plugin) `memory-forensics`

## Exploitation & protocol
- `performing-binary-exploitation-analysis` — memory corruption / ROP
- `analyzing-heap-spray-exploitation`
- (plugin) `protocol-reverse-engineering` — proprietary protocol dissection
- `analyzing-network-traffic-of-malware`, `analyzing-network-covert-channels-in-malware`

## Dynamic / sandbox
- `performing-automated-malware-analysis-with-cape`, `analyzing-malware-behavior-with-cuckoo-sandbox`
- `performing-dynamic-analysis-with-any-run`
