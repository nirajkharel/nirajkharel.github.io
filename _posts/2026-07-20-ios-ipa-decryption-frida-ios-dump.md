---
title: iOS - IPA Decryption with frida-ios-dump
author: nirajkharel
date: 2026-07-20 14:30:00 +0800
categories: [Mobile Pentesting, iOS]
tags: [Mobile Pentesting, iOS, IPA Decryption, FairPlay, frida-ios-dump, Static Analysis]
render_with_liquid: false
---


App Store binaries ship with FairPlay DRM. `otool` on the on-disk binary shows `cryptid=1`, which means every attempt at static analysis, class-dump, Ghidra, Hopper, `strings`, hits encrypted bytes. `frida-ios-dump` dumps the binary from process memory after the kernel has already decrypted it, handing you a `cryptid=0` IPA ready for static tooling.

<br>**Why the on-disk binary blocks you**

```bash
otool -l Payload/VulnLabAppiOS.app/VulnLabAppiOS | grep -A 4 LC_ENCRYPTION_INFO
```

```
          cryptoff 16384
         cryptsize 2850816
           cryptid 1          # 1 = encrypted
```

`cryptid=1` means the `__TEXT` segment is encrypted with the device's hardware key. Every byte in `cryptoff..cryptoff+cryptsize` is ciphertext on disk. Disassemblers show garbage. `strings` returns near nothing useful.

<br>**Setup**

```bash
pip3 install frida-ios-dump
```

frida-ios-dump SSHes into the device, spawns the target app via Frida, reads the decrypted pages out of process memory, and re-packs them into an IPA.

Forward the device's SSH port over USB so you do not need the device's Wi-Fi IP:

```bash
# iproxy maps localhost:2222 -> device:22 over USB
iproxy 2222 22
```

Then tunnel the dump tool through that forwarded port:

```bash
ssh -p 2222 root@localhost -L 2222:localhost:22
```

Default Checkra1n / unc0ver SSH credentials are `root:alpine`. Change them if you leave the device networked.

<br>**Running frida-ios-dump**

```bash
python3 frida-ios-dump.py -H 127.0.0.1 -p 2222 -u root -P alpine VulnLabAppiOS
```

The tool:

1. Resolves the app's bundle ID from the installed app list.
2. Spawns the process via `frida.spawn`.
3. Maps every `__TEXT` page from process memory once the loader has decrypted them.
4. Pulls Frameworks/ dylibs if present (each may have its own `cryptid`).
5. Re-packs everything into `VulnLabAppiOS.ipa`.

The output file lands in the current directory. Progress prints each module as it is pulled.

<br>**Confirming decryption**

```bash
unzip VulnLabAppiOS.ipa -d Payload/
otool -l Payload/VulnLabAppiOS.app/VulnLabAppiOS | grep -A 4 LC_ENCRYPTION_INFO
```

```
          cryptoff 16384
         cryptsize 2850816
           cryptid 0          # 0 = decrypted
```

`cryptid=0` means the segment is plaintext. Static tooling now works.

<br>**IPA structure walkthrough**

```
VulnLabAppiOS.ipa
└── Payload/
    └── VulnLabAppiOS.app/
        ├── VulnLabAppiOS          # the Mach-O binary
        ├── Info.plist          # bundle ID, version, permissions
        ├── Frameworks/         # embedded dylibs, may each need separate decryption
        │   └── AFNetworking.framework/
        └── _CodeSignature/
            └── CodeResources   # file hashes (resign before side-loading)
```

`Info.plist` tells you the bundle identifier, minimum iOS version, URL schemes, and permission usage strings. Read it before anything else.

<br>**Hand-off to class-dump**

```bash
class-dump -H Payload/VulnLabAppiOS.app/VulnLabAppiOS -o headers/
# debug build installed via Xcode — code is in the dylib:
class-dump -H Payload/VulnLabAppiOS.app/*.dylib -o headers/
```

Every Objective-C class, ivar, and method signature drops into `headers/`. For Swift classes the symbol table still exposes method names and the string literals in `__TEXT,__cstring` are plaintext.

<br>**Hand-off to nm**

```bash
nm Payload/VulnLabAppiOS.app/VulnLabAppiOS \
  | grep -E 'api\.|token|secret|password|Bearer|https://' \
  | sort -u
```

Common hits on real apps: API base URLs, AWS access key prefixes, hardcoded tokens, debug endpoint hostnames. Each is a follow-up test target.

<br>**How frida-ios-dump maps the pages**

At the Frida RPC layer the tool calls `Process.enumerateModules()` to list every loaded module and its base address, then iterates `module.base` through `module.base + module.size` in page-aligned chunks, calling `Memory.readByteArray(addr, pageSize)`. The kernel has already run FairPlay decryption at load time, so the read returns plaintext. The tool replaces the encrypted region in the on-disk binary with the memory-read bytes and zeroes `cryptid`.

For apps with embedded Frameworks/, the same read is done per-framework since each has its own `LC_ENCRYPTION_INFO`.

<br>**When frida-ios-dump fails**

- **App crashes on Frida attach** - the app has anti-Frida detection. Run the bypass script from the [iOS Frida Detection Bypass post](2026-07-11-ios-frida-detection-bypass.md) as a pre-script.
- **cryptid is still 1 after dump** - a framework was not pulled. Run the tool with `--target` pointing at the specific framework path.
- **Checkra1n device, wrong arch** - ensure you are running arm64 frida-server, not armv7.

<br>**Closing**

FairPlay is a distribution control, not a security layer against a tester with the device. `frida-ios-dump` automates the decryption in under a minute. The resulting IPA feeds every static tool in the toolchain. Run it first on every App Store target.

Happy Hacking !!
