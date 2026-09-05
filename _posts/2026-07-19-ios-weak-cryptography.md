---
title: iOS - Weak Cryptography
author: nirajkharel
date: 2026-07-19 14:30:00 +0800
categories: [Mobile Pentesting, iOS]
tags: [Mobile Pentesting, iOS, Cryptography, DES, MD5, CBC, Padding Oracle]
render_with_liquid: false
---


iOS ships `CommonCrypto` as the native symmetric cipher library. Every algorithm it supports is accessible, including the broken ones. DES, 3DES, RC4, MD5, SHA-1 - all compile, link, and run without warnings. The same `CCCrypt` call that runs AES-GCM also runs single-DES. The framework does not enforce algorithm policy; the developer's choice is the only safeguard. Apps from codebases that pre-date modern algorithm guidance routinely ship production builds that encrypt user data with ciphers that are broken, keys that are guessable, and modes that are vulnerable to padding oracles.

<aside class="lab">
  <p><strong>Vulnerable demo</strong> · <a href="https://github.com/nirajkharel/VulnLabAppiOS">VulnLabAppiOS</a></p>
  <ul>
    <li><code>ios/VulnLabAppiOS/ViewControllers/CryptoViewController.swift</code></li>
  </ul>
</aside>

<br>**The shape - four bugs in one class**

<img alt="CryptoViewController.swift encryptWithDES with static 8-byte key (highlight 1) and ECB mode (highlight 2)" loading="lazy" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/ios-weakcrypto-annotated.png">

<br>**Highlight 1** is `let key = "vulnkey".data(using: .utf8)!` - static 8-byte DES key hardcoded as a string literal; recoverable via `strings` on the binary and reusable to decrypt any ciphertext produced by this function.

**Highlight 2** is `CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode)` - ECB mode means identical 8-byte plaintext blocks produce identical ciphertext blocks; structural patterns in the plaintext (repeated fields, padding) are directly visible in the ciphertext.

<br>**Bug 1 - DES / 3DES / RC4**

Single DES has a 56-bit key. With modern GPU hashcat rigs, exhaustive search takes hours to days depending on the hardware. 3DES was withdrawn as a NIST standard in 2023. RC4 has known biases in the first bytes of its keystream and fails plaintext-recovery attacks at scale.

Identifying it:

```bash
nm Payload/VulnLabAppiOS.app/VulnLabAppiOS | grep -E 'kCCAlgorithmDES|kCCAlgorithm3DES|kCCAlgorithmRC4'
# debug build — code is in the dylib:
nm Payload/VulnLabAppiOS.app/*.dylib | grep -E 'kCCAlgorithmDES|kCCAlgorithm3DES|kCCAlgorithmRC4'
```

Any match is the finding. These constants are embedded as integers in the binary; the string form sometimes appears in debug symbols.

<br>**Bug 2 - MD5 / SHA-1 for password or integrity checks**

MD5 and SHA-1 are collision-broken. For password storage, a collision attack allows constructing a password hash that matches without knowing the original. For HMAC-MD5, attacks are harder but the algorithm is still non-compliant with modern standards (FIPS 140-3, SOC 2).

```bash
nm Payload/VulnLabAppiOS.app/VulnLabAppiOS | grep -E 'CC_MD5|CC_SHA1|kCCHmacAlgMD5|kCCHmacAlgSHA1'
# debug build — code is in the dylib:
nm Payload/VulnLabAppiOS.app/*.dylib | grep -E 'CC_MD5|CC_SHA1|kCCHmacAlgMD5|kCCHmacAlgSHA1'
```

The presence of `CC_MD5` in a password or authentication code path is reportable. In a checksum-only path (verifying a downloaded file against a publisher-provided MD5), it's lower severity.

<br>**Bug 3 - AES-CBC with static IV and PKCS7 padding**

A zero or hardcoded IV combined with CBC mode and PKCS7 padding creates two problems:

- **Static IV**: two identical plaintexts under the same key produce identical first cipher blocks. Patterns in the plaintext become visible in the ciphertext (the ECB penguin problem applies to CBC when the IV is fixed).
- **Padding oracle**: any network endpoint that decrypts PKCS7-padded CBC ciphertext and returns different responses for valid vs. invalid padding allows the [padding oracle attack](https://en.wikipedia.org/wiki/Padding_oracle_attack). An attacker can decrypt the ciphertext one byte at a time with ~128 queries per byte.

Runtime confirmation - hook the IV extraction:

```javascript
const CCCrypt = Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt');
Interceptor.attach(CCCrypt, {
  onEnter: function (args) {
    const algo = args[1].toInt32();
    const opts  = args[2].toInt32();
    const ivLen = 16;
    const ivPtr = args[6];
    if (algo === 0 /* AES */ && ivPtr.isNull() === false) {
      const iv = ivPtr.readByteArray(ivLen);
      console.log('[CCCrypt] AES opts=' + opts + ' IV=' + Array.from(new Uint8Array(iv)).map(b => b.toString(16).padStart(2,'0')).join(''));
    }
  }
});
```

If the IV is `00000000000000000000000000000000` on every call, the static IV bug is confirmed.

The fix is a random IV generated fresh per encryption, prepended to the ciphertext:

```swift
// FIX: random IV generated per encryption
var ivBytes = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
let rc = SecRandomCopyBytes(kSecRandomDefault, ivBytes.count, &ivBytes)  // crypto RNG
let iv = Data(ivBytes)
// Prepend iv to ciphertext so the decryptor can read it back
let ciphertext = iv + encryptedData
```

<br>**Bug 4 - arc4random for cryptographic key generation**

`arc4random()` is a PRNG, not a CSPRNG. Its seed is not secret (it can be reconstructed from other observable outputs), and its output is not suitable for key material, nonces, or session tokens.

```bash
nm Payload/VulnLabAppiOS.app/VulnLabAppiOS | grep -E '\barc4random\b|\brand\b|\bsrand\b'
# debug build — code is in the dylib:
nm Payload/VulnLabAppiOS.app/*.dylib | grep -E '\barc4random\b|\brand\b|\bsrand\b'
```

The correct API is `SecRandomCopyBytes`:

```swift
// FIX: cryptographically secure random bytes
var keyBytes = [UInt8](repeating: 0, count: 32)
let status = SecRandomCopyBytes(kSecRandomDefault, keyBytes.count, &keyBytes)
guard status == errSecSuccess else { fatalError("key generation failed") }
let key = Data(keyBytes)
```

<br>**Closing**

CommonCrypto does not stop you from calling `kCCAlgorithmDES`. Neither does Swift. The only check is the audit. Grep for algorithm constants, grep for IV usage, grep for `arc4random`. Four greps, four distinct findings, four separate risk scores. This is one of the higher-yield signal categories on iOS - the fix is one constant swap, and the finding is real regardless of whether anyone is actively exploiting it.

Happy Hacking !!
