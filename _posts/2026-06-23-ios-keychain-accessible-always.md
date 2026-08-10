---
title: iOS - Keychain Accessibility Misuse
author: nirajkharel
date: 2026-06-23 14:30:00 +0800
categories: [Mobile Pentesting, iOS]
tags: [Mobile Pentesting, iOS, Keychain, Secret Storage]
render_with_liquid: false
---


The iOS Keychain is the right place to store secrets. The detail that determines whether your secrets are actually protected: which `kSecAttrAccessible` constant the developer chose. iOS provides six levels of accessibility, and only the strictest one survives device theft and jailbreak-based data extraction. The most permissive, `kSecAttrAccessibleAlways`, survives every lock state and is readable from a jailbroken device without the user's passcode.

<aside class="lab">
  <p><strong>Vulnerable demo</strong> · <a href="https://github.com/nirajkharel/VulnLabApp">VulnLabApp</a></p>
  <ul>
    <li><code>ios/VulnLabApp/ViewControllers/LoginViewController.swift</code></li>
  </ul>
</aside>

<br>**The six accessibility levels**

From most to least restrictive:

```
kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
kSecAttrAccessibleWhenUnlockedThisDeviceOnly
kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
kSecAttrAccessibleWhenUnlocked
kSecAttrAccessibleAfterFirstUnlock
kSecAttrAccessibleAlways   (deprecated but still functional)
```

The `ThisDeviceOnly` variants exclude the item from iCloud Keychain sync and from device-to-device transfers. The `WhenPasscodeSet` variant ties the item to the existence of a device passcode, removing the passcode deletes the item.

Apps that store sensitive secrets and choose `kSecAttrAccessibleAlways` (or the deprecated `kSecAttrAccessibleAlwaysThisDeviceOnly`) are giving up the strongest protections. The secrets are readable:

- When the device is locked.
- After a cold boot before any unlock.
- From a jailbroken device with `keychain_dumper` or similar tools.
- From a forensic acquisition (Cellebrite-style) that bypasses unlock.

<br>**The vulnerable pattern**

`LoginViewController.storeApiKeyWithAlwaysAccessible` in VulnLabApp persists the API key with the broadest possible accessibility constant:

<img alt="LoginViewController.swift - storeApiKeyWithAlwaysAccessible with kSecAttrAccessibleAlways (highlight 1) and SecItemAdd call (highlight 2) annotated" loading="lazy" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/ios-keychain-annotated.png">

<br>**Highlight 1** is `kSecAttrAccessibleAlways` - the accessibility constant. It grants read access at every lock state: locked screen, cold boot before first unlock, and via any jailbreak-based keychain extractor. This single constant choice removes the Keychain's entire protection model for this item.

**Highlight 2** is `SecItemAdd` - the call that commits the query dictionary to the Keychain with the insecure attribute already in it. From this point, `SecItemCopyMatching` returns the plaintext API key to any process that gains filesystem access - no device unlock required.

The service identifier is the bundle ID (`com.vulnlab.iosapp`), the account is `api_key`, and the value is the hardcoded production-looking string `sk-prod-8f3k2j9x0q1w5e6r`. Every characteristic of this entry, service, account, accessibility, is recoverable from a jailbroken device or a forensic acquisition.

<br>**Identifying the bug**

Pull the IPA, decompile, and grep:

```bash
strings Payload/VulnLabApp.app/VulnLabApp | grep kSecAttrAccessible
```

Each match shows the accessibility level the binary uses. `kSecAttrAccessibleAlways` is the worst case.

For Swift code, the constants are mapped to Foundation strings (`kSecAttrAccessibleAlways` is the string `"dku"`). The strings command catches both.

At runtime, hook `SecItemAdd` and `SecItemUpdate`:

```javascript
const SecItemAdd = Module.findExportByName('Security', 'SecItemAdd');
Interceptor.attach(SecItemAdd, {
  onEnter: function (args) {
    const dict = new ObjC.Object(args[0]);
    console.log('[SecItemAdd] ' + dict);
  }
});
```

The trace shows every keychain insert with its full attribute dictionary, including the accessibility level.

<br>**Extracting keychain items from a jailbroken device**

If you have access to the test device (or in the case of a stolen device with JB), dump every keychain item the app stored:

```bash
# Via objection
objection -g com.vulnlab.iosapp explore
ios keychain dump

# Or frida-ios-dump's keychain action
fridump --target-process com.vulnlab.iosapp --keychain
```

The output lists every keychain item the app stored. Items with `kSecAttrAccessibleAlways` are readable. Items with `WhenPasscodeSetThisDeviceOnly` may not be, depending on whether the device has a passcode set and the dump method.

Either tool surfaces the same data, alias, account, service, accessibility level, and `v_Data` (the actual secret payload, returned base64-encoded; decode for the plaintext). The keychain query under the hood is `SecItemCopyMatching` with `kSecMatchLimitAll`. You can also call it yourself from Frida if you prefer manual control:

```javascript
const SecItemCopyMatching = new NativeFunction(
    Module.findExportByName('Security', 'SecItemCopyMatching'),
    'int', ['pointer', 'pointer']);

const query = ObjC.classes.NSMutableDictionary.dictionary();
query.setObject_forKey_(ObjC.classes.NSString.stringWithString_('genp'), 'class');
query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), 'r_Data');
query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), 'r_Attributes');
query.setObject_forKey_(ObjC.classes.NSString.stringWithString_('m_LimitAll'), 'm_Limit');

const resultPtr = Memory.alloc(Process.pointerSize);
const status = SecItemCopyMatching(query, resultPtr);
console.log('status=' + status, 'items=' + new ObjC.Object(Memory.readPointer(resultPtr)));
```

This dumps every generic-password keychain item the app has stored, including the accessibility level on each.

<br>**The threat model gap**

The argument for `kSecAttrAccessibleAfterFirstUnlock` (a common choice) is "the user has already unlocked once after boot, so the device is in a trusted state". The argument against:

- "Trusted state" is broken by jailbreak. Once jailbroken, the device's lock state is irrelevant for keychain access.
- Cold-boot forensic attacks may be possible on older iOS versions.
- BFU (Before First Unlock) acquisition tools target unlocked states specifically.

For apps that need to access keys before the user unlocks (background fetch tasks, location updates), `AfterFirstUnlock` is necessary. For apps where the keys are only needed while the user is actively using the app, `WhenUnlocked` (or `WhenUnlockedThisDeviceOnly` if iCloud sync should be excluded) is correct.

The right choice is:

```swift
// User-facing secret (token, password, biometric-bound key):
kSecAttrAccessibleWhenUnlockedThisDeviceOnly

// Background-process secret (push notification key):
kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
```

`Always` is essentially never correct on modern iOS.

<br>**The `kSecAttrAccessControl` upgrade**

Beyond accessibility, `kSecAccessControl` lets developers add biometric or passcode requirements:

```swift
let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    .biometryCurrentSet,    // require biometric, invalidate on enrollment change
    nil)
```

With this, accessing the keychain item requires the user to authenticate via biometric. The Keychain Service shows the biometric prompt automatically. Bypassing this requires:

- Hooking `LAContext.evaluatePolicy` to return success without prompting. Doable with Frida if the app's process is open.
- Replacing `SecItemCopyMatching`'s return value with hardcoded values. Same Frida hook.

Apps that combine `WhenPasscodeSetThisDeviceOnly` + `biometryCurrentSet` are well-defended against everything short of an attacker who is in the app's process.

<br>**Closing**

iOS Keychain is a tiered storage system. The tier matters more than the fact that you used Keychain. Worth grepping `kSecAttrAccessible` strings on every iOS app you audit, and matching the chosen level against the threat model the app actually faces.

Happy Hacking !!
