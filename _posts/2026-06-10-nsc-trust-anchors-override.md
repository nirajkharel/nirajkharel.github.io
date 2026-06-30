---
title: Network Security Config Trust-Anchor Override
author: nirajkharel
date: 2026-06-10 14:30:00 +0800
categories: [Mobile Pentesting, Android]
tags: [Mobile Pentesting, Android, TLS, Network Security Config]
render_with_liquid: false
---


`network_security_config.xml` is Android's declarative way to control TLS trust. From API 24, Android stopped trusting user-installed CAs by default - apps had to explicitly opt in. That protection disappears the moment `<certificates src="user" />` lands in `<base-config>`. VulnLabApp ships exactly that in production, making every HTTPS connection interceptable by any proxy whose CA is installed in the device's user cert store.

<aside class="lab">
  <p><strong>Vulnerable demo</strong> · <a href="https://github.com/nirajkharel/VulnLabApp">VulnLabApp</a></p>
  <ul>
    <li><code>android/app/src/main/res/xml/network_security_config.xml</code></li>
  </ul>
</aside>

<br>**Where do you find it?**

Pull the NSC file from the APK and check the manifest:

```bash
find . -name 'network_security_config*' -exec cat {} \;
grep -E 'networkSecurityConfig|debuggable|usesCleartextTraffic' AndroidManifest.xml
```

VulnLabApp's manifest wires all three flags on at once:

```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:debuggable="true"
    android:usesCleartextTraffic="true">
```

<br>**What does the config do?**

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <!-- VULN: user certs trusted in production build -->
            <certificates src="user" />
        </trust-anchors>
    </base-config>

    <domain-config>
        <domain includeSubdomains="true">api.vulnlabapp.example.com</domain>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </domain-config>
</network-security-config>
```

`<certificates src="system" />` trusts the device's built-in CA store. `<certificates src="user" />` adds every CA the user installed via Settings - including mitmproxy's CA, Burp's CA, Charles's CA. Because this sits in `<base-config>` and not `<debug-overrides>`, it applies to every connection in every build. The domain config for `api.vulnlabapp.example.com` repeats the same mistake - any pinning intended for that domain is immediately undermined by the user-cert anchor above it.

<br>**Can you confirm it at runtime?**

Install mitmproxy's CA in the device user cert store (Settings - Security - Install certificate), configure the proxy, and make any HTTPS request from the app. Traffic decrypts in mitmproxy with no certificate error. No Frida needed for the actual interception - the NSC config does all the work.

<br>**What are the two bug classes?**

**User certs in `<base-config>`.** This is what VulnLabApp does. No `android:debuggable` dependency - user certs are trusted in every build. A developer added `<certificates src="user" />` to make proxy interception work during testing and forgot to remove it or gate it.

**`<debug-overrides>` shipped to production.** Some apps correctly put user certs inside `<debug-overrides>`, which is supposed to activate only when `android:debuggable="true"`. If the release build ships with `android:debuggable="true"` - also present in VulnLabApp's manifest - `<debug-overrides>` activates in production and the protection collapses. Both bugs are present here, though user-certs-in-base-config is the more direct one.

<br>**What does a missing pin-set look like?**

NSC also supports cert pinning:

```xml
<domain-config>
    <domain includeSubdomains="true">api.target.com</domain>
    <pin-set expiration="2027-01-01">
        <pin digest="SHA-256">primary-key-hash==</pin>
        <pin digest="SHA-256">backup-key-hash==</pin>
    </pin-set>
</domain-config>
```

Two failure modes worth checking:
- **No `<pin-set>`** - a `<domain-config>` with only `<trust-anchors>` does not pin anything. Many developers assume any `<domain-config>` means pinning. It does not.
- **Expired `expiration` date** - after the date passes the pin is silently not enforced. Apps stay on the store for years; pins do not rotate themselves.

VulnLabApp's `<domain-config>` for `api.vulnlabapp.example.com` has no `<pin-set>` - and even if it did, the user-cert trust anchor above would bypass it anyway.

<br>**Closing**

The API-24 protection against user-installed CAs exists specifically to block the mitmproxy interception pattern. `<certificates src="user" />` in `<base-config>` disables it for every build. The audit is one XML file and one grep. On every app you test, open `network_security_config.xml` first.

Happy Hacking !!
