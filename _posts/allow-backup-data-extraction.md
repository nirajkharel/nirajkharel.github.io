---
title: allowBackup=true — Extracting App Data With adb backup
author: nirajkharel
date: 2026-06-05 14:30:00 +0800
categories: [Mobile Pentesting, Android]
tags: [Mobile Pentesting, Android, Backup, Data Disclosure]
render_with_liquid: false
---


`android:allowBackup` defaults to `true` if not specified in the manifest. The setting was designed for "user can restore their app data after factory reset". The side effect: `adb backup` can dump the app's entire data directory to a file on the user's machine, where the file is decryptable without root. For apps that store sensitive data in `/data/data/`, this is a data exfiltration vector that requires only USB debugging (which many users leave on).

<h4>Demo: <a href="https://github.com/nirajkharel/AllowBackupLeak">Github Repo</a>.</h4>

<br>**The pattern**

```xml
<application
    android:allowBackup="true"
    android:fullBackupContent="@xml/backup_rules"
    ...>
```

`allowBackup="true"` (or absent — same thing) enables both the legacy Key-Value backup and the modern Auto Backup. `fullBackupContent` lets the developer opt out of specific subdirectories, but most apps do not bother — they ship with `allowBackup="true"` and no `fullBackupContent` filter.

<br>**The extraction command**

```bash
adb backup -f target.ab -noapk com.target.app
```

The phone prompts the user to confirm. If they tap "Back up my data", `target.ab` is written to the host machine containing the encrypted (but with empty password) app data tarball. Convert to tar:

```bash
dd if=target.ab bs=24 skip=1 | openssl zlib -d > target.tar
# Or with abe.jar:
java -jar abe.jar unpack target.ab target.tar
```

Inside the tar: `apps/com.target.app/db/`, `apps/com.target.app/sp/`, `apps/com.target.app/f/` — the full data dir contents. Read `auth.xml`, dump `main.db`, harvest tokens.

<br>**Realism — when this actually matters**

The user has to tap "Back up my data" on the device. That is the realism gap. Three scenarios where it bridges:

**Pretextual support call.** Attacker calls the user pretending to be tech support, asks them to enable USB debugging "for diagnostics" and tap accept on a popup. The popup is the backup confirmation.

**Compromised desktop.** Attacker controls the user's PC. User has USB debugging enabled (developers, power users, many enterprise BYOD deployments). Backup fires when phone is plugged in.

**Lost / stolen device with USB debugging on.** Finder of the phone (legitimate or not) connects to a computer. If debugging was on and authorized, backup works without user interaction. Many users authorize debugging on their personal computers and never revoke.

The triage view on this for bounty programs: severity tracks with what the data dir contains. If `auth.xml` has session tokens, the impact is account takeover. If `main.db` has unencrypted PII, the impact is data exposure.

<br>**Identifying it**

Read the manifest:

```bash
grep 'allowBackup' AndroidManifest.xml
```

If the value is `true` or the attribute is missing, the app is backup-enabled. Check for `fullBackupContent`:

```xml
<application
    android:allowBackup="true"
    android:fullBackupContent="@xml/backup_rules">
```

If present, open the rules:

```xml
<full-backup-content>
    <include domain="sharedpref" path="non_secret_prefs.xml" />
    <exclude domain="sharedpref" path="auth.xml" />
    <exclude domain="database" path="." />
</full-backup-content>
```

Good apps exclude everything sensitive. Many apps have `fullBackupContent` for the sake of having it and exclude one file while shipping ten others unrestricted.

<br>**The exfiltration via attacker app — no ADB required**

`adb backup` is the standard path, but some apps and OEM SDKs expose backup-like APIs that can be triggered without ADB:

**BackupManager.requestRestore.** Some apps schedule restore operations. Less attacker-relevant.

**Google Drive backup blob.** Apps with `allowBackup="true"` and a logged-in Google account upload their backup to Drive. An attacker with the user's Google credentials downloads from Drive. Not a mobile-app finding directly, but the upstream cause is the manifest setting.

**OEM-specific backup tools.** Samsung Smart Switch, Huawei Backup, Xiaomi Mi Cloud. Each has its own backup format and trust model. Worth testing if the target is OEM-specific.

For the bug bounty, the standard `adb backup` PoC is sufficient. The triage understands the chain.

<br>**The keyword-targeting heuristic**

Bounty triagers downgrade `allowBackup=true` findings on apps that "obviously do not store sensitive data". The way to keep the severity is to demonstrate that this specific app's data dir contains sensitive content:

- Pull the backup.
- Show contents of `auth.xml` / `main.db` / `session.json` with sensitive fields visible.
- Frame the impact as account takeover or PII disclosure, not "user data can be backed up".

The framing flip moves the report from informational to medium-or-high.

For your own audit triage, apply the same heuristic manually — if the package name contains keywords matching banking, healthcare, government, or identity domains, the `allowBackup=true` finding deserves a higher severity tier in your writeup because the recovered data is intrinsically sensitive. Name the specific user data at stake in the report.

<br>**Defence**

```xml
<application
    android:allowBackup="false"
    ...>
```

The cleanest fix. For apps that want backup for non-sensitive prefs:

```xml
<full-backup-content>
    <exclude domain="sharedpref" path="auth.xml" />
    <exclude domain="database" path="." />
    <exclude domain="file" path="." />
    <include domain="sharedpref" path="ui_prefs.xml" />
</full-backup-content>
```

Exclude everything by default and include only what the user needs to restore (UI preferences, accessibility settings).

For Android 12+ targets, `android:dataExtractionRules` in API 31 is the modern replacement that lets you control device-to-device transfers separately from cloud backups.

<br>**Severity discussion**

Pure `allowBackup=true` with no `fullBackupContent` filter on a banking / wallet / health app: high, sometimes critical. The realism caveat is acknowledged in the report ("requires USB debugging + user confirmation on the device"). Some programs accept it as informational, some accept it as medium. The fact-based framing (here are the sensitive files exposed, here is what they contain) is what moves it up.

<br>**Closing**

`allowBackup=true` is the bug nobody wants to talk about because the realism gap is bigger than most Android-IPC bugs. The pivot from informational to medium is naming the specific sensitive content. Worth pulling a backup on every banking / healthcare / wallet app you audit and listing what falls out.

Happy Hacking !!
