---
title: Android - Tokens and PII in Logcat
author: nirajkharel
date: 2026-06-15 14:30:00 +0800
categories: [Mobile Pentesting, Android]
tags: [Mobile Pentesting, Android, Logging, Data Disclosure]
render_with_liquid: false
---


`Log.d`, `Log.v`, `Log.i` calls in production builds dump strings to logcat. On Android 4.1+ the `READ_LOGS` permission is signature-only, so a regular third-party app cannot read another app's logs. But anyone with USB debugging enabled can. Crash-reporting SDKs like Crashlytics, Sentry, and Bugsnag also capture nearby logcat output when a crash occurs and ship it off-device. If sensitive data is in a `Log.*` call that was not stripped by ProGuard/R8, it leaks.

<aside class="lab">
  <p><strong>Vulnerable demo</strong> · <a href="https://github.com/nirajkharel/VulnLabApp">VulnLabApp</a></p>
  <ul>
    <li><code>android/app/src/main/java/com/vulnlab/app/activities/LoginActivity.java</code></li>
    <li><code>android/app/src/main/java/com/vulnlab/app/VulnApplication.java</code></li>
  </ul>
</aside>

<br>**Where do you find it?**

```bash
grep -rn 'Log\.\(d\|v\|i\|w\|e\)(' decompile/sources/ | grep -E 'token|auth|password|email|secret|key|ssn|dob|cc|bearer'
```

**What does this code do?**

```java
// LoginActivity.java — TAG = "VulnLabLogin"
Log.d(TAG, "Login attempt: email=" + email + " password=" + password);
Log.d(TAG, "Session token issued: " + fakeToken);
Log.d(TAG, "User PII: DOB=1990-01-15, SSN=123-45-6789, CC=4111111111111111");

// VulnApplication.java — TAG = "VulnLabApp", fires once on process start
Log.d(TAG, "VulnLabApp started. API key: sk-prod-8f3k2j9x0q1w5e6r");
Log.d(TAG, "DB connection: jdbc:mysql://internal.vulnlab.corp:3306/prod?user=admin&password=S3cr3t!");
Log.d(TAG, "OAuth client secret: oauth_secret_abc123xyz789");
```

These strings are constructed at runtime and appear verbatim in logcat. The default `proguard-android-optimize.txt` does NOT strip Log calls - apps need explicit rules in their ProGuard config for that to happen.

<br>**Can you confirm it at runtime?**

```bash
adb shell am start -n com.vulnlab.app/.activities.LoginActivity
adb logcat -s "VulnLabLogin:*" "VulnLabApp:*"
```

Or hook every Log call from Frida to catch them all regardless of tag:

```javascript
Java.perform(function () {
  const Log = Java.use('android.util.Log');
  ['v', 'd', 'i', 'w', 'e'].forEach(function (level) {
    Log[level].overload('java.lang.String', 'java.lang.String').implementation =
        function (tag, msg) {
      console.log('[Log.' + level + '][' + tag + '] ' + msg);
      return this[level](tag, msg);
    };
  });
});
```

Walk the app through a login cycle. The trace prints every log call and its content, including the password and session token from `LoginActivity` and the API key from `VulnApplication` on process start.

<br>**What about READ_LOGS restrictions?**

Three reachability paths that still matter:

**USB debugging.** Anyone with physical access who enables USB debugging can run `adb logcat`. Same realism as `allowBackup` exploits.

**OEM-bundled apps.** Samsung, Xiaomi, Huawei, Oppo ship "diagnostics" or "device assistant" apps with `READ_LOGS` granted by system signature. If one of those apps is compromised or abused, it can read the full logcat stream.

**Integrated crash reporters.** Apps that ship Crashlytics, Sentry, or Bugsnag have those SDKs capturing logcat output around crashes. The log content goes to the SDK provider's infrastructure. The data leaves the device without the user knowing.

The crash-reporter path is the strongest bounty framing because it removes the USB requirement - the data exits to a third party automatically.

<br>**What do exception logs leak?**

Even when `Log.d` calls are stripped by ProGuard, exception handlers often are not:

```java
try {
    apiClient.request(url, body);
} catch (Exception e) {
    Log.e("Network", "Request failed: " + url + " body=" + body, e);
}
```

If `body` contains credentials or session tokens, those appear in the exception log verbatim. Crash reporters capture exception logs even when debug logging is stripped.

<br>**What about third-party logging wrappers?**

Many apps use Timber or custom wrappers:

```bash
grep -rn 'Timber\.\|Logger\.d\|LogUtils\.' decompile/
```

Same audit applies. `Timber.d(...)` routes to Android's `Log` under the hood. The wrapper does not strip the call unless specifically configured.

<br>**What is the fix?**

Build-time stripping via ProGuard:

```proguard
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
    public static *** w(...);
}
-assumenosideeffects class timber.log.Timber {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
}
```

This removes the calls entirely from the compiled bytecode. `BuildConfig.DEBUG` guards are more fragile - they depend on every developer remembering to wrap every call.

<br>**Closing**

`Log.d` in release builds is passive data exfiltration. The audit is mechanical - one grep, then check what's in the strings. The realistic attack chain is "developer has USB debugging on, attacker has five seconds with the device" or "app ships a crash reporter that forwards the log contents off-device". Both chains are bounty-relevant on any app that logs tokens, session identifiers, or PII in production.

Happy Hacking !!
