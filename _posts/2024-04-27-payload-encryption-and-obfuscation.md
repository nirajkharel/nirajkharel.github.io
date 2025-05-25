---
title: Offensive C & Nim - Shellcode Obfuscation
author: nirajkharel
date: 2025-05-26 14:10:00 +0800
categories: [Red Teaming, Offensive Programming]
tags: [Red Teaming, Offensive Programming]
render_with_liquid: false
---


## Shellcode
We have already discussed about [process injection using shellcode](https://nirajkharel.com.np/posts/process-injection-shellcode/) which pretty much explains about the shellcode, why and how to use it.

Giving the background again, shellcode is just a collection of instructions within the windows system which executes the command inorder to take a control or generates the reverse shell connection to an attacker machine. Below is a simple example of generating windows reverse tcp payload/shellcode which is obviously detected easily by Windows Defender.

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-1.png">

## Shellcode Obfuscation
There are usually two types of techniques to bypass Defender detection which are Encryption and Obfuscation. In this module, we will be focusing on different types of Shellcode Obsufcation.

Obfuscation is just a technique to transfer or modify the raw shellcode into different forms which are harder to detect or analyze. There are various types of Obfuscation techniques such as IPv4/IPv6, MAC and UUID Obfuscations.

### IPv4/IPv6 Obfuscation 
IPv4/IPv6 Obfuscation generally consists of a technique which converts the raw shellcode into IPv4 or IPV6 style syntax. 

IPv4Fuscation converts each byte of the shellcode to their corresnponding octets. Since IPv4 address contains 4 octets `192.168.1.0`, IPv4 obfuscation converts each byte of the shellcode into each octet of the IPv4 by converting the bytes in hex into the decimal.

Example: For this chunk of the raw payload `"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"`, IPv4 slipts it into 4-byte chucnks to form IPv4 addresses. It first divides them into 4-byte groups as shown below:

```
\xfc \x48 \x83 \xe4
\xe8 \xcc \x00 \x00
\x00 \x41 \x51 \x41
\x50 \x00 \x00 \x00
```
And then convers each byte into the decimal format, which results in:

```
[252, 72, 131, 228]
[232, 204, 0, 0]
[0, 65, 81, 65]
[80, 0, 0, 0]
```

And then finally it is organised into IPv4 addresses:
```
252.72.131.228
240.232.204.0
0.0.65.81
65.80.0.0
```

This is how you can get your shellcode/payload obfuscated into IPv4 formats.

You can refer to this [blog from Kylerosario](https://www.kylerosario.com/blog/IPObfuscation) to understand in detail on how and what are the functions that are being called during the obfuscation and deobfuscation. But we can use a pre-built tools like [HellShell](https://github.com/NUL0x4C/HellShell) and [Supernova](https://github.com/nickvourd/Supernova) to do this.

Below is an example which shows how we can use a tool like Supernova to obfuscate the payload.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-2.png">

Similar technique can be used on IPv6Fuscation where the shellcodes are grouped into 16 bytes to generated one IPv6 address. Again for the detailed explanation, you can navigate to Kylerosario blog. Since IPv6 addresses are expressed in hexadecimal, converting it into decimal is not needed.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-3.png">

### MACFuscation
MACFuscation consists of the techqniue of converting raw shellcode into MAC addresses `aa:bb:cc:dd:ee:ff`. Each `aa, bb` represents one byte in hexadecimal. Since a typical MAC address contains 6 bytes, therefore the shellcode is grouped into 6 bytes and then converted into the MAC addresses. If its not the multiple of 6 bytes, padding is used on it.

We can use the same tool to convert our shellcode into MAC address.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-4.png">

### UUIDFuscation
UUIDFuscation is a technique to obfuscate raw shellcode into UUID format `550e8400-e29b-41d4-a716-446655440000`. The raw shellcode is grouped into 16 bytes chunks as each UUID represents 16 bytes. When the shellcode is not muliple of 16, padding can bse used.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-5.png">

Since now we have explored at least 3 types of obfuscation techniques, lets move towards a practical demonstrations. But before that one important thing to understand and required is that we need to deobfuscate the payload as well. The **deobfuscation** is usually done before allocating the shellcode into virtual memory. We will explore one of the technique of **deobfuscation** on the demonstration itself.

## Sliver Shellcode Generation

## Obfuscation using Nim

#### References