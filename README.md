# Project Scorpio

A Windows process injection loader combining PPID spoofing, manual DLL mapping, module stomping, and direct NT syscall usage to execute staged shellcode in a remote process.

---

## Architecture Overview

```
FetchPayload()         — Pull shellcode from C2 over HTTP
SpawnSpoofed()         — Spawn decoy process with spoofed PPID
ManualMapDLL()         — Map a System32 DLL into decoy manually
StompTextSection()     — Overwrite .text section with shellcode
ExecuteInRemote()      — Kick off execution via NtCreateThreadEx
```

---

## Configuration (`#define`)

| Macro | Purpose |
|---|---|
| `C2_HOST` | WinHTTP target hostname for shellcode staging |
| `C2_PORT` | Port (default 8080) |
| `C2_PATH` | URI path to the raw shellcode blob |
| `DECOY_PROC` | Process binary to spawn as the injection host |
| `STOMP_DLL` | DLL from `System32` to manually map and stomp |

---

## Functions

### `ResolveNtFunctions()`

Dynamically resolves four NT functions from `ntdll.dll` at runtime using `GetProcAddress`:

- `NtCreateThreadEx` — create remote threads
- `NtWriteVirtualMemory` — write to remote process memory
- `NtProtectVirtualMemory` — change memory protection
- `NtAllocateVirtualMemory` — allocate memory in remote process

**Why:** Avoids static IAT entries for these functions, reducing signature surface for static scanners. Does **not** bypass userland hooks on its own for that you'd need direct syscalls or NTDLL unhooking.

---

### `GetTargetPID(procName)`

Walks the process snapshot via `CreateToolhelp32Snapshot` + `Process32NextW` and returns the PID of the first match for `procName`.

Used internally by `SpawnSpoofed` to locate `explorer.exe` as the fake parent.

---

### `SpawnSpoofed(targetProc)`

Spawns `targetProc` (e.g. `notepad.exe`) with `explorer.exe` as its spoofed parent process using `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.

Key flags:
- `CREATE_SUSPENDED` — process starts paused so injection can complete before any code runs
- `EXTENDED_STARTUPINFO_PRESENT` — required to pass the attribute list
- `SW_HIDE` — suppresses the window

**Effect:** Process tree in tools like Process Hacker / Task Manager shows `explorer.exe → notepad.exe` instead of the real loader as parent.

---

### `FetchPayload(outLen)`

Fetches raw shellcode bytes from the C2 over HTTP using WinHTTP.

Details:
- Randomized jitter sleep (2–6 seconds) before the request basic sandbox evasion against short-timeout dynamic analysis
- Spoofed `User-Agent` mimicking Chrome on Windows 10
- Adds plausible browser headers (`Accept`, `Accept-Language`, `Cache-Control`)
- Reads response in 4096-byte chunks into a heap buffer
- Returns pointer to shellcode buffer and its length via `outLen`

**No TLS by default** the `WinHttpOpenRequest` call uses no `WINHTTP_FLAG_SECURE`. For operational use, switch `C2_PORT` to 443 and add that flag.

---

### `ManualMapDLL(hProc, dllPath)`

Manually maps a DLL from disk into the target process without calling `LoadLibrary`. This means:
- No `LdrLoadDll` call → no loader lock, no `LDR_DATA_TABLE_ENTRY` in the PEB
- The DLL does **not** appear in `EnumProcessModules` or `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`

Steps:
1. Read the DLL file from disk into a local heap buffer
2. Parse the PE headers (`IMAGE_DOS_HEADER` → `IMAGE_NT_HEADERS`)
3. Allocate `SizeOfImage` bytes in the remote process as `PAGE_READWRITE`
4. Write PE headers into remote allocation
5. Iterate section headers and write each section to its correct `VirtualAddress`

**Note:** Relocations and imports are **not** processed in this implementation. The mapped image is essentially a raw PE in memory sufficient for stomping purposes since the shellcode replaces the `.text` section content entirely.

---

### `StompTextSection(hProc, remoteBase, shellcode, scLen)`

Locates and overwrites the `.text` section of the manually mapped DLL with the fetched shellcode.

Steps:
1. Read DOS and NT headers back from remote process memory
2. Walk section headers looking for a section named `.text`
3. Change protection on that region to `PAGE_READWRITE` via `NtProtectVirtualMemory`
4. Write shellcode bytes over `.text` via `NtWriteVirtualMemory`
5. Restore protection to `PAGE_EXECUTE_READ`

**Evasion rationale:** The shellcode now lives inside a memory region that looks like a legitimate DLL's `.text` section backed by a file on disk. This defeats detections that flag unbacked `EXECUTE` regions (private RWX pages). The page appears as a mapped image section rather than anonymous memory.

**Caveat:** If the shellcode is larger than the `.text` section of the chosen DLL, this will overflow into adjacent sections. Pick a DLL with a `.text` section larger than your shellcode, or add a size check.

---

### `ExecuteInRemote(hProc, startAddr)`

Creates a remote thread starting at `startAddr` (the stomped `.text` base) using `NtCreateThreadEx` directly.

The `FALSE` flag for the suspended parameter means the thread starts running immediately. The `THREAD_ALL_ACCESS` access mask is broad for opsec you'd narrow this.

---

### `main()`

Orchestration flow:

```
1. ResolveNtFunctions()
2. FetchPayload()          → shellcode buffer
3. SpawnSpoofed()          → suspended decoy process (PPID spoofed)
4. ManualMapDLL()          → DLL mapped into decoy (no loader)
5. StompTextSection()      → shellcode written into .text
6. ResumeThread()          → decoy process main thread resumes
7. ExecuteInRemote()       → shellcode thread created in decoy
8. SecureZeroMemory()      → clear shellcode from loader's heap
```

`SecureZeroMemory` on the shellcode buffer before `free()` prevents the payload from being recovered via a heap dump of the loader process after execution.

---

## Detection Considerations

| Technique | What It Defeats | What It Doesn't Defeat |
|---|---|---|
| PPID spoofing | Naive parent-process lineage checks | ETW `ProcessCreate` events; kernel callbacks still see real parent |
| Manual map (no LoadLibrary) | Module enumeration via PEB/TH32CS_SNAPMODULE | Scanners walking VAD tree; memory scanning |
| Module stomping (.text overwrite) | Unbacked private RWX page detections | File-backed region content scanning; hash mismatch on .text |
| Dynamic NT resolution | Static IAT analysis | Userland hooks on NtWriteVirtualMemory etc. are still hit |
| Jitter + spoofed UA | Trivial sandbox timeout evasion | Network-level C2 pattern detection |

---

## Build

```bash
cl scorpio.cpp /Fe:scorpio.exe /link winhttp.lib psapi.lib
```
or you can use Visual Studio to build it

Tested on Windows 10/11 x64. Requires the target DLL to exist under `C:\Windows\System32\`.
