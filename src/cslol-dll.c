#define WIN32_LEAN_AND_MEAN
#include <windows.h>
// do not reorder
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// do not reorder
#define CSLOL_IMPL
#include "cslol-api.h"

#define MAX_PATH_WIDE 1024
#define PAGE_SIZE 0x1000
#define LOL_WINDOW "League of Legends (TM) Client"
#define LOL_EXE "League of Legends.exe"
#define LOG_ENTRY_COUNT 16
#define LOG_ENTRY_SIZE 512
#define PIPE_NAME L"\\\\.\\pipe\\cslol-patcher-pipe"
#define EOL_TIMESTAMP 1767164400  // December 31st 2025
// #define LOL_WINDOW "VALORANT  "
// #define LOL_EXE "VALORANT-Win64-Shipping.exe"

#define log_error(msg, ...) write_log(CSLOL_LOG_ERROR, "error: " msg, ##__VA_ARGS__)
#define log_info(msg, ...) write_log(CSLOL_LOG_INFO, "info: " msg, ##__VA_ARGS__)
#define log_debug(msg, ...) write_log(CSLOL_LOG_DEBUG, "debug: " msg, ##__VA_ARGS__)
#define log_trace(msg, ...) write_log(CSLOL_LOG_TRACE, "trace: " msg, ##__VA_ARGS__)

#define error_if(condition, msg, ...)             \
    if ((condition)) {                            \
        log_error(#condition msg, ##__VA_ARGS__); \
        return 0;                                 \
    }

typedef struct cslol_config_s {
    cslol_hook_flags flags;
    cslol_log_level log_level;
    WCHAR prefix[MAX_PATH_WIDE];
    WCHAR log_file[MAX_PATH_WIDE];
} cslol_config_t;

typedef struct cslol_msg_s {
    cslol_config_t config;
    ULONG64 checksum;
} cslol_msg_t;

static cslol_config_t g_config = {0, 0, {0}};

static void write_log(int level, char const* fmt, ...);

typedef HANDLE(WINAPI* CreateFileA_fnptr)(LPCSTR lpFileName,
                                          DWORD dwDesiredAccess,
                                          DWORD dwShareMode,
                                          LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                          DWORD dwCreationDisposition,
                                          DWORD dwFlagsAndAttributes,
                                          HANDLE hTemplateFile);

static CreateFileA_fnptr CreateFileA_original = NULL;

static HANDLE WINAPI CreateFileA_hook(LPCSTR lpFileName,
                                      DWORD dwDesiredAccess,
                                      DWORD dwShareMode,
                                      LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                      DWORD dwCreationDisposition,
                                      DWORD dwFlagsAndAttributes,
                                      HANDLE hTemplateFile) {

    // Only care about reading existing normal files.
    if (lpFileName == NULL) goto call_original;

    log_debug("open: %s", lpFileName);

    if (dwDesiredAccess != GENERIC_READ) goto call_original;
    if (dwShareMode != FILE_SHARE_READ) goto call_original;
    if (lpSecurityAttributes != NULL) goto call_original;
    if (dwCreationDisposition != OPEN_EXISTING) goto call_original;
    if (dwFlagsAndAttributes != FILE_ATTRIBUTE_NORMAL) goto call_original;

    // Only care about .wad files in "DATA/".
    if (_strnicmp(lpFileName, "DATA/", 5) != 0) goto call_original;
    if (!strstr(lpFileName, ".wad")) goto call_original;

    // TODO: Maybe some sort of logging would be good here?

    WCHAR buffer[MAX_PATH_WIDE];
    LPWSTR dst = buffer;
    LPWSTR end = buffer + MAX_PATH_WIDE;

    // Copy prefix
    for (LPWSTR src = g_config.prefix; dst != end && *src; ++dst, ++src) *dst = *src;
    if (dst == end) goto call_original;

    // Copy filename
    for (LPCSTR src = lpFileName; dst != end && *src; ++dst, ++src) *dst = *src == '/' ? L'\\' : *src;
    if (dst == end) goto call_original;

    // Add null terminator
    *dst = 0;

    // Call wide version of CreateFile because user might have prefix in non-ascii path.
    HANDLE result = CreateFileW(buffer,
                                dwDesiredAccess,
                                dwShareMode,
                                lpSecurityAttributes,
                                dwCreationDisposition,
                                dwFlagsAndAttributes,
                                hTemplateFile);

    // If failed call original.
    if (result == INVALID_HANDLE_VALUE) goto call_original;
    log_info("redirected wad: %s", lpFileName);

    // All done...
    return result;

// Just call original function with same args.
call_original:
    return CreateFileA_original(lpFileName,
                                dwDesiredAccess,
                                dwShareMode,
                                lpSecurityAttributes,
                                dwCreationDisposition,
                                dwFlagsAndAttributes,
                                hTemplateFile);
}

static LPVOID get_proc_address(LPVOID module, const char* func_name) {
    char* base = (char*)module;

    IMAGE_DOS_HEADER dos_header = {0};
    ReadProcessMemory((HANDLE)-1, base, &dos_header, sizeof(dos_header), NULL);

    IMAGE_NT_HEADERS64 nt_headers = {0};
    ReadProcessMemory((HANDLE)-1, base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers), NULL);

    IMAGE_EXPORT_DIRECTORY export_dir = {0};
    ReadProcessMemory((HANDLE)-1,
                      base + nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
                      &export_dir,
                      sizeof(export_dir),
                      NULL);

    const DWORD* names_rvas = (const DWORD*)(base + export_dir.AddressOfNames);
    const DWORD* func_rvas = (const DWORD*)(base + export_dir.AddressOfFunctions);
    const USHORT* ordinals = (const USHORT*)(base + export_dir.AddressOfNameOrdinals);
    for (DWORD i = 0; i != export_dir.NumberOfNames; ++i) {
        const DWORD name_rva = names_rvas[i];
        if (0 == name_rva || 0 != strcmp(func_name, base + name_rva)) continue;
        const USHORT ord = ordinals[i];
        if (ord < export_dir.Base || ord >= export_dir.NumberOfFunctions) continue;
        const DWORD func_rva = func_rvas[ord];
        if (func_rva == 0) continue;
        return base + func_rva;
    }
    return NULL;
}

static int patch_CreateFileA() {
    HMODULE module = GetModuleHandleW(L"Kernel32.dll");
    error_if(!module, "Failed to find CreateFileA module");

    char path[MAX_PATH_WIDE] = {0};
    GetModuleFileNameA(module, path, sizeof(path));
    log_info("Kernel32 module %p: %s", module, path);

    LPVOID target = (LPVOID)get_proc_address(module, "CreateFileA");
    error_if(!target, "Failed to find CreateFileA funtion");
    log_info("CreateFileA thunk: %p", target);

    __declspec(align(16)) BYTE data[16] = {0};
    BOOL res = ReadProcessMemory((HANDLE)(LONG_PTR)-1, target, data, sizeof(data), NULL);
    error_if(!res, "Failed to read CreateFileA bytes: ", GetLastError());
    log_info("CreateFileA bytes: %016llx%016llx", ((unsigned long long*)data)[1], ((unsigned long long*)data)[0]);

    PVOID* import_ptr;
    if (data[0] == 0xFF && data[1] == 0x25) {
        import_ptr = (PVOID*)(((PBYTE)target + 6) + *(LONG32 __unaligned*)(&data[2]));
    } else if (data[1] == 0xFF && data[2] == 0x25) {
        import_ptr = (PVOID*)(((PBYTE)target + 7) + *(LONG32 __unaligned*)(&data[3]));
    } else {
        error_if(FALSE, "CreateFileA is not a thunk (old windows version?)");
    }

    PVOID original = NULL;
    res = ReadProcessMemory((HANDLE)(LONG_PTR)-1, import_ptr, &original, sizeof(original), NULL);
    error_if(!res, "Failed to read import ptr: %x", GetLastError());
    log_info("CreateFileA original: [%p] -> %p", import_ptr, original);
    CreateFileA_original = (CreateFileA_fnptr)original;

    // Create hook directly in import thunk.
    data[0] = 0x90;
    data[1] = 0x48;
    data[2] = 0xB8;
    *(ULONG_PTR __unaligned*)(data + 3) = (ULONG_PTR)(PVOID)&CreateFileA_hook;
    data[11] = 0xFF;
    data[12] = 0xE0;

    // Protect RWX and then write in place.
    DWORD old = {};
    res = VirtualProtect(target, sizeof(data), PAGE_EXECUTE_READWRITE, &old);
    error_if(!res, "Failed to rwx protect CreateFileA bytes: ", GetLastError());
    res = WriteProcessMemory((HANDLE)(LONG_PTR)-1, target, data, sizeof(data), NULL);
    error_if(!res, "Failed to write CreateFileA bytes: ", GetLastError());
    VirtualProtect(target, sizeof(data), old, &old);

    return 1;
}

// Set int_rsa_verify return value to true.
__attribute__((naked)) static void CRYPTO_free_hook_tail(LPVOID ptr) { __asm__("or $1, %rbx\n\tretn\n\t"); }

// (Ab)use CRYPTO_free to swap out return value of int_rsa_verify function.
// We do this because pacman integrity checks code pages.
void CRYPTO_free_hook(LPVOID ptr) {
    // Get return address so we can filter only necessary callsite.
    LPVOID ret = __builtin_return_address(0);

    // Nothing to do here.
    if (ptr == NULL) return;

    // Free pointer.
    HeapFree(GetProcessHeap(), 0, ptr);

    // Try to read instructions at address, use RPM to avoid throwing exceptions.
    SIZE_T ret_insn = 0;
    BOOL result = ReadProcessMemory((HANDLE)-1, (LPCVOID)ret, &ret_insn, sizeof(ret_insn), NULL);

    // Check for return instructions:
    // 48 8b 7c 24 70          mov    rdi, QWORD PTR [rsp+0x70]
    // 8b c3                   mov    eax, ebx
    // 48                      rex.W
    if (result != 0 && ret_insn == 0x48C38B70247C8B48) {
        // Call a naked function with musttail instead of asm to avoid fucking with call frames.
        // Musttail will force compiler to generate jmp instead of retn.
        __attribute__((musttail)) return CRYPTO_free_hook_tail(NULL);
    }
}

// Scan image on disk for pattern.
static UINT_PTR find_in_image(LPVOID module, BYTE* what, SIZE_T size, SIZE_T step) {
    // Get main module path.
    WCHAR path[MAX_PATH_WIDE];
    DWORD path_size = GetModuleFileNameW(module, path, sizeof(path));
    error_if(path_size >= MAX_PATH_WIDE, "Failed to get module path because %x", GetLastError());

    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    error_if(!file || file == INVALID_HANDLE_VALUE, "Failed to open module file because %x", GetLastError());

    // Buffer up to 2 pages.
    BYTE buffer[PAGE_SIZE * 2] = {0};

    // Read first page and extract section information.
    IMAGE_DOS_HEADER dos_header = {0};
    IMAGE_NT_HEADERS64 nt_headers = {0};
    IMAGE_SECTION_HEADER sections[64] = {0};
    if (ReadFile(file, buffer, PAGE_SIZE, NULL, NULL)) {
        memcpy(&dos_header, buffer, sizeof(dos_header));
        memcpy(&nt_headers, buffer + dos_header.e_lfanew, sizeof(nt_headers));
        memcpy(&sections,
               buffer + dos_header.e_lfanew + 0x18 + nt_headers.FileHeader.SizeOfOptionalHeader,
               sizeof(sections[0]) * nt_headers.FileHeader.NumberOfSections);
    }

    SIZE_T page = 0;
    SIZE_T raw = -1;
    SIZE_T i = 0;
    while (ReadFile(file, buffer + PAGE_SIZE, PAGE_SIZE, NULL, NULL)) {
        for (i = 0; i + size <= PAGE_SIZE * 2; i += step) {
            if (memcmp(what, buffer + i, size) == 0) {
                raw = page + i;
                goto done;
            }
        }
        memcpy(buffer, buffer + PAGE_SIZE, PAGE_SIZE);
        page += PAGE_SIZE;
    }

// If we found raw offset, walk sections to transform it into virtual address + base of module.
done:
    CloseHandle(file);
    for (i = 0; raw != -1 && i != nt_headers.FileHeader.NumberOfSections; i += 1) {
        if (raw < sections[i].PointerToRawData) continue;
        if (raw - sections[i].PointerToRawData > sections[i].SizeOfRawData) continue;
        return (raw - sections[i].PointerToRawData) + sections[i].VirtualAddress;
    }
    return 0;
}

// Scan for:
// 80 00 00 00
// 01 00 00 00
// FF FF FF FF
// 01 00 00 00
// ?? ?? ?? ?? ?? ?? 00 00
// ?? ?? ?? ?? ?? ?? 00 00
// ?? ?? ?? ?? ?? ?? 00 00 <= pointer to CRYPTO_free
static int patch_CRYPTO_free() {
    BYTE pattern[16] = {0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00};

    LPVOID module = GetModuleHandleW(NULL);
    error_if(!module || module == INVALID_HANDLE_VALUE, "Failed to get main module!");

    UINT_PTR offset = find_in_image(module, pattern, sizeof(pattern), 8);
    error_if(!offset, "Failed to find CRYPTO_free ptr.");

    log_info("patching module: %p CRYPTO_free offset: %p", module, offset);

    void* dst = (LPVOID)(offset + 32 + (char*)module);
    void* hook_ptr = &CRYPTO_free_hook;
    BOOL result = WriteProcessMemory((HANDLE)-1, dst, &hook_ptr, sizeof(hook_ptr), NULL);
    error_if(result == 0, "Failed to write crypto free ptr: %x", GetLastError());

    return 1;
}

// Get build timestamp.
static DWORD get_module_timestamp() {
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return 0;

    __try {
        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)(char*)base;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 1;

        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((char*)base + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 2;

        return ntHeaders->FileHeader.TimeDateStamp;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 4;
    }
}

static BOOL g_is_in_process = {0};

static HINSTANCE g_instance = NULL;

static HANDLE g_log = NULL;

static int cslol_init_in_process() {
    g_is_in_process = 1;

    // Fetch config from named pipe.
    {
        HANDLE pipe = CreateFileW(PIPE_NAME, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (!pipe) {
            DWORD error = GetLastError();
            log_error("Failed to open pipe because: %08x!", error);
            return 0;
        }

        cslol_msg_t msg = {0};
        DWORD readed = 0;
        if (!ReadFile(pipe, &msg, sizeof(msg), &readed, NULL)) {
            DWORD error = GetLastError();
            log_error("Failed to read pipe because: %08x!", error);
            CloseHandle(pipe);
            return 0;
        }

        msg.config.prefix[(sizeof(msg.config.prefix) / sizeof(msg.config.prefix[0])) - 1] = 0;
        msg.config.log_file[(sizeof(msg.config.log_file) / sizeof(msg.config.log_file[0])) - 1] = 0;
        g_config = msg.config;

        CloseHandle(pipe);
    }

    // Open log
    {
        HANDLE log = CreateFileW(g_config.log_file,
                                 FILE_APPEND_DATA,
                                 FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ,
                                 NULL,
                                 OPEN_ALWAYS,
                                 FILE_FLAG_WRITE_THROUGH,
                                 NULL);
        if (!log || log == INVALID_HANDLE_VALUE) {
            log_error("Failed to open log file because: %d, log: '%ls'", GetLastError(), g_config.log_file);
            return 0;
        }
        g_log = log;
    }

    log_info("Init in process!");

    DWORD timestamp = get_module_timestamp();
    error_if(timestamp <= 0x5E2D1F00, "Failed to get valid timestamp: %08X", timestamp);
    error_if(timestamp > EOL_TIMESTAMP, "End of life reached, please update: %08X", timestamp);

    // Pach int_rsa_verify via CRYPTO_free before patching CreateFileA.
    if (!(g_config.flags & CSLOL_HOOK_DISABLE_VERIFY)) {
        error_if(!patch_CRYPTO_free(), "Failed to patch crypto free!");
    }

    // Patch CreateFileA for filesystem overlay effect.
    if (!(g_config.flags & CSLOL_HOOK_DISABLE_FILE)) {
        error_if(!patch_CreateFileA(), "Failed to patch CreateFileA!");
    }

    log_info("Init done!");
    return 1;
}

static const char* open_log_for_tail(PCWSTR path) {
    if (g_log && wcscmp(g_config.log_file, path) == 0) return NULL;

    if (g_log) {
        CloseHandle(g_log);
        g_log = NULL;
    }
    g_config.log_file[0] = 0;

    g_log = CreateFileW(path,
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL,
                        OPEN_ALWAYS,
                        0,
                        NULL);
    if (g_log == INVALID_HANDLE_VALUE) g_log = NULL;

    if (!g_log) return "Failed to open log file.";
    SetFilePointer(g_log, 0, NULL, FILE_END);
    wcscpy_s(g_config.log_file, MAX_PATH_WIDE, path);

    return NULL;
}

CSLOL_API intptr_t cslol_msg_hookproc(int code, uintptr_t wParam, intptr_t lParam) {
    __asm__ __volatile__("nop" : : "g"((char*)(lParam)) : "memory");
    return CallNextHookEx(NULL, code, wParam, lParam);
}

CSLOL_API const char* cslol_init() { return NULL; }

CSLOL_API const char* cslol_set_config(const char16_t* prefix) {
    WCHAR full[MAX_PATH_WIDE];
    // Get full path.
    DWORD length = GetFullPathNameW(prefix, MAX_PATH_WIDE, full, NULL);
    if (length == 0 || length >= MAX_PATH_WIDE) return "Failed to get full path.";

    WCHAR buffer[MAX_PATH_WIDE];
    int ret = swprintf_s(buffer,
                         MAX_PATH_WIDE,
                         L"%s%s%s",
                         // Prepend \\\\?\\ if not there already.
                         wcsstr(full, L"\\\\") != 0 ? L"\\\\?\\" : L"",
                         // path itself
                         full,
                         // directory at end
                         full[length - 1] != L'\\' && full[length - 1] != '/' ? L"\\" : L"");
    if (ret < 0) return "Prefix path too big!";
    for (size_t i = 0; i != MAX_PATH_WIDE; ++i)
        if (buffer[i] == L'/') buffer[i] = L'\\';

    memcpy((void*)g_config.prefix, buffer, MAX_PATH_WIDE);

    DWORD attrib = GetFileAttributesW((LPCWSTR)g_config.prefix);
    if (attrib == INVALID_FILE_ATTRIBUTES || !(attrib & FILE_ATTRIBUTE_DIRECTORY)) return "Prefix path does not exist";

    return NULL;
}

CSLOL_API const char* cslol_set_flags(cslol_hook_flags flags) {
    g_config.flags = flags;
    return NULL;
}

CSLOL_API const char* cslol_set_log_level(cslol_log_level level) {
    g_config.log_level = level;
    return NULL;
}

CSLOL_API unsigned cslol_find() {
    HWND hwnd = FindWindowExA(NULL, NULL, NULL, LOL_WINDOW);
    if (!hwnd) return 0;
    return GetWindowThreadProcessId(hwnd, NULL);
}

CSLOL_API const char* cslol_hook(unsigned tid, unsigned timeout, unsigned step) {
    // Open log.
    {
        WCHAR log[MAX_PATH_WIDE + 16];
        swprintf_s(log, MAX_PATH_WIDE + 16, L"%slog.txt", g_config.prefix);
        const char* error = open_log_for_tail(log);
        if (error) return error;
    }

    // Setup the pipe.
    HANDLE pipe = CreateNamedPipeW(PIPE_NAME,
                                   PIPE_ACCESS_OUTBOUND,
                                   PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                   1,
                                   4096,
                                   4096,
                                   0,
                                   NULL);

    // Inject ourselves with classic SetWindowsHookExA
    // NOTE: this will only work with signed dll when vanguard is turned on
    //       that's why for releases we need to sign our dlls with valid certificate
    HHOOK hook = SetWindowsHookExA(WH_GETMESSAGE, &cslol_msg_hookproc, g_instance, tid);
    const char* error = NULL;
    if (!hook) {
        error = "Failed to create hook!";
        goto done;
    }

    BOOL connected = ConnectNamedPipe(pipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected) {
        error = "Failed to connect to named pipe!";
        goto done;
    }

    cslol_msg_t msg = {0};
    msg.config = g_config;
    msg.checksum = 0x67736d6c6f6c7363ull;

    DWORD written;
    if (!WriteFile(pipe, &msg, sizeof(msg), &written, NULL)) {
        error = "Failed to write config to pipe!";
        goto done;
    }

    if (!FlushFileBuffers(pipe)) {
        error = "Failed to flush pipe!";
        goto done;
    }

done:
    if (pipe && pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    if (hook) UnhookWindowsHookEx(hook);
    return error;
}

CSLOL_API char const* cslol_log_pull() {
    static char buffer[LOG_ENTRY_SIZE + 1] = {0};
    static int nxt = 0;
    static int end = 0;

    // shift already consumed data
    if (nxt > 0) {
        memmove(buffer, buffer + nxt, end - nxt);
        end -= nxt;
        nxt = 0;
    }

    // re-fill if possible
    if (end < LOG_ENTRY_SIZE) {
        DWORD readed = 0;
        if (!ReadFile(g_log, buffer + end, LOG_ENTRY_SIZE - end, &readed, NULL)) readed = 0;
        end += readed;
        buffer[end] = 0;
    }

    // we have some data
    if (end > 0) {
        int endline = 0;
        while (endline < end && buffer[endline] != '\n') endline += 1;
        buffer[endline] = 0;
        nxt = endline + (endline < end ? 1 : 0);
        return buffer;
    }

    return NULL;
}

static void write_log(cslol_log_level level, char const* fmt, ...) {
    if (level > g_config.log_level || (!g_log && level > CSLOL_LOG_ERROR)) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    char buffer[LOG_ENTRY_SIZE];
    const int ret = _vsnprintf(buffer, LOG_ENTRY_SIZE - 2, fmt, args);
    va_end(args);
    if (ret < 0 || ret >= LOG_ENTRY_SIZE - 2) {
        return;
    }
    buffer[ret] = '\n';
    buffer[ret + 1] = '\0';

    if (g_log) {
        WriteFile(g_log, buffer, ret + 1, NULL, NULL);
    } else {
        MessageBoxA(NULL, buffer, "cslol-patcher error", MB_OK | MB_ICONERROR);
    }
}

static volatile ULONG64 loaded = 0;
extern IMAGE_DOS_HEADER __ImageBase;
extern long LdrAddRefDll(ULONG Flags, PVOID BaseAddress);

VOID tls_callback(PVOID inst, DWORD reason, PVOID reserved) {
    if (loaded++ == 0) {
        // Pin ourselves ASAP, so we don't get unloaded if windows hook drops.
        LdrAddRefDll(GET_MODULE_HANDLE_EX_FLAG_PIN, (PVOID)&__ImageBase);

        g_instance = inst;
        if (GetModuleHandleA(LOL_EXE) == GetModuleHandleA(NULL)) {
            // Pin ourselfs so we persist even after a hook.
            cslol_init_in_process();
        }
    }
}

static char _tls_vars[2] = {0};
static ULONG _tls_index = 0;
static const PIMAGE_TLS_CALLBACK _tls_callbacks[2] = {&tls_callback, NULL};

__attribute__((used)) const IMAGE_TLS_DIRECTORY64 _tls_used = {
    (ULONGLONG)&_tls_vars[0],
    (ULONGLONG)&_tls_vars[1],
    (ULONGLONG)&_tls_index,
    (ULONGLONG)&_tls_callbacks[0],
    (ULONG)0,
    (ULONG)0,
};
