#define WIN32_LEAN_AND_MEAN
#include <windows.h>
// do not reorder
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// do not reorder
#include <MinHook.h>
// do not reorder
#define CSLOL_IMPL
#include "cslol-api.h"

#define MAX_PATH_WIDE 1024
#define PAGE_SIZE 0x1000
#define LOL_WINDOW "League of Legends (TM) Client"
#define LOL_EXE "League of Legends.exe"
#define LOG_ENTRY_COUNT 16
#define LOG_ENTRY_SIZE 0x1000
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
} cslol_config_t;

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
    MH_STATUS s = MH_Initialize();
    error_if(s, "Failed to init CreateFileA hook: %s", MH_StatusToString(s));

    HMODULE module = GetModuleHandleW(L"Kernel32.dll");
    error_if(!module, "Failed to find CreateFileA module");

    char path[MAX_PATH_WIDE] = {0};
    GetModuleFileNameA(module, path, sizeof(path));
    log_info("Kernel32 module %p: %s", module, path);

    LPVOID target = (LPVOID)get_proc_address(module, "CreateFileA");
    error_if(!target, "Failed to find CreateFileA funtion");

    log_info("Hoking CreateFileA: %p", target);

    s = MH_CreateHook(target, &CreateFileA_hook, (LPVOID*)&CreateFileA_original);
    error_if(s, "Failed to create CreateFileA hook: %s", MH_StatusToString(s));

    s = MH_EnableHook(target);
    error_if(s, "Failed to enable CreateFileA hook: %s", MH_StatusToString(s));

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
    free(ptr);

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
        memcpy_s(&dos_header, sizeof(dos_header), buffer, sizeof(dos_header));
        memcpy_s(&nt_headers, sizeof(nt_headers), buffer + dos_header.e_lfanew, sizeof(nt_headers));
        memcpy_s(&sections,
                 sizeof(sections),
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
        memcpy_s(buffer, PAGE_SIZE, buffer + PAGE_SIZE, PAGE_SIZE);
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

__asm__(".section .shared,\"ds\"\n");

static volatile int s_inited __attribute__((section(".shared"))) = {0};

static volatile cslol_config_t s_config __attribute__((section(".shared"))) = {0, 0, {0}};

static size_t s_log_end __attribute__((section(".shared"))) = {0};

static size_t s_log_start __attribute__((section(".shared"))) = {0};

static char s_log_buffer[LOG_ENTRY_COUNT][LOG_ENTRY_SIZE] __attribute__((section(".shared"))) = {0};

static BOOL g_is_in_process = {0};

static HINSTANCE g_instance = NULL;

static int cslol_init_in_process() {
    s_inited++;
    s_log_end = 0;
    s_log_start = 0;
    g_is_in_process = 1;

    // Copy in config.
    memcpy_s(&g_config, sizeof(g_config), (const void*)&s_config, sizeof(s_config));

    log_info("Init in process!");

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

CSLOL_API intptr_t cslol_msg_hookproc(int code, uintptr_t wParam, intptr_t lParam) {
    PMSG msg = (PMSG)lParam;
    if (msg && msg->wParam == 0x306c6f6c7363 && msg->message == 0x511) {
        UnhookWindowsHookEx((HHOOK)msg->lParam);
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

CSLOL_API const char* cslol_init() {
    return NULL;
}

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

    memcpy_s((void*)s_config.prefix, MAX_PATH_WIDE, buffer, MAX_PATH_WIDE);

    DWORD attrib = GetFileAttributesW((LPCWSTR)s_config.prefix);
    if (attrib == INVALID_FILE_ATTRIBUTES || !(attrib & FILE_ATTRIBUTE_DIRECTORY)) return "Prefix path does not exist";

    return NULL;
}

CSLOL_API const char* cslol_set_flags(cslol_hook_flags flags) {
    s_config.flags = flags;
    return NULL;
}

CSLOL_API const char* cslol_set_log_level(cslol_log_level level) {
    s_config.log_level = level;
    return NULL;
}

CSLOL_API unsigned cslol_find() {
    HWND hwnd = FindWindowExA(NULL, NULL, NULL, LOL_WINDOW);
    if (!hwnd) return 0;
    return GetWindowThreadProcessId(hwnd, NULL);
}

CSLOL_API const char* cslol_hook(unsigned tid, unsigned timeout, unsigned step) {
    // Inject ourselves with classic SetWindowsHookExA
    // NOTE: this will only work with signed dll when vanguard is turned on
    //       that's why for releases we need to sign our dlls with valid certificate
    const int old_inited = s_inited;
    HHOOK hook = SetWindowsHookExA(WH_GETMESSAGE, &cslol_msg_hookproc, g_instance, tid);
    if (!hook) return "Failed to create hook!";

    for (long long t = timeout; t > 0; t -= step) {
        PostThreadMessageA(tid, 0x511u, 0x306c6f6c7363, (LPARAM)hook);
        Sleep(step);
        if (old_inited != s_inited) {
            UnhookWindowsHookEx(hook);
            return NULL;
        }
    }

    UnhookWindowsHookEx(hook);
    return "Timeout out while waiting for init!";
}

CSLOL_API char const* cslol_log_pull() {
    static char buffer[LOG_ENTRY_SIZE];
    if (s_log_start >= s_log_end) {
        return NULL;
    }
    size_t pos = s_log_start % LOG_ENTRY_COUNT;
    memcpy_s(buffer, LOG_ENTRY_SIZE, s_log_buffer[pos], LOG_ENTRY_SIZE);
    buffer[LOG_ENTRY_SIZE - 1] = 0;
    ++s_log_start;
    return buffer;
}

static void write_log(cslol_log_level level, char const* fmt, ...) {
    if (level > g_config.log_level) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    char buffer[LOG_ENTRY_SIZE];
    const int ret = vsnprintf(buffer, LOG_ENTRY_SIZE - 1, fmt, args);
    va_end(args);
    buffer[LOG_ENTRY_SIZE - 1] = 0;
    if (ret < 0) {
        return;
    }

    size_t pos = s_log_end % LOG_ENTRY_COUNT;
    memcpy_s(s_log_buffer[pos], LOG_ENTRY_SIZE, buffer, LOG_ENTRY_SIZE);
    ++s_log_end;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        g_instance = inst;
        if (GetModuleHandleA(LOL_EXE) == GetModuleHandleA(NULL)) {
            WCHAR path[MAX_PATH_WIDE];
            GetModuleFileNameW(g_instance, path, sizeof(path));
            LoadLibraryW(path);
            cslol_init_in_process();
        }
    }
    if (reason == DLL_PROCESS_DETACH && g_is_in_process) {
        log_info("Exit in process!");
    }
    return 1;
}
