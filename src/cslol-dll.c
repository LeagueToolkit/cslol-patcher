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
#define LOG_BUFFER 0x10000
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
    if (dwDesiredAccess != GENERIC_READ) goto call_original;
    if (dwShareMode != FILE_SHARE_READ) goto call_original;
    if (lpSecurityAttributes != NULL) goto call_original;
    if (dwCreationDisposition != OPEN_EXISTING) goto call_original;
    if (dwFlagsAndAttributes != FILE_ATTRIBUTE_NORMAL) goto call_original;

    // Only care about .wad files in "DATA/".
    if (memcmp(lpFileName, "DATA/", 5) != 0) goto call_original;
    if (!strstr(lpFileName, ".wad")) goto call_original;

    // TODO: Maybe some sort of logging would be good here?

    WCHAR buffer[MAX_PATH_WIDE];
    LPWSTR dst = buffer;

    // Copy prefix
    for (LPWSTR src = g_config.prefix; *src; ++dst, ++src) *dst = *src;

    // Copy filename
    for (LPCSTR src = lpFileName; *src; ++dst, ++src) *dst = *src == '/' ? L'\\' : *src;

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

static int patch_CreateFileA() {
#pragma pack(push, 1)
    typedef struct _ImportThunk {
        UINT16 jmp;
        INT32 rel32;
        BYTE pad[10];
    } ImportThunk;

    typedef struct _ImportTrampoline {
        BYTE mov_rax[2];
        UINT64 abs64;
        BYTE jmp_rax[2];
        BYTE pad[4];
    } ImportTrampoline;
#pragma pack(pop)

    LPVOID module = GetModuleHandleW(L"KERNEL32.DLL");
    error_if(!module || module == INVALID_HANDLE_VALUE, "Failed to get kernel32 module because %x", GetLastError());

    ImportThunk* thunk = (ImportThunk*)GetProcAddress(module, "CreateFileA");
    error_if(!thunk, "Failed to get CreateFileA import thunk because %x", GetLastError());

    log_info("patching thunk %p from module %p", thunk, module);

    error_if(thunk->jmp != 0x25FF, "CreateFileA import unexpected thunk: %x %x", thunk->jmp, thunk->rel32);

    CreateFileA_original = *(CreateFileA_fnptr*)(thunk->pad + thunk->rel32);

    ImportTrampoline tramp = {{0x48, 0xB8u}, (UINT64)&CreateFileA_hook, {0xFF, 0xE0}};
    BOOL result = WriteProcessMemory((HANDLE)-1, thunk, &tramp, sizeof(tramp), NULL);
    error_if(result == 0, "Failed to write import trampoline because: %x", GetLastError());

    return 1;
}

// Check if CRYPTO_free will return into int_rsa_verify.
extern SIZE_T CDECL CRYPTO_free_check(LPVOID ptr, LPVOID* ret);
SIZE_T CDECL CRYPTO_free_check(LPVOID ptr, LPVOID* ret) {
    // Nothing to do here.
    if (ptr == NULL) return 0;

    // Free pointer.
    free(ptr);

    // Try to read instructions at address.
    SIZE_T ret_insn = 0;
    BOOL result = ReadProcessMemory((HANDLE)-1, (LPCVOID)ret, &ret_insn, sizeof(ret_insn), NULL);

    // Check for return instructions:
    // 48 8b 7c 24 70          mov    rdi, QWORD PTR [rsp+0x70]
    // 8b c3                   mov    eax, ebx
    // 48                      rex.W
    return result != 0 && ret_insn == 0x48C38B70247C8B48;
}

// (Ab)use CRYPTO_free to swap out return value of int_rsa_verify function.
extern void CRYPTO_free_hook();
__asm__(
    ".intel_syntax\n"
    ".section .text\n"
    ".global CRYPTO_free_check\n"
    ".global CRYPTO_free_hook\n"
    "CRYPTO_free_hook:\n\t"
    // put return address in second argument
    "mov rdx, [rsp] \n\t"
    // adjust stack by 8 to align for call
    "sub rsp, 8 \n\t"
    // call hook func to check if we need to patch
    "call CRYPTO_free_check \n\t"
    // adjust stack back
    "add rsp, 8 \n\t"
    // if hook func returns 1, set rbx to 1, optimized to 1 instruction
    "or rbx, rax \n\t"
    // done
    "retn\n"
    //
);

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

static int s_log_end __attribute__((section(".shared"))) = {0};

static int s_log_start __attribute__((section(".shared"))) = {0};

static int g_log_end = {0};

static char s_log_buffer[LOG_BUFFER] __attribute__((section(".shared"))) = {0};

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
    return CallNextHookEx(NULL, code, wParam, lParam);
}

CSLOL_API const char* cslol_init() {
    return NULL;
}

CSLOL_API const char* cslol_set_config(const char16_t* prefix) {
    WCHAR buffer[MAX_PATH_WIDE] = {'\\', '\\', '?', '\\'};
    WCHAR* buffer_start = buffer + 4;
    WCHAR* buffer_end = buffer_start + MAX_PATH_WIDE - 1;

    // Get full path.
    DWORD length = GetFullPathNameW(prefix, buffer_end - buffer_start, buffer_start, NULL);
    if (length == 0 || length >= (buffer_end - buffer_start)) return "Failed to get full path.";

    // Transform directory separators to windows ones.
    for (WCHAR* i = buffer_start; i != buffer_end; ++i)
        if (*i == '/') *i = '\\';

    // Append \\ to end.
    if (buffer_start[length - 1] != '\\') {
        buffer_start[length++] = '\\';
        buffer_start[length] = '\0';
    }

    // Prepend \\\\?\\ if not there already.
    if (0 != memcmp(buffer_start, u"\\\\", 4)) {
        buffer_start = buffer;
        length += 4;
    }

    memcpy_s((void*)s_config.prefix, sizeof(s_config.prefix), buffer_start, (length + 1) * sizeof(WCHAR));

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
    const int old_inited = s_inited;
    HHOOK hook = SetWindowsHookExA(WH_GETMESSAGE, &cslol_msg_hookproc, g_instance, tid);
    if (!hook) return "Failed to create hook!";

    for (long long t = timeout; t > 0; t -= step) {
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
    if (s_log_start >= s_log_end) {
        return NULL;
    }
    const char* msg = &s_log_buffer[s_log_start];
    s_log_start += strlen(msg) + 1;
    return msg;
}

static void write_log(cslol_log_level level, char const* fmt, ...) {
    if (level > g_config.log_level) {
        return;
    }
    const int pos = g_log_end;
    const int remain = sizeof(s_log_buffer) - pos;
    if (remain < 1) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    const int ret = vsnprintf(&s_log_buffer[pos], remain, fmt, args);
    va_end(args);

    if (ret <= 0 || ret >= remain) {
        return;
    }

    g_log_end = pos + ret + 1;
    s_log_end = pos + ret + 1;
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
