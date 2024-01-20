#define WIN32_LEAN_AND_MEAN
#include <windows.h>
// do not reorder
#include <stdlib.h>
#include <string.h>
// do not reorder
#define CSLOL_IMPL
#include "cslol-api.h"

#define MAX_PATH_WIDE 1024
#define PAGE_SIZE 0x1000
#define LOL_WINDOW "League of Legends (TM) Client"
#define LOL_EXE "League of Legends.exe"

// TODO: make this into something nicer:
#define error_if(condition, msg)            \
    if (condition) {                        \
        MessageBoxA(0, #condition, msg, 0); \
        return 0;                           \
    }

static WCHAR CreateFileA_prefix[MAX_PATH_WIDE] = {0};

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
    for (LPWSTR src = CreateFileA_prefix; *src; ++dst, ++src) *dst = *src;

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
    error_if(!module || module == INVALID_HANDLE_VALUE, "Failed to get kernel32 module!");

    ImportThunk* thunk = (ImportThunk*)GetProcAddress(module, "CreateFileA");
    error_if(!thunk, "Failed to get CreateFileA import thunk.");
    error_if(thunk->jmp != 0x25FF, "CreateFileA import thunk is not jmp rel32.");

    CreateFileA_original = *(CreateFileA_fnptr*)(thunk->pad + thunk->rel32);

    ImportTrampoline tramp = {{0x48, 0xB8u}, (UINT64)&CreateFileA_hook, {0xFF, 0xE0}};
    BOOL result = WriteProcessMemory((HANDLE)-1, thunk, &tramp, sizeof(tramp), NULL);
    error_if(result == 0, "Failed to write import trampoline!");

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
    error_if(path_size >= MAX_PATH_WIDE, "Failed to get module path.");

    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    error_if(!file || file == INVALID_HANDLE_VALUE, "Failed to open module file!");

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

    *(LPVOID*)(offset + 32 + (UINT_PTR)module) = &CRYPTO_free_hook;

    return 1;
}

static LRESULT msg_hookproc(int code, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(NULL, code, wParam, lParam);
}

__asm__(".section .shared,\"ds\"\n");
static volatile int s_inited __attribute__((section(".shared"))) = {0};
static WCHAR s_prefix_buffer[MAX_PATH_WIDE] __attribute__((section(".shared"))) = {0};

static HINSTANCE g_instance = NULL;

static void init_in_process() {
    // Ensure that dll stays loaded.
    {
        WCHAR path[MAX_PATH_WIDE];
        GetModuleFileNameW(g_instance, path, sizeof(path));
        LoadLibraryW(path);
    }

    // Copy shared prefix buffer into private prefix buffer.
    {
        memcpy_s(CreateFileA_prefix, sizeof(CreateFileA_prefix), s_prefix_buffer, sizeof(s_prefix_buffer));
        ++s_inited;
    }

    // Pach int_rsa_verify via CRYPTO_free before patching CreateFileA.
    if (!patch_CRYPTO_free()) {
        return;
    }

    // Patch CreateFileA for filesystem overlay effect.
    if (!patch_CreateFileA()) {
        return;
    }
}

CSLOL_API const char* cslol_set_prefix(const char16_t* prefix) {
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
        buffer_start[length] = '0';
    }

    // Prepend \\\\?\\ if not there already.
    if (0 != memcmp(buffer_start, "\\\0\\\0", 4)) {
        buffer_start = buffer;
        length += 4;
    }

    // Copy to shared buffer.
    memcpy_s(s_prefix_buffer, sizeof(s_prefix_buffer), buffer_start, (length + 1) * sizeof(WCHAR));

    return NULL;
}

CSLOL_API void cslol_sleep(unsigned ms) { Sleep(ms); }

CSLOL_API unsigned cslol_find_lol() {
    HWND hwnd = FindWindowExA(NULL, NULL, NULL, LOL_WINDOW);
    if (hwnd) {
        DWORD pid = 0;
        DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
        if (pid && tid) return tid;
    }
    return 0;
}

CSLOL_API const char* cslol_hook(unsigned tid) {
    const int old_inited = s_inited;
    HHOOK hhook = SetWindowsHookExA(WH_GETMESSAGE, &msg_hookproc, g_instance, tid);
    if (!hhook) return "Failed to set hook.";
    while (old_inited == s_inited) cslol_sleep(250);
    UnhookWindowsHookEx(hhook);
    return NULL;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_instance = inst;
        if (GetModuleHandleA(LOL_EXE) == GetModuleHandleA(NULL)) {
            init_in_process();
        }
    }
    return 1;
}
