#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cslol-conf.h"
#include "cslol-hook.h"
#include "cslol-log.h"
#include "cslol-win32.h"

typedef NTSTATUS (*StringRoutine_fn)(PUNICODE_STRING dst, PCANSI_STRING src, BOOLEAN alloc);

static StringRoutine_fn g_cslol_hook_ovfs_StringRoutine_original = NULL;

static NTSTATUS StringRoutine_hook(PUNICODE_STRING dst, PCANSI_STRING src, BOOLEAN alloc) {
    // Consider only valid invocations that can allocate.
    if (!dst || !src || !alloc || !src->Buffer || src->Length >= CSLOL_CONF_MAX_PATH_NAROW) goto call_original;

    // Copy string on stack, avoid throwing exceptions.
    char source[CSLOL_CONF_MAX_PATH_NAROW];
    if (!ReadProcessMemory((HANDLE)-1, src->Buffer, source, src->Length, NULL)) goto call_original;
    source[src->Length] = 0;

    // Cache this for later.
    const char16_t* prefix = cslol_conf_get()->prefix;

    // Only consider DATA/ relative .wad paths.
    if (_strnicmp(source, "DATA/", 5) != 0 || !strstr(source, ".wad")) goto call_original;

    // Combine prefix + path in a local buffer.
    char16_t buffer[CSLOL_CONF_MAX_PATH_NAROW + CSLOL_CONF_MAX_PATH_WIDE];
    swprintf_s(buffer, sizeof(buffer) / sizeof(buffer[0]), L"%s%hs", prefix, source);

    // Transform all path separators to native windows ones.
    for (char16_t* i = buffer; *i; ++i)
        if (*i == L'/') *i = L'\\';

    // Ensure this is valid file.
    if (GetFileAttributesW(buffer) == INVALID_FILE_ATTRIBUTES) {
        cslol_log_debug("wad SKIPPED(%lx): %s)", GetLastError(), source);
        goto call_original;
    }

    // Perform any additional validation here.
    if (!cslol_hook_callback_ovfs(prefix, source)) goto call_original;

    cslol_log_info("wad FIXED: %s", source);

    if (!RtlCreateUnicodeString(dst, buffer)) goto call_original;
    return 0;

call_original:
    /* [[clang::musttail]] */ return g_cslol_hook_ovfs_StringRoutine_original(dst, src, alloc);
}

static void* cslol_hook_find_ovfs_StringRoutineFNPtr(void) {
    // Get KernelBase module handle.
    HMODULE module = cslol_win32_get_module_handle(L"KernelBase.dll");
    cslol_fail_if(!module, "Failed to find KernelBase module");

    // Malware detection: grab local path kernelbase.dll log it.
    char path[CSLOL_CONF_MAX_PATH_WIDE] = {0};
    GetModuleFileNameA(module, path, sizeof(path));
    cslol_log_info("KernelBase module=%p [%s]", module, path);

    // Find internal ascii -> unicode conversion function.
    LPVOID target = (LPVOID)cslol_win32_get_proc_address(module, "GetEightBitStringToUnicodeStringRoutine");
    cslol_fail_if(!target, "Failed to find StringRoutine funtion");
    cslol_log_info("StringRoutine=%p", target);

    // Find offset where StringRoutine is held in memory by dissasembling its getter function.
    // Unfortunately there is no setter :(
    //
    // static StringRoutine_fn fnptr;
    // StringRoutine_fn GetEightBitStringToUnicodeStringRoutine() {
    //   return fnptr;
    // }
    //
    // Dissembled:
    // mov rax, [offset]
    // ret
    DWORD64 data;
    BOOL result = ReadProcessMemory((HANDLE)-1, target, &data, sizeof(data), NULL);
    cslol_fail_if(!result, "Failed RPM GetStringRoutine: %lx", GetLastError());
    cslol_fail_if(((data & 0xff00000000ffffffull) != 0xc300000000058b48ull),
                  "Failed parse GetStringRoutine opcode: 0x%llx",
                  data);

    void* fnptr = (char*)target + 7 + (int32_t)(uint32_t)(data >> 24);
    cslol_log_info("StringRoutine_fnptr=%p", fnptr);

    return fnptr;

fail:
    return false;
}

bool cslol_hook_install_ovfs(void) {
    void* fnptr = cslol_hook_find_ovfs_StringRoutineFNPtr();

    // We have the offset now just read id.
    StringRoutine_fn StringRoutine_original = 0;
    BOOL res_rpm = ReadProcessMemory((HANDLE)-1, fnptr, &StringRoutine_original, sizeof(StringRoutine_original), NULL);
    cslol_fail_if(!res_rpm, "Failed RPM StringRoutineFNPtr: %lx", GetLastError());
    cslol_fail_if(!StringRoutine_original, "FIXME: StringRoutine not set yet?");

    // Some sanity checks to make sure we don't recurse into ourself in the hook.
    if (StringRoutine_original == &StringRoutine_hook) return true;
    g_cslol_hook_ovfs_StringRoutine_original = StringRoutine_original;

    // Writeout our hook pointer.
    void* hookptr = &StringRoutine_hook;
    BOOL res_wpm = WriteProcessMemory((HANDLE)-1, fnptr, &hookptr, sizeof(hookptr), NULL);
    cslol_fail_if(!res_wpm, "Failed WPM StringRoutine: %lx", GetLastError());

    return true;
fail:
    return false;
}
