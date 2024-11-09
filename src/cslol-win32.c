#include "cslol-win32.h"

#include "cslol-log.h"

// This exists because exports can be pretty unreliable (we want to fail instead of getting thunk).
// Other than that antiviruses dislike GetProcAddress even more than manually resolving imports...
// Reconsider in future just using GetProcAddress.
FARPROC cslol_win32_get_proc_address(HMODULE module, LPCSTR proc_name) {
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
        if (0 == name_rva || 0 != strcmp(proc_name, base + name_rva)) continue;
        const USHORT ord = ordinals[i];
        if (ord < export_dir.Base || ord >= export_dir.NumberOfFunctions) continue;
        const DWORD func_rva = func_rvas[ord];
        if (func_rva == 0) continue;
        return (FARPROC)(base + func_rva);
    }
    return NULL;
}

// We are being somewhat nice by not leaking refcounts.
HMODULE cslol_win32_get_module_handle(LPCWSTR mod_name) {
    HMODULE module = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, mod_name, &module);
    return module;
}

// Just a wrapper in case we ever want do something more with it.
DWORD cslol_win32_get_module_file_name(HMODULE module, LPWSTR file_name, DWORD file_name_size) {
    DWORD result = GetModuleFileNameW(module, file_name, file_name_size);
    return result;
}

// Memory mapping made easier.
LPVOID cslol_win32_mmap(LPCWSTR file_name, DWORD protect, SIZE_T* out_size) {
    HANDLE file = NULL;
    HANDLE mapping = NULL;
    LPVOID result = NULL;

    // Only support read-only and optional PE image.
    protect &= SEC_IMAGE_NO_EXECUTE;
    protect |= PAGE_READONLY;

    file = CreateFileW(file_name, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    cslol_fail_if(!file || file == INVALID_HANDLE_VALUE, "CreateFileW error %x", GetLastError());

    mapping = CreateFileMappingA(file, 0, protect, 0, 0, NULL);
    cslol_fail_if(!mapping || mapping == INVALID_HANDLE_VALUE, "CreateFileMappingA error %x", GetLastError());

    result = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    cslol_fail_if(!result || result == INVALID_HANDLE_VALUE, "MapViewOfFile error %x", GetLastError());

    if (out_size) {
        MEMORY_BASIC_INFORMATION info = {0};
        VirtualQuery(result, &info, sizeof(info));
        *out_size = info.RegionSize;
    }

fail:
    if (mapping && mapping != INVALID_HANDLE_VALUE) CloseHandle(mapping);
    if (file && file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return result;
}

// Memory unmapping made easier.
void cslol_win32_munmap(LPVOID data) {
    if (data && data != INVALID_HANDLE_VALUE) UnmapViewOfFile(data);
}
