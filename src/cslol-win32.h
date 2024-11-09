#ifndef CSLOL_WIN32_H
#define CSLOL_WIN32_H
#define NOMINMAX 1
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;
typedef STRING* PSTRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef STRING CANSI_STRING;
typedef PSTRING PCANSI_STRING;

extern BOOLEAN RtlCreateUnicodeString(UNICODE_STRING* DestinationString, PCWSTR SourceString);

extern FARPROC cslol_win32_get_proc_address(HMODULE module, LPCSTR proc_name);

extern HMODULE cslol_win32_get_module_handle(LPCWSTR mod_name);

extern LPVOID cslol_win32_mmap(LPCWSTR file_name, DWORD protect, SIZE_T* out_size);

extern void cslol_win32_munmap(LPVOID data);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // CSLOL_WIN32_H
