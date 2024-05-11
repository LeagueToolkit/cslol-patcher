#ifndef CSLOL_WIN32_H
#define CSLOL_WIN32_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef STRING CANSI_STRING;
typedef PSTRING PCANSI_STRING;

BOOLEAN RtlCreateUnicodeString(UNICODE_STRING *DestinationString, PCWSTR SourceString);

#endif  // CSLOL_WIN32_H
