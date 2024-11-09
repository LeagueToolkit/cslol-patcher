#include "cslol-conf.h"

#include <stdio.h>
#include <string.h>

#define NOMINMAX 1
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

__asm__(".section .shared,\"ds\"\n");

static volatile cslol_config s_cslol_conf_shared __attribute__((section(".shared"))) = {0, 0, {0}};

static cslol_config g_cslol_conf_private = {0, 0, {0}};

const cslol_config* cslol_conf_get() { return &g_cslol_conf_private; }

const char* cslol_conf_set_prefix(const char16_t* prefix) {
    // Get full path.
    WCHAR full[CSLOL_CONF_MAX_PATH_WIDE];
    DWORD length = GetFullPathNameW(prefix, CSLOL_CONF_MAX_PATH_WIDE, full, NULL);
    if (length == 0 || length >= CSLOL_CONF_MAX_PATH_WIDE) return "Prefix path invalid length";

    // Upgrade normal paths to long paths.
    WCHAR buffer[CSLOL_CONF_MAX_PATH_WIDE];
    int ret = swprintf_s(buffer,
                         CSLOL_CONF_MAX_PATH_WIDE,
                         L"%s%s%s",
                         // #1. Prepend \\\\?\\ if NOT there already.
                         wcsstr(full, L"\\\\") != 0 ? L"\\\\?\\" : L"",
                         // #2 Path itself.
                         full,
                         // #3 Directory separator at end.
                         full[length - 1] != L'\\' && full[length - 1] != '/' ? L"\\" : L"");
    if (ret < 0) return "Prefix too big!";

    // Use proper windows path separator.
    for (size_t i = 0; i != CSLOL_CONF_MAX_PATH_WIDE; ++i)
        if (buffer[i] == L'/') buffer[i] = L'\\';

    // Ensure that the path actually exists.
    DWORD attrib = GetFileAttributesW((LPCWSTR)buffer);
    if (attrib == INVALID_FILE_ATTRIBUTES || !(attrib & FILE_ATTRIBUTE_DIRECTORY)) return "Prefix does not exist";

    // Apply this to shared config.
    memcpy_s((void*)g_cslol_conf_private.prefix, CSLOL_CONF_MAX_PATH_WIDE, buffer, CSLOL_CONF_MAX_PATH_WIDE);
    return NULL;
}

const char* cslol_conf_set_flags(cslol_hook_flags flags) {
    g_cslol_conf_private.flags = flags;
    return NULL;
}

const char* cslol_conf_set_log_level(cslol_log_level level) {
    g_cslol_conf_private.log_level = level;
    return NULL;
}

void cslol_conf_push(void) { s_cslol_conf_shared = g_cslol_conf_private; }

void cslol_conf_pull(void) {
    g_cslol_conf_private = s_cslol_conf_shared;
    // make sure prefix is nullterminated
    g_cslol_conf_private.prefix[sizeof(g_cslol_conf_private.prefix) / sizeof(g_cslol_conf_private.prefix[0]) - 1] = 0;
}
