#include "cslol-log.h"

#include <stdio.h>

#include "cslol-conf.h"
#include "cslol-win32.h"

__asm__(".section .shared,\"ds\"\n");

static volatile char s_cslol_log_buffer[CSLOL_CONF_PAGE_SIZE * 4] __attribute__((section(".shared"))) = {0};

static volatile int s_clsol_log_buffer_end __attribute__((section(".shared"))) = 0;

static volatile int g_cslol_log_buffer_end = 0;

static cslol_log_level g_cslol_log_level = 0;

static HANDLE g_cslol_log_handle = NULL;

static bool g_cslol_log_shared_allways = 0;

void cslol_log_init(void) {
    s_clsol_log_buffer_end = 0;
    g_cslol_log_level = cslol_conf_get()->log_level;

    wchar_t file_name[CSLOL_CONF_MAX_PATH_WIDE + CSLOL_CONF_MAX_PATH_NAROW] = {0};
    swprintf_s(file_name, sizeof(file_name), L"%s/log.txt", cslol_conf_get()->prefix);
    g_cslol_log_handle = CreateFileW(file_name,
                                     FILE_APPEND_DATA,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     0,
                                     OPEN_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL,
                                     0);
    if (!g_cslol_log_handle || g_cslol_log_handle == INVALID_HANDLE_VALUE)
        cslol_log_error("failed to open log file because %x", GetLastError());
}

void cslol_log_shared_allways(bool enabled) { g_cslol_log_shared_allways = enabled; }

void cslol_log_finish(void) {
    // just make sure to flush, no need to close the handle
    if (g_cslol_log_handle && g_cslol_log_handle != INVALID_HANDLE_VALUE) FlushFileBuffers(g_cslol_log_handle);
}

void cslol_log_fmt(cslol_log_level level, char const* fmt, ...) {
    if (level > g_cslol_log_level) return;

    char buffer[CSLOL_CONF_LOG_MAX_LINE] = {0};
    int ret;

    va_list args;
    va_start(args, fmt);
    ret = vsnprintf(buffer, sizeof(buffer) - 1, fmt, args);
    va_end(args);

    // be extra carefull, truncate output if necessary
    if (ret < 0) return;
    if (ret >= (sizeof(buffer) - 1)) ret = sizeof(buffer) - 1;

    // if we have log file write there as well
    if (g_cslol_log_handle && g_cslol_log_handle != INVALID_HANDLE_VALUE) {
        buffer[ret] = '\n';
        if (WriteFile(g_cslol_log_handle, buffer, ret + 1, NULL, NULL)) {
            FlushFileBuffers(g_cslol_log_handle);
            // don't waste shared log buffer space on non-errors
            if (!g_cslol_log_shared_allways && level > CSLOL_LOG_ERROR) return;
        }
    }

    // while we have space in small shared log buffer
    if ((sizeof(s_cslol_log_buffer) - g_cslol_log_buffer_end) >= (ret + 1)) {
        buffer[ret] = '\0';
        memcpy((char*)(s_cslol_log_buffer + g_cslol_log_buffer_end), buffer, ret + 1);
        g_cslol_log_buffer_end += ret + 1;
        s_clsol_log_buffer_end = g_cslol_log_buffer_end;
    }
}

void cslol_log_pull_reset(void) {
    g_cslol_log_buffer_end = 0;
    s_clsol_log_buffer_end = 0;
}

int cslol_log_pull_into(char* out, size_t out_size) {
    const int new_end = s_clsol_log_buffer_end;
    const int cur = g_cslol_log_buffer_end;

    // is there any new message ?
    if (cur >= new_end) return 0;
    if (cur >= sizeof(s_cslol_log_buffer)) return 0;

    // bounds check output size, truncate if message is too big
    const int len = strlen((const char*)s_cslol_log_buffer + cur) + 1;
    const int len_out = (len > CSLOL_CONF_LOG_MAX_LINE) ? CSLOL_CONF_LOG_MAX_LINE : len;
    if (len_out >= out_size) return -len_out;

    // copy the message and make sure to null terminate, then advance buffer with actual length
    memcpy(out, (const char*)s_cslol_log_buffer + cur, len_out);
    out[len_out - 1] = 0;
    g_cslol_log_buffer_end = cur + len;

    return len_out;
}
