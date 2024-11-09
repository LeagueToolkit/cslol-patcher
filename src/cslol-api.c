#include "cslol-api.h"

#include <stdint.h>
#include <stdio.h>

#include "cslol-conf.h"
#include "cslol-hook.h"
#include "cslol-log.h"
#include "cslol-win32.h"

__asm__(".section .shared,\"ds\"\n");

static volatile int __attribute__((section(".shared"))) s_cslol_api_inited_shared = 0;

static HINSTANCE g_cslol_api_instance = 0;

static int g_cslol_api_internal = 0;

static char g_cslol_api_log_buffer[CSLOL_CONF_LOG_MAX_LINE] = {0};

intptr_t cslol_api_msg_hookproc(int code, uintptr_t wParam, intptr_t lParam) {
    PMSG msg = (PMSG)lParam;
    if (msg && msg->wParam == 0x306c6f6c7363 && msg->message == 0x511) {
        UnhookWindowsHookEx((HHOOK)msg->lParam);
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

const char* cslol_api_init() {
    // Add some kind of multi-instance check here?
    return NULL;
}

const char* cslol_api_set_prefix(const char16_t* prefix) { return cslol_conf_set_prefix(prefix); }

const char* cslol_api_set_flags(cslol_hook_flags flags) { return cslol_conf_set_flags(flags); }

const char* cslol_api_set_log_level(cslol_log_level level) { return cslol_conf_set_log_level(level); }

const char* cslol_api_log_pull() {
    const int ret = cslol_log_pull_into(g_cslol_api_log_buffer, sizeof(g_cslol_api_log_buffer));
    if (ret <= 0) return NULL;
    return g_cslol_api_log_buffer;
}

unsigned cslol_api_find_tid() {
    HWND hwnd = FindWindowExW(NULL, NULL, NULL, L"" CSLOL_CONF_LOL_WINDOW);
    if (!hwnd) return 0;
    return GetWindowThreadProcessId(hwnd, NULL);
}

const char* cslol_api_hook(unsigned tid, unsigned timeout, unsigned step) {
    cslol_conf_push();
    cslol_log_pull_reset();

    const int old_inited = s_cslol_api_inited_shared;
    HHOOK hook = SetWindowsHookExA(WH_GETMESSAGE, &cslol_api_msg_hookproc, g_cslol_api_instance, tid);
    if (!hook) return "Failed to create hook!";

    for (long long t = timeout; t > 0; t -= step) {
        PostThreadMessageA(tid, 0x511u, 0x306c6f6c7363, (LPARAM)hook);
        Sleep(step);
        if (old_inited != s_cslol_api_inited_shared) {
            UnhookWindowsHookEx(hook);
            return NULL;
        }
    }

    UnhookWindowsHookEx(hook);
    return "Timeout out while waiting for init!";
}

static void cslol_api_init_in_process() {
    // grab handle to lol executable and main executable, be carefull not to leak reference count at this point yet
    HMODULE lol_exe = cslol_win32_get_module_handle(L"" CSLOL_CONF_LOL_EXE);
    if (!lol_exe) return;

    HMODULE main_exe = cslol_win32_get_module_handle(NULL);
    if (!main_exe) return;

    // if we got both handles and they match, we are in correct process
    if (lol_exe != main_exe) return;

    // pin our module to never be unloaded
    HMODULE api_dll = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                       (LPCWSTR)&cslol_api_init_in_process,
                       &api_dll);

    // we can now more safely proceed
    s_cslol_api_inited_shared++;
    g_cslol_api_internal = 1;

    // copy config from shared memory into our process
    cslol_conf_pull();

    // start logging as soon as we have config
    cslol_log_init();
    cslol_log_shared_allways(true);

    // initialize remapping
    cslol_log_info("Init start!");
    cslol_hook_init();
    cslol_log_info("Init done!");

    // we don't care about shared logging anymore
    cslol_log_shared_allways(false);

    return;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        g_cslol_api_instance = inst;
        cslol_api_init_in_process();
    }
    if (reason == DLL_PROCESS_DETACH && g_cslol_api_internal) {
        cslol_log_shared_allways(true);
        cslol_log_info("Exit in process!");
        cslol_log_shared_allways(false);
        cslol_log_finish();
    }
    return 1;
}
