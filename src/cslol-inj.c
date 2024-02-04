#define WIN32_LEAN_AND_MEAN
#include <windows.h>
// do not reorder
#include <shellapi.h>
// do not reorder
#include <stdio.h>
// do not reorder
#include "cslol-api.h"

int main() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    // Grab args.
    if (argc < 2) {
        puts("No profile path provided!");
        return -1;
    }

    // Initialize first proces.
    {
        const char* error = cslol_init();
        if (error) {
            printf("Failed to init: %s: %x\n", error, GetLastError());
            return -1;
        }
    }

    // cslol_set_flags(CSLOL_HOOK_DISABLE_ALL);

    // Set prefix.
    {
        const char* error = cslol_set_config((const char16_t*)argv[1]);
        if (error) {
            printf("Failed to set prefix: %s\n", error);
            return -1;
        }
    }

    // Main loop.
    while (1) {
        // Scan for lol.
        puts("Waiting for game to start...");
        unsigned tid;
        while (!(tid = cslol_find())) Sleep(16);

        puts("Game found...");
        {
            const char* error = cslol_hook(tid, 30000, 100);
            if (error) {
                printf("Failed to hook: %s\n", error);
                return -1;
            }
        }

        puts("Waiting for game to exit...");
        while (tid == cslol_find()) Sleep(1000);
    }

    return 0;
}
