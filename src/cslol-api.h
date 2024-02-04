#ifndef CSLOL_API_H
#define CSLOL_API_H

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stdbool.h>
#include <uchar.h>

#ifdef CSLOL_IMPL
#    ifdef _MSC_VER
#        define CSLOL_API __declspec(dllexport)
#    else
#        define CSLOL_API
#    endif
#else
#    ifdef _MSC_VER
#        define CSLOL_API __declspec(dllimport)
#    else
#        define CSLOL_API extern
#    endif
#endif

#define CSLOL_HOOK_DISALBE_NONE 0u
#define CSLOL_HOOK_DISABLE_VERIFY 1u
#define CSLOL_HOOK_DISABLE_FILE 2u
#define CSLOL_HOOK_DISABLE_ALL (unsigned)(-1)

// Msg proc used for injection.
CSLOL_API intptr_t cslol_msg_hookproc(int code, uintptr_t wParam, intptr_t lParam);

// Initialize IPC, returns error if any.
CSLOL_API const char* cslol_init();

// Sets prefix folder, returns error if any.
CSLOL_API const char* cslol_set_config(const char16_t* prefix);

// Sets flags, return error if any.
CSLOL_API const char* cslol_set_flags(unsigned flags);

// Find thread id of running lol instance.
CSLOL_API unsigned cslol_find();

// Hook, return error if any.
CSLOL_API const char* cslol_hook(unsigned tid, unsigned post_iters, unsigned event_iters);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // CSLOL_API_H
