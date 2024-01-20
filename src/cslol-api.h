#ifndef CSLOL_API_H
#define CSLOL_API_H

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

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

// Sets prefix folder, returns error if any.
CSLOL_API const char* cslol_set_prefix(const char16_t* prefix);

// Find thread id of running lol instance.
CSLOL_API unsigned cslol_find_lol();

// Hooks.
CSLOL_API const char* cslol_hook(unsigned tid);

// Sleep.
CSLOL_API void cslol_sleep(unsigned ms);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // CSLOL_API_H
