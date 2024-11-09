#ifndef CSLOL_HOOK_H
#define CSLOL_HOOK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <uchar.h>

// setup hooks
extern bool cslol_hook_init(void);

// set evil hash engine as default engine
extern bool cslol_hook_install_evil(void);

// setup overlay filesystem
extern bool cslol_hook_install_ovfs(void);

// ovfs callback
extern bool cslol_hook_callback_ovfs(const char16_t* prefix, const char* path);

// evil callback
extern bool cslol_hook_callback_evil(unsigned char md[32]);

#ifdef __cplusplus
}
#endif

#endif  // CSLOLHOOK_H
