#ifndef CSLOL_CONF_H
#define CSLOL_CONF_H

#include "cslol-api.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#define CSLOL_CONF_MAX_PATH_WIDE 1024
#define CSLOL_CONF_MAX_PATH_NAROW 128
#define CSLOL_CONF_PAGE_SIZE 0x1000
#define CSLOL_CONF_LOL_WINDOW "League of Legends (TM) Client"
#define CSLOL_CONF_LOL_EXE "League of Legends.exe"
#define CSLOL_CONF_LOG_MAX_LINE 1024

typedef struct cslol_config {
    cslol_hook_flags flags;
    cslol_log_level log_level;
    char16_t prefix[CSLOL_CONF_MAX_PATH_WIDE];
} cslol_config;

extern const cslol_config* cslol_conf_get();

extern const char* cslol_conf_set_prefix(const char16_t* prefix);

extern const char* cslol_conf_set_flags(cslol_hook_flags flags);

extern const char* cslol_conf_set_log_level(cslol_log_level level);

extern void cslol_conf_push(void);

extern void cslol_conf_pull(void);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // CSLOL_CONF_H
