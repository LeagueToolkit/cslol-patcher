#ifndef CSLOL_LOG_H
#define CSLOL_LOG_H

#include "cslol-api.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#define cslol_log_error(msg, ...) cslol_log_fmt(CSLOL_LOG_ERROR, "error: " msg, ##__VA_ARGS__)
#define cslol_log_warn(msg, ...) cslol_log_fmt(CSLOL_LOG_WARN, "warn: " msg, ##__VA_ARGS__)
#define cslol_log_info(msg, ...) cslol_log_fmt(CSLOL_LOG_INFO, "info: " msg, ##__VA_ARGS__)
#define cslol_log_debug(msg, ...) cslol_log_fmt(CSLOL_LOG_DEBUG, "debug: " msg, ##__VA_ARGS__)
#define cslol_log_trace(msg, ...) cslol_log_fmt(CSLOL_LOG_TRACE, "trace: " msg, ##__VA_ARGS__)

#define cslol_fail_if(condition, msg, ...)              \
    if ((condition)) {                                  \
        cslol_log_error(#condition msg, ##__VA_ARGS__); \
        goto fail;                                      \
    }

// Init logger.
extern void cslol_log_init(void);

// Should we allways log to shared buffer.
extern void cslol_log_shared_allways(bool enabled);

// Switch to more detailed logging at this point.
extern void cslol_log_finish(void);

// Write a message to log.
extern void cslol_log_fmt(cslol_log_level level, char const* fmt, ...);

// Start pulling logs.
extern void cslol_log_pull_reset(void);

// Pull a log entry.
extern int cslol_log_pull_into(char* out, size_t out_size);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // CSLOL_LOG_H
