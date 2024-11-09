#include "cslol-hook.h"

#include <stdalign.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cslol-conf.h"
#include "cslol-db.h"
#include "cslol-log.h"
#include "cslol-win32.h"

typedef struct cslol_hook_evil_md {
    unsigned char from_md[32];
    unsigned char into_md[32];
} cslol_hook_evil_md;

typedef struct cslol_hook_context {
    size_t count;
    cslol_hook_evil_md hashes[0];
} cslol_hook_context;

static _Atomic(cslol_hook_context*) g_cslol_hook_context = NULL;

static atomic_bool g_cslol_hook_context_failed = false;

static int cslol_hook_evil_md_cmp(void const* l, void const* r) {
    // this is sha256, only first 128bits should be more than enough?
    int x = memcmp(l, r, 32);
    if (x < 0) return -1;
    if (x > 0) return 1;
    return 0;
}

static cslol_hook_context* cslol_hook_context_lazy_init(void) {
    // if we failed previously, no point in re-trying again!
    if (atomic_load(&g_cslol_hook_context_failed)) return false;

    cslol_hook_context* ctx = NULL;
    cslol_hook_context* old = atomic_load(&g_cslol_hook_context);
    if (old) return old;

    // PREFIX\\wad.csloldb, note that prefix already should include trailing separator
    char16_t db_filename[CSLOL_CONF_MAX_PATH_WIDE + CSLOL_CONF_MAX_PATH_NAROW] = {0};
    swprintf_s(db_filename, sizeof(db_filename) / sizeof(db_filename[0]), L"%swad.csloldb", cslol_conf_get()->prefix);

    cslol_db db = {0};
    SIZE_T data_size = 0;
    LPVOID data = cslol_win32_mmap(db_filename, PAGE_READONLY, &data_size);
    cslol_db_err err = cslol_db_parse(&db, (const unsigned char*)data, data_size);
    cslol_win32_munmap(data);
    cslol_fail_if(err != NULL, "%s", err);

    ctx = malloc(offsetof(cslol_hook_context, hashes[db.header.toc_wads_count]));
    cslol_fail_if(!ctx, "malloc failed");
    memset(ctx, 0, offsetof(cslol_hook_context, hashes[db.header.toc_wads_count]));

    // TODO: initialize signature verification context here

    // copy wad hashes
    for (size_t i = 0; i != db.header.toc_wads_count; ++i) {
        cslol_toc_wad* wad = &db.toc_wads[i];

        // TODO: verify wad entries provenenance here
        // TODO: verify mod signatures here

        cslol_hook_evil_md* hash = &ctx->hashes[ctx->count];
        memcpy_s(hash->from_md, sizeof(cslol_hook_evil_md), wad->header.md_new, sizeof(cslol_hook_evil_md));
        memcpy_s(hash->into_md, sizeof(cslol_hook_evil_md), wad->header.md_org, sizeof(cslol_hook_evil_md));

        cslol_log_debug("load hash from(%llx) into (%llx)", *(uint64_t*)hash->from_md, *(uint64_t*)hash->into_md);

        ++ctx->count;
    }

    // sort hashes after copying
    qsort(ctx->hashes, ctx->count, sizeof(cslol_hook_evil_md), cslol_hook_evil_md_cmp);

    cslol_log_info("ovfs loaded %zu hashes", ctx->count);

    // realistically this should never be accessed from multiple threads but guard against it anyways
    if (!atomic_compare_exchange_strong(&g_cslol_hook_context, &old, ctx)) {
        cslol_db_free(&db);
        free(ctx);
        return old;
    }
    return ctx;

fail:
    atomic_store(&g_cslol_hook_context_failed, true);
    cslol_db_free(&db);
    free(ctx);
    return NULL;
}

bool cslol_hook_callback_ovfs(const char16_t* prefix, const char* path) {
    cslol_hook_context* ctx = cslol_hook_context_lazy_init();
    cslol_log_debug("ovfs (%p): %s", ctx, path);
    if (!ctx) return false;

    return true;
}

bool cslol_hook_callback_evil(unsigned char md[32]) {
    // we should allways be initialized BEFORE this
    cslol_hook_context* ctx = atomic_load(&g_cslol_hook_context);
    if (!ctx) return false;

    const void* i = bsearch(md,
                            g_cslol_hook_context->hashes,
                            g_cslol_hook_context->count,
                            sizeof(cslol_hook_evil_md),
                            cslol_hook_evil_md_cmp);

    if (!i) {
        cslol_log_debug("evil miss from %llx", *(uint64_t*)md);
        return false;
    }
    cslol_log_debug("evil write from %llx into %llx",
                    *(uint64_t*)md,
                    *(uint64_t*)(((const cslol_hook_evil_md*)i)->into_md));
    memcpy_s(md, 32, ((const cslol_hook_evil_md*)i)->into_md, 32);

    return true;
}

bool cslol_hook_init(void) {
    if (!cslol_hook_install_evil()) return false;
    if (!cslol_hook_install_ovfs()) return false;
    return true;
}
