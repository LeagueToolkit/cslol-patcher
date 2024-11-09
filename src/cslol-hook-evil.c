#include <stdalign.h>
#include <stdlib.h>
#include <string.h>

#include "cslol-conf.h"
#include "cslol-hook.h"
#include "cslol-log.h"
#include "cslol-win32.h"

// openss configuration
#define OPENSSL_NO_ASM
#define DECLARE_DEPRECATED(f) f;
#define DEPRECATEDIN_1_2_0(f) DECLARE_DEPRECATED(f)
#define DEPRECATEDIN_1_1_0(f) DECLARE_DEPRECATED(f)
#define DEPRECATEDIN_1_0_0(f) DECLARE_DEPRECATED(f)
#define DEPRECATEDIN_0_9_8(f) DECLARE_DEPRECATED(f)
#define SIXTY_FOUR_BIT
#define OPENSSL_cleanse PRIVATE_OPENSSL_cleanse
#define SHA224 PRIVATE_SHA224
#define SHA224_Init PRIVATE_SHA224_Init
#define SHA224_Update PRIVATE_SHA224_Update
#define SHA224_Transform PRIVATE_SHA224_Transform
#define SHA224_Final PRIVATE_SHA224_Final
#define SHA256 PRIVATE_SHA256
#define SHA256_Init PRIVATE_SHA256_Init
#define SHA256_Update PRIVATE_SHA256_Update
#define SHA256_Transform PRIVATE_SHA256_Transform
#define SHA256_Final PRIVATE_SHA256_Final

// public parts of openssl
#include <crypto/evp.h>
#include <openssl/engine.h>
#include <openssl/sha.h>

// private parts of openssl
#include <crypto/engine/eng_local.h>
#include <crypto/evp/evp_local.h>

// source parts of openssl
#include <crypto/sha/sha256.c>

// curl configuration
#define USE_OPENSSL
#define CURL_DISABLE_FTP

// only private parts of curl
#include <urldata.h>
#include <vtls/vtls.h>
#ifdef _WIN32
_Static_assert(offsetof(struct Curl_easy, state.engine) == 3760, "Bad offset sanity check!");
#endif

static const char CSLOL_HOOK_EVIL_ENGINE_NAME[] = "evil engine";

void OPENSSL_cleanse(void *ptr, size_t len) { memset(ptr, 0, len); }

static int cslol_hook_evil_md_sha256_init(EVP_MD_CTX *ctx) { return SHA256_Init(ctx->md_data); }

static int cslol_hook_evil_md_sha256_update(EVP_MD_CTX *ctx, const void *data, size_t count) {
    return SHA256_Update(ctx->md_data, data, count);
}

static int cslol_hook_evil_md_sha256_final(EVP_MD_CTX *ctx, unsigned char *md) {
    SHA256_Final(md, ctx->md_data);
    if (ctx->engine && ctx->engine->name == CSLOL_HOOK_EVIL_ENGINE_NAME) cslol_hook_callback_evil(md);
    return 1;
}

static const EVP_MD g_cslol_hook_evil_sha256_md = {
    NID_sha256,
    NID_sha256WithRSAEncryption,
    SHA256_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    &cslol_hook_evil_md_sha256_init,
    &cslol_hook_evil_md_sha256_update,
    &cslol_hook_evil_md_sha256_final,
    NULL,
    NULL,
    SHA256_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA256_CTX),
};

static int cslol_hook_evil_engine_digests(ENGINE *engine, const EVP_MD **digest, const int **nids, int nid) {
    if (engine && engine->name == CSLOL_HOOK_EVIL_ENGINE_NAME) {
        if (nid == 0) {
            if (nids) *nids = &g_cslol_hook_evil_sha256_md.type;
            return 1;
        }
        if (digest && nid == g_cslol_hook_evil_sha256_md.type) {
            *digest = &g_cslol_hook_evil_sha256_md;
            return 1;
        }
    }
    return 0;
}

static struct engine_st g_cslol_hook_evil_engine = {
    .name = CSLOL_HOOK_EVIL_ENGINE_NAME,
    .digests = &cslol_hook_evil_engine_digests,
    .struct_ref = 2,
};

// Scan image on disk for pattern.
static uintptr_t cslol_hook_find_evil(LPVOID module) {
    // Get module file path.
    LPVOID data = 0;
    SIZE_T data_size = 0;

    // Get module path so we can map it.
    WCHAR path[CSLOL_CONF_MAX_PATH_WIDE];
    DWORD path_size = GetModuleFileNameW(module, path, sizeof(path));
    cslol_fail_if(!path_size || path_size >= CSLOL_CONF_MAX_PATH_WIDE, "Failed GetModuleFileNameW: %x", GetLastError());

    // Map a new copy of module as read-only image.
    data = cslol_win32_mmap(path, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, &data_size);
    cslol_fail_if(!data || data == INVALID_HANDLE_VALUE, "Failed cslol_win32_mmap: %x", GetLastError());

    // Reference curl openssl vtable.
    const struct Curl_ssl reference = {
        .info = {CURLSSLBACKEND_OPENSSL, NULL},  // we do not care about name
        .supports = 0x7F,                        // openssl supports everything
        .sizeof_ssl_backend_data = 0x20,
    };

    // To speed this up we can iterate with alignment size.
    // Note we intentionaly don't start at 0 because we use it for error.
    const size_t size = offsetof(struct Curl_ssl, sizeof_ssl_backend_data) + sizeof(reference.sizeof_ssl_backend_data);
    const size_t step = alignof(struct Curl_ssl);
    for (size_t i = step; i + sizeof(struct Curl_ssl) <= data_size; i += step) {
        // Compare only info.id, supports and sizeof_ssl_backend_data.
        struct Curl_ssl copy;
        memset(&copy, 0, size);
        memcpy(&copy, data + i, size);
        copy.info.name = reference.info.name;
        if (memcmp(&reference, &copy, size) != 0) continue;

        cslol_win32_munmap(data);
        return i;
    }

fail:
    cslol_win32_munmap(data);
    return false;
}

bool cslol_hook_install_evil(void) {
    // We operate on main module only (for now?).
    HMODULE main_module = cslol_win32_get_module_handle(NULL);
    cslol_fail_if(!main_module, "Failed to find main module!");

    // Find curl ssl vtable.
    uintptr_t curl_ssl_rva = cslol_hook_find_evil(main_module);
    cslol_fail_if(!curl_ssl_rva, "Failed to find ssl vtable in module: %p", main_module);

    // Read and perform some sanity checks.
    struct Curl_ssl curl_ssl;
    BOOL result1 = ReadProcessMemory((HANDLE)-1, (char *)main_module + curl_ssl_rva, &curl_ssl, sizeof(curl_ssl), NULL);
    cslol_fail_if(!result1, "Failed to read ssl vtable because: %x", GetLastError());
    cslol_fail_if(curl_ssl.info.id != CURLSSLBACKEND_OPENSSL, "Ssl vtable info.id  mismatch");
    cslol_fail_if(curl_ssl.supports != 0x7F, "Ssl vtable supports mismatch");
    cslol_fail_if(curl_ssl.sizeof_ssl_backend_data != 0x20, "Ssl vtable sizeof_ssl_backend_data mismatch");
    cslol_fail_if(!curl_ssl.engines_list, "Ssl vtable engines_list null");
    cslol_fail_if(!curl_ssl.set_engine_default, "Ssl vtable set_engine_default null");

    // Thre should be nothing else written or read here but still guard against this with 2 pages of zeroes.
    union {
        struct Curl_easy easy;
        char extra[CSLOL_CONF_PAGE_SIZE * 2];
    } storage;
    memset(&storage, 0, sizeof(storage));

    // Before we can register engine we must initialize engine lock.
    // Instead of initializing everything abuse the fact that ENGINE_first() initializes lock for us.
    // Note that this potentially leaks bit of memory.
    curl_ssl.engines_list(&storage.easy);

    // Alternative is to call actual init function
    // curl_ssl.init();

    // CURL should now set the engine for us :).
    storage.easy.state.engine = &g_cslol_hook_evil_engine;
    int error = curl_ssl.set_engine_default(&storage.easy);
    cslol_fail_if(error != 0, "Error setting ssl engine %d", error);

    return true;

fail:
    return false;
}
