#include "cslol-crypto.h"

#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
//
#include <bcrypt.h>
//
#include <wincrypt.h>
// FIXME: use something better here
#define STATUS_ALLOC_FAILED 0xC00000A0

typedef struct cslol_crypto_ctx {
    BCRYPT_ALG_HANDLE sha256;
    BCRYPT_ALG_HANDLE rsa;
    BCRYPT_KEY_HANDLE pkey;
    HCERTSTORE root_store;
    HCERTSTORE extra_store;
} cslol_crypto_ctx;

cslol_crypto_err cslol_crypto_ctx_create(cslol_crypto_ctx** out_ctx) {
    if (!out_ctx) return STATUS_INVALID_PARAMETER;

    cslol_crypto_ctx* ctx = (*out_ctx = calloc(1, sizeof(cslol_crypto_ctx)));
    if (!ctx) return STATUS_ALLOC_FAILED;

    return 0;
}

void cslol_crypto_ctx_free(cslol_crypto_ctx* ctx) {
    if (!ctx) return;

    if (ctx->sha256) BCryptCloseAlgorithmProvider(ctx->sha256, 0);
    if (ctx->rsa) BCryptCloseAlgorithmProvider(ctx->rsa, 0);
    if (ctx->pkey) BCryptDestroyKey(ctx->pkey);
    if (ctx->root_store) CertCloseStore(ctx->root_store, 0);

    free(ctx);
}

// verify wad entires are same as provided sha256 mds
cslol_crypto_err cslol_crypto_sha256(cslol_crypto_ctx* ctx,
                                     const unsigned char* data,
                                     size_t len,
                                     unsigned char md[32]) {
    if (!ctx || (!data && len) || !md) return STATUS_INVALID_PARAMETER;

    // we cache this in context
    NTSTATUS status;

    if (!ctx->sha256) {
        status = BCryptOpenAlgorithmProvider(&ctx->sha256, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (status != 0) return status;
    }

    return BCryptHash(ctx->sha256, NULL, 0, (PUCHAR)data, len, md, 32);
}

// verify mod entries are same as provided sha256 md
cslol_crypto_err cslol_crypto_import_rsa_pub(cslol_crypto_ctx* ctx, const unsigned char* pk, size_t pklen) {
    if (!ctx || (!pk && pklen)) return STATUS_INVALID_PARAMETER;

    NTSTATUS status;

    if (!ctx->rsa) {
        status = BCryptOpenAlgorithmProvider(&ctx->rsa, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (status != 0) return status;
    }

    BCRYPT_ALG_HANDLE pkey = NULL;

    status = BCryptImportKeyPair(ctx->rsa,
                                 NULL,
                                 BCRYPT_RSAPUBLIC_BLOB,  // For RSA public key
                                 &pkey,
                                 (PUCHAR)pk,
                                 pklen,
                                 0);
    if (status != 0) return status;

    // only set new key if everything is good
    if (ctx->pkey) BCryptDestroyKey(ctx->pkey);
    ctx->pkey = pkey;

    return 0;
}

cslol_crypto_err cslol_crypto_verify_pkcs15_rsa_sha256(cslol_crypto_ctx* ctx,
                                                       const unsigned char* sig,
                                                       size_t siglen,
                                                       const unsigned char md[32]) {
    if (!ctx || (!sig && siglen) || !md) return STATUS_INVALID_PARAMETER;

    return BCryptVerifySignature(ctx->pkey, NULL, (PUCHAR)md, 32, (PUCHAR)sig, siglen, BCRYPT_PAD_PKCS1);
}

cslol_crypto_err cslol_crypto_import_root_cert(cslol_crypto_ctx* ctx, const unsigned char* certdata, size_t certlen) {
    if (!ctx || (!certdata && certlen)) return STATUS_INVALID_PARAMETER;

    if (!ctx->root_store) {
        HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, 0);
        if (!store) return GetLastError();
        ctx->root_store = store;
    }

    PCCERT_CONTEXT cert_context = CertCreateCertificateContext(X509_ASN_ENCODING, certdata, certlen);
    if (!cert_context) return GetLastError();

    // Add the certificate to the in-memory store
    if (!CertAddCertificateContextToStore(ctx->root_store, cert_context, CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
        DWORD error = GetLastError();
        CertFreeCertificateContext(cert_context);
        return error;
    }

    CertFreeCertificateContext(cert_context);
    return 0;
}

cslol_crypto_err cslol_crypto_import_extra_certs(cslol_crypto_ctx* ctx, const unsigned char* certdata, size_t certlen) {
    if (!ctx || (!certdata && certlen)) return STATUS_INVALID_PARAMETER;

    if (!ctx->extra_store) {
        HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, 0);
        if (!store) return GetLastError();
        ctx->extra_store = store;
    }

    CMSG_STREAM_INFO info = {0};
    HCRYPTMSG msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, CMSG_BARE_CONTENT_FLAG, 0, 0, 0, &info);

    if (!msg) return GetLastError();

    if (!CryptMsgUpdate(msg, certdata, certlen, TRUE)) {
        DWORD error = GetLastError();
        CryptMsgClose(msg);
        return error;
    }

    CryptMsgClose(msg);

    return 0;
}
