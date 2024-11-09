#ifndef CSLOL_CRYPTO_H
#define CSLOL_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

// crypto context, necessary for all operations
typedef struct cslol_crypto_ctx cslol_crypto_ctx;

// error type, 0 means no error
typedef long cslol_crypto_err;

// initialize verification context
extern cslol_crypto_err cslol_crypto_ctx_create(cslol_crypto_ctx** out_ctx);

// free previously initializer context
extern void cslol_crypto_ctx_free(cslol_crypto_ctx* ctx);

// verify wad entires are same as provided sha256 mds
extern cslol_crypto_err cslol_crypto_sha256(cslol_crypto_ctx* ctx,
                                            const unsigned char* data,
                                            size_t len,
                                            unsigned char md[32]);

// load public key for wad verification
extern cslol_crypto_err cslol_crypto_import_rsa_pub(cslol_crypto_ctx* ctx, const unsigned char* pk, size_t pklen);

// verify pub key signature
extern cslol_crypto_err cslol_crypto_verify_pkcs15_rsa_sha256(cslol_crypto_ctx* ctx,
                                                              const unsigned char* sig,
                                                              size_t siglen,
                                                              const unsigned char md[32]);

// import pre-trusted root certificate
extern cslol_crypto_err cslol_crypto_import_root_cert(cslol_crypto_ctx* ctx,
                                                      const unsigned char* certdata,
                                                      size_t certlen);

// import untrusted intermediates from pkcs7 blob (might enforce CRL presence)
extern cslol_crypto_err cslol_crypto_import_extra_certs(cslol_crypto_ctx* ctx,
                                                        const unsigned char* certdata,
                                                        size_t certlen);

#ifdef __cplusplus
}
#endif

#endif  // CSLOL_CRYPTO_H
