#ifndef CSLOL_DB_H
#define CSLOL_DB_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CSLSIG_MAGIC_HEADER = 0x4341bf7c,
    CSLSIG_MAGIC_WAD_V3 = 0xda91f42bu,
    CSLSIG_MAGIC_MOD_V0 = 0x8e48ed86u,
};

typedef struct cslol_mod_entry {
    uint64_t name;
    uint64_t checksum_compressed;
    uint64_t checksum_uncompressed;
} cslol_mod_entry;

typedef struct cslol_wad_entry_v3 {
    uint64_t name;
    uint64_t unused[2];
    uint64_t checksum;
} cslol_wad_entry_v3;

typedef union cslol_wad_provenance {
    struct {
        uint32_t toc_index;
        uint32_t entry_index;
    };
    volatile uint64_t one;
} cslol_wad_provenance;

typedef struct cslol_toc_mod_header {
    uint32_t magic;
    uint32_t reserved;
    unsigned char md[32];
    uint32_t entries_count;
    uint32_t sig_len;
} cslol_toc_mod_header;

typedef struct cslol_toc_wad_header {
    uint32_t magic;
    uint32_t reserved;
    unsigned char md_org[32];
    unsigned char md_new[32];
    unsigned char sig_org[256];
    uint32_t entries_org_count;
    uint32_t entries_new_count;
    uint32_t provenance;
} cslol_toc_wad_header;

typedef struct cslol_toc_mod {
    cslol_toc_mod_header header;
    cslol_mod_entry* entries;
    unsigned char* sig;
} cslol_toc_mod;

typedef struct cslol_toc_wad {
    cslol_toc_wad_header header;
    cslol_wad_entry_v3* entries_org;
    cslol_wad_entry_v3* entries_new;
    unsigned char* sig;
    cslol_wad_provenance* provenance;
} cslol_toc_wad;

typedef struct cslol_db_header {
    uint32_t magic;
    uint32_t toc_mods_count;
    uint32_t toc_wads_count;
    uint32_t certs;
} cslol_db_header;

typedef struct cslol_db {
    cslol_db_header header;
    cslol_toc_mod* toc_mods;
    cslol_toc_wad* toc_wads;
    unsigned char* certs;
} cslol_db;

// error type is a string, NULL string signifies no error
typedef const char* cslol_db_err;

// read databse from memory
extern cslol_db_err cslol_db_parse(cslol_db* db, const unsigned char* data, size_t data_size);

// free previously read database
extern void cslol_db_free(cslol_db* db);

// makes sure that every entry in entries_new is either found in entries_org or some mod entry
extern cslol_db_err cslol_wad_provenance_verify(const cslol_toc_wad* wad, const cslol_db* db);

// makes sure that every entry in entries_new is either found in entries_org or some mod entry
// modifies provenance in place, this function can be called from multiple threads
extern cslol_db_err cslol_wad_provenance_build(cslol_toc_wad* wad, const cslol_db* db);

#ifdef __cplusplus
}
#endif

#endif  // CSLOL_DB_H
