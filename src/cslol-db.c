#include "cslol-db.h"

#include <stdlib.h>
#include <string.h>

cslol_db_err cslol_db_parse(cslol_db* db, const unsigned char* data, size_t size) {
    size_t pos = 0;
    size_t req = 0;

#define ALLOC(ptr, count)                        \
    (ptr) = calloc((count) | 1, sizeof(*(ptr))); \
    if (!(ptr)) return "cslol_db_read calloc failed " #ptr;

#define READ(ptr, count)                                              \
    req = sizeof(*(ptr)) * count;                                     \
    if (req > (size - pos)) return "cslol_db_read read failed " #ptr; \
    memcpy_s((ptr), req, data + pos, req);                            \
    pos += req;

    READ(&db->header, 1);
    if (db->header.magic != CSLSIG_MAGIC_HEADER) return "cslol_db_parse bad header magic";

    ALLOC(db->toc_mods, db->header.toc_mods_count);
    for (uint32_t i = 0; i < db->header.toc_mods_count; ++i) {
        cslol_toc_mod* mod = &db->toc_mods[i];

        READ(&mod->header, 1);
        if (mod->header.magic != CSLSIG_MAGIC_MOD_V0) return "cslol_db_parse bad mod magic";

        ALLOC(mod->entries, mod->header.entries_count);
        READ(mod->entries, mod->header.entries_count);

        ALLOC(mod->sig, mod->header.sig_len);
        READ(mod->sig, mod->header.sig_len);
    }

    ALLOC(db->toc_wads, db->header.toc_wads_count);
    for (uint32_t i = 0; i < db->header.toc_wads_count; ++i) {
        cslol_toc_wad* wad = &db->toc_wads[i];

        READ(&wad->header, 1);
        if (wad->header.magic != CSLSIG_MAGIC_WAD_V3) return "cslol_db_parse bad wad magic";

        ALLOC(wad->entries_org, wad->header.entries_org_count);
        READ(wad->entries_org, wad->header.entries_org_count);

        ALLOC(wad->entries_new, wad->header.entries_new_count);
        READ(wad->entries_new, wad->header.entries_new_count);

        if (wad->header.provenance) {
            ALLOC(wad->provenance, wad->header.provenance);
            READ(wad->provenance, wad->header.provenance);
        } else {
            // make provenance optional (we can rebuild it latter)
            wad->header.provenance = wad->header.entries_new_count;
            ALLOC(wad->provenance, wad->header.provenance);
        }
    }

    ALLOC(db->certs, db->header.certs);
    READ(db->certs, db->header.certs);

#undef READ
#undef ALLOC
    return NULL;
}

void cslol_db_free(cslol_db* db) {
    if (!db) return;

    if (db->toc_wads) {
        for (size_t i = db->header.toc_wads_count; --i;) {
            cslol_toc_wad* wad = &db->toc_wads[i];
            free(wad->provenance);
            free(wad->sig);
            free(wad->entries_new);
            free(wad->entries_org);
        }
        free(db->toc_wads);
    }

    if (db->toc_mods) {
        for (size_t i = db->header.toc_mods_count; --i;) {
            cslol_toc_mod* mod = &db->toc_mods[i];
            free(mod->sig);
            free(mod->entries);
        }
        free(db->toc_mods);
    }

    free(db->certs);

    memset(db, 0, sizeof(*db));
}

cslol_db_err cslol_wad_provenance_build(cslol_toc_wad* wad, const cslol_db* db) {
    if (!wad || (!db->toc_mods && db->header.toc_mods_count) || (!wad->provenance && wad->header.provenance))
        return "cslol_wad_provenance_build invalid argument";
    if (wad->header.provenance != wad->header.entries_new_count)
        return "cslol_wad_provenance_build provenance count mismatch";

    // We iterate all mod entries in locks with new entries and orginal wad.
    uint32_t* counter = calloc(db->header.toc_mods_count | 1, sizeof(uint32_t));
    for (uint32_t i = 0, j = 0; i != wad->header.entries_new_count; ++i) {
        cslol_wad_provenance* prov = &wad->provenance[i];
        const cslol_wad_entry_v3* new_entry = &wad->entries_new[i];

        // Sanity check that new entries are sorted by name hash.
        if (i && new_entry[0].name <= new_entry[-1].name) {
            free(counter);
            return "cslol_wad_provenance entries_new unsorted";
        }

        int found = 0;

        // Advance original wad entries
        while (j != wad->header.entries_org_count) {
            const cslol_wad_entry_v3* org_entry = &wad->entries_org[j];

            // Ensure that original entries are sorted as well.
            if (j && org_entry[0].name <= org_entry[-1].name) {
                free(counter);
                return "cslol_wad_provenance_build entires_org unsorted";
            }

            // New entry has same name and hash as original entry!
            if (org_entry[0].name == new_entry[0].name && org_entry[0].checksum == new_entry[0].checksum) {
                // Mark provenance of new entry as original wad (-1) with entry index `j`.
                cslol_wad_provenance new_prov = {{-1, j}};
                *prov = new_prov;  // lame atempt at making this atomic
                found = 1;
            }

            // Consume all entries up to and including this one.
            if (org_entry[0].name > new_entry[0].name) break;
            ++j;
        }

        for (uint32_t m = 0; m != db->header.toc_mods_count; ++m) {
            uint32_t k = counter[m];
            while (k != wad->header.entries_org_count) {
                const cslol_mod_entry* mod_entry = &db->toc_mods[m].entries[k];

                // Ensure that mod entries are sorted as well.
                if (k && mod_entry[0].name <= mod_entry[-1].name) {
                    free(counter);
                    return "cslol_wad_provenance_build mad entires unsorted";
                }

                // New entry has same name and hash as mod entry!
                if (mod_entry[0].name == new_entry[0].name &&
                    (mod_entry[0].checksum_compressed == new_entry[0].checksum ||
                     mod_entry[0].checksum_uncompressed == new_entry[0].checksum)) {
                    // Mark provenance of new entry as mod `m + 1` with entry index `k`.
                    cslol_wad_provenance new_prov = {{m + 1, k}};
                    *prov = new_prov;
                    found = 1;
                }

                // Consume all entries up to and including this one.
                if (mod_entry[0].name > new_entry[0].name) break;

                ++k;
            }
            counter[m] = k;
        }

        if (!found) {
            free(counter);
            return "cslol_wad_provenance_build not found";
        }
    }

    free(counter);
    return NULL;
}

cslol_db_err cslol_wad_provenance_verify(const cslol_toc_wad* wad, const cslol_db* db) {
    if (!wad || (!db->toc_mods && db->header.toc_mods_count) || (!wad->provenance && wad->header.provenance))
        return "cslol_wad_provenance_verify invalid argument";
    if (wad->header.provenance != wad->header.entries_new_count) return "cslol_wad_provenance_verify count mismatch";

    for (uint32_t i = 0; i != wad->header.entries_new_count; ++i) {
        const cslol_wad_provenance prov = wad->provenance[i];
        const cslol_wad_entry_v3 new_entry = wad->entries_new[i];

        // Toc index should never be zero
        if (prov.toc_index == 0) {
            return "cslol_wad_provenance_verify not built";
        } else if (prov.toc_index == 0xFFFFFFFF) {
            // Verify against entries_org
            if (prov.entry_index >= wad->header.entries_org_count)
                return "cslol_wad_provenance_verify entries_org out of range";

            const cslol_wad_entry_v3 org_entry = wad->entries_org[i];
            if (new_entry.name != org_entry.name || new_entry.checksum != org_entry.checksum) {
                return "cslol_wad_provenance_verify entries_org mismatch";
            }
        } else if (prov.toc_index <= db->header.toc_mods_count) {
            // Verify against mod
            if (prov.entry_index >= db->toc_mods[prov.toc_index - 1].header.entries_count)
                return "cslol_wad_provenance_verify entries_mod out of range";

            const cslol_mod_entry mod_entry = db->toc_mods[prov.toc_index - 1].entries[prov.entry_index];
            if (new_entry.name != mod_entry.name || (new_entry.checksum != mod_entry.checksum_compressed &&
                                                     new_entry.checksum != mod_entry.checksum_uncompressed)) {
                return "cslol_wad_provenance_verify mod_entry mismatch";
            }
        } else {
            return "cslol_wad_provenance_verify not found";
        }
    }

    return NULL;
}
