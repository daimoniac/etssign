/*
 * etssign - recompute the per-file integrity hash ETS 5 and ETS 6 keep
 * next to each file in a ProjectStore directory. Both versions write the
 * ".ets5hash" companion with this recipe.
 *
 * Reverse engineered from Knx.Ets.ObjectModel.dll's HashedFileStream.Check
 * and FileProjectStore.set_ProjectGuid. Not related to, and does not touch,
 * the license dongle check.
 *
 * Recipe:
 *   mask = (sum(project_guid bytes, .NET Guid.ToByteArray order)
 *           + sum(utf8 bytes of project_id string)) mod 65536
 *   digest = SHA1(file_bytes)                       # 20 bytes
 *   digest[i] = (digest[i] + 41) mod 256             for all i
 *   digest[i] ^= (mask >> 8) & 0xFF   if i is even
 *   digest[i] ^= mask & 0xFF          if i is odd
 *   .ets5hash file content = base64(digest)
 */
#ifndef ETSSIGN_H
#define ETSSIGN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Base64 text of a 20-byte digest, as ETS writes it: 28 chars + NUL. */
#define ETSSIGN_B64_LEN 29

/*
 * Parse a dashed UUID string (e.g. "851555f1-28bb-44de-9ea8-baac8bcd413d")
 * and a project id string (e.g. "P-03C4") into the 16-bit mask ETS uses for
 * every file in that project. Returns 0 on success, -1 if guid_str is not a
 * well-formed UUID.
 */
int ets_mask(const char *guid_str, const char *project_id, uint16_t *mask_out);

/* Compute the raw 20-byte .ets5hash digest of file_bytes under mask. */
void ets_hash(const uint8_t *file_bytes, size_t len, uint16_t mask,
               uint8_t out_digest[20]);

/*
 * Compute the .ets5hash digest and base64-encode it the way ETS stores it
 * (no line breaks, standard alphabet, padded with '='). out_b64 must have
 * room for at least ETSSIGN_B64_LEN bytes; the result is NUL-terminated.
 */
void ets_hash_b64(const uint8_t *file_bytes, size_t len, uint16_t mask,
                    char out_b64[ETSSIGN_B64_LEN]);

/*
 * Scan a ProjectStore "P" file's raw bytes for Proj/@Id and ProjInfo/@Guid.
 * This is a plain string scan, not a real XML parser -- it only needs to
 * find two attributes in a file ETS itself writes in a stable, simple form.
 * id_out/guid_out must be at least 64 bytes. Returns 0 on success, -1 if
 * either attribute could not be found.
 */
int ets_read_project_p(const char *p_file_bytes, size_t len, char *id_out,
                         size_t id_out_size, char *guid_out,
                         size_t guid_out_size);

#ifdef __cplusplus
}
#endif

#endif
