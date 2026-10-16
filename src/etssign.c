#include "etssign.h"
#include "sha1.h"

#include <ctype.h>
#include <string.h>

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_byte(const char *s, uint8_t *out) {
    int hi = hex_nibble(s[0]);
    int lo = hex_nibble(s[1]);
    if (hi < 0 || lo < 0) return -1;
    *out = (uint8_t)((hi << 4) | lo);
    return 0;
}

/*
 * Parse "851555f1-28bb-44de-9ea8-baac8bcd413d" into .NET's
 * Guid.ToByteArray() layout: Data1/Data2/Data3 little-endian, Data4 as the
 * 8 trailing bytes verbatim.
 */
static int parse_guid(const char *s, uint8_t out[16]) {
    size_t len = strlen(s);
    if (len != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-') {
        return -1;
    }

    uint8_t data1[4], data2[2], data3[2], data4[8];
    for (int i = 0; i < 4; i++) {
        if (hex_byte(s + 2 * i, &data1[i]) != 0) return -1;
    }
    for (int i = 0; i < 2; i++) {
        if (hex_byte(s + 9 + 2 * i, &data2[i]) != 0) return -1;
    }
    for (int i = 0; i < 2; i++) {
        if (hex_byte(s + 14 + 2 * i, &data3[i]) != 0) return -1;
    }
    for (int i = 0; i < 8; i++) {
        int off = i < 2 ? 19 + 2 * i : 24 + 2 * (i - 2);
        if (hex_byte(s + off, &data4[i]) != 0) return -1;
    }

    out[0] = data1[3]; out[1] = data1[2]; out[2] = data1[1]; out[3] = data1[0];
    out[4] = data2[1]; out[5] = data2[0];
    out[6] = data3[1]; out[7] = data3[0];
    memcpy(out + 8, data4, 8);
    return 0;
}

int ets_mask(const char *guid_str, const char *project_id, uint16_t *mask_out) {
    uint8_t guid[16];
    if (parse_guid(guid_str, guid) != 0) {
        return -1;
    }
    unsigned total = 0;
    for (int i = 0; i < 16; i++) {
        total += guid[i];
    }
    for (const unsigned char *p = (const unsigned char *)project_id; *p; p++) {
        total += *p;
    }
    *mask_out = (uint16_t)(total % 65536u);
    return 0;
}

void ets_hash(const uint8_t *file_bytes, size_t len, uint16_t mask,
               uint8_t out_digest[20]) {
    sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, file_bytes, len);
    sha1_final(&ctx, out_digest);

    uint8_t hi = (uint8_t)(mask >> 8);
    uint8_t lo = (uint8_t)(mask & 0xFF);
    for (int i = 0; i < 20; i++) {
        uint8_t mixed = (uint8_t)(out_digest[i] + 41);
        out_digest[i] = mixed ^ ((i % 2 == 0) ? hi : lo);
    }
}

static const char BASE64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void ets_hash_b64(const uint8_t *file_bytes, size_t len, uint16_t mask,
                    char out_b64[ETSSIGN_B64_LEN]) {
    uint8_t digest[20];
    ets_hash(file_bytes, len, mask, digest);

    int out = 0;
    size_t i = 0;
    for (; i + 3 <= 20; i += 3) {
        uint32_t chunk = ((uint32_t)digest[i] << 16) | ((uint32_t)digest[i + 1] << 8) | digest[i + 2];
        out_b64[out++] = BASE64_ALPHABET[(chunk >> 18) & 0x3F];
        out_b64[out++] = BASE64_ALPHABET[(chunk >> 12) & 0x3F];
        out_b64[out++] = BASE64_ALPHABET[(chunk >> 6) & 0x3F];
        out_b64[out++] = BASE64_ALPHABET[chunk & 0x3F];
    }
    size_t remaining = 20 - i;
    if (remaining == 1) {
        uint32_t chunk = (uint32_t)digest[i] << 16;
        out_b64[out++] = BASE64_ALPHABET[(chunk >> 18) & 0x3F];
        out_b64[out++] = BASE64_ALPHABET[(chunk >> 12) & 0x3F];
        out_b64[out++] = '=';
        out_b64[out++] = '=';
    } else if (remaining == 2) {
        uint32_t chunk = ((uint32_t)digest[i] << 16) | ((uint32_t)digest[i + 1] << 8);
        out_b64[out++] = BASE64_ALPHABET[(chunk >> 18) & 0x3F];
        out_b64[out++] = BASE64_ALPHABET[(chunk >> 12) & 0x3F];
        out_b64[out++] = BASE64_ALPHABET[(chunk >> 6) & 0x3F];
        out_b64[out++] = '=';
    }
    out_b64[out] = '\0';
}

/* Finds `name="value"` starting at or after `from` and copies value out. */
static const char *find_attr(const char *data, size_t len, const char *name,
                              char *out, size_t out_size) {
    size_t name_len = strlen(name);
    for (size_t i = 0; i + name_len + 2 < len; i++) {
        if (data[i] != name[0]) continue;
        if (memcmp(data + i, name, name_len) != 0) continue;
        size_t j = i + name_len;
        if (data[j] != '=' || data[j + 1] != '"') continue;
        j += 2;
        size_t k = 0;
        while (j < len && data[j] != '"' && k + 1 < out_size) {
            out[k++] = data[j++];
        }
        if (j >= len || data[j] != '"') continue;
        out[k] = '\0';
        return data + j + 1;
    }
    return NULL;
}

int ets_read_project_p(const char *p_file_bytes, size_t len, char *id_out,
                         size_t id_out_size, char *guid_out,
                         size_t guid_out_size) {
    if (find_attr(p_file_bytes, len, " Id", id_out, id_out_size) == NULL) {
        /* "Proj Id=" at the start of the file; " Id" matches "<Proj Id=". */
        return -1;
    }
    if (find_attr(p_file_bytes, len, "Guid", guid_out, guid_out_size) == NULL) {
        return -1;
    }
    return 0;
}
