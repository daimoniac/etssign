/*
 * Public domain SHA-1 implementation, originally by Steve Reid
 * <steve@edmweb.com>, with 1995-2010 contributions folded in by various
 * authors into the version widely circulated as public domain (e.g. the one
 * shipped with Mozilla, Git, and PuTTY). Adapted here only for formatting.
 */
#include "sha1.h"

#include <string.h>

#define ROL32(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t block[80];
    for (int i = 0; i < 16; i++) {
        block[i] = ((uint32_t)buffer[i * 4] << 24) |
                   ((uint32_t)buffer[i * 4 + 1] << 16) |
                   ((uint32_t)buffer[i * 4 + 2] << 8) |
                   ((uint32_t)buffer[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
        block[i] = ROL32(block[i - 3] ^ block[i - 8] ^ block[i - 14] ^ block[i - 16], 1);
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        uint32_t temp = ROL32(a, 5) + f + e + k + block[i];
        e = d;
        d = c;
        c = ROL32(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void sha1_init(sha1_ctx *ctx) {
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xEFCDAB89u;
    ctx->state[2] = 0x98BADCFEu;
    ctx->state[3] = 0x10325476u;
    ctx->state[4] = 0xC3D2E1F0u;
    ctx->count[0] = 0;
    ctx->count[1] = 0;
}

void sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len) {
    size_t have = (size_t)((ctx->count[0] >> 3) & 0x3F);
    uint32_t bits_added_low = (uint32_t)(len << 3);
    ctx->count[0] += bits_added_low;
    if (ctx->count[0] < bits_added_low) {
        ctx->count[1]++;
    }
    ctx->count[1] += (uint32_t)(len >> 29);

    size_t i = 0;
    if (have) {
        size_t need = 64 - have;
        if (len < need) {
            memcpy(ctx->buffer + have, data, len);
            return;
        }
        memcpy(ctx->buffer + have, data, need);
        sha1_transform(ctx->state, ctx->buffer);
        i = need;
    }
    for (; i + 64 <= len; i += 64) {
        sha1_transform(ctx->state, data + i);
    }
    memcpy(ctx->buffer, data + i, len - i);
}

void sha1_final(sha1_ctx *ctx, uint8_t digest[20]) {
    uint8_t finalcount[8];
    for (int i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((ctx->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 0xFF);
    }

    uint8_t pad = 0x80;
    sha1_update(ctx, &pad, 1);
    uint8_t zero = 0x00;
    while ((ctx->count[0] & 0x1F8) != 448) {
        sha1_update(ctx, &zero, 1);
    }
    sha1_update(ctx, finalcount, 8);

    for (int i = 0; i < 20; i++) {
        digest[i] = (uint8_t)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 0xFF);
    }
}
