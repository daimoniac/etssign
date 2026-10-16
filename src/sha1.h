/* Public domain SHA-1, originally by Steve Reid <steve@edmweb.com>. */
#ifndef ETS5SIGN_SHA1_H
#define ETS5SIGN_SHA1_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} sha1_ctx;

void sha1_init(sha1_ctx *ctx);
void sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len);
void sha1_final(sha1_ctx *ctx, uint8_t digest[20]);

#endif
