#ifndef _TINY_AES_H_
#define _TINY_AES_H_

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

struct AES_ctx {
    uint32_t RoundKey[60]; // Nb * (Nr + 1) = 4 * 15 = 60 words for AES-256
    uint8_t Iv[AES_BLOCKLEN];
};

void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);
void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);
void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);

void AES_CTR_xcrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, size_t length);

#endif // _TINY_AES_H_
