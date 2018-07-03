/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 *  Description : SHA256-related functions
 */

/**
 * @file
 * SHA256-related functions
 *
 * Implements the SHA256 hashing function.
 */

#include "quark_sha256.h"

#define QUARK_SHA256_FINALCOUNT_SIZE      8
#define QUARK_SHA256_K_SIZE               64

/* If QUARK_USE_SHA256_C is defined then the C-version of SHA256 compression     */
/* funtion will be used, otherwise the ASM-version of the compression function */
/* will be used.                                                               */
#define QUARK_USE_SHA256_C

#ifdef QUARK_USE_SHA256_C
static const uint32_t K[QUARK_SHA256_K_SIZE] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


/**
 * Rotate x right by rot bits.
 *
 * @param[in] x    Value that is to be rotated.
 * @param[in] rot  Number of bits that value will be rotated by.
 *
 * @return Value rotated right by rot bits.
 */
static uint32_t RORc(uint32_t x, int rot) {
  rot &= 31;
  if (rot == 0)
    return x;
  uint32_t right = ((x & 0xFFFFFFFFUL) >> rot);
  uint32_t left = ((x & 0xFFFFFFFFUL) << (32 - rot));
  return (right | left) & 0xFFFFFFFFUL;
}

/* Define a number of logical functions used by SHA256 compression function */
#define Ch(x, y, z)       (z ^ (x & (y ^ z)))
#define Maj(x, y, z)      (((x | y) & z) | (x & y))
#define S(x, n)         RORc((x),(n))
#define R(x, n)         (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))


/**
 * Perform SHA256 compression function as per NIST standard.
 *
 * @param[out] ctx  Pointer to the context holding the current SHA256 state,
 *                  which will be updated by the compression operation.
 * @param[in]  buf  Pointer to the buffer holding the data that will be 
 *                  processed.
 *
 * @return void
 */
static void quark_sha256_c_compress(QUARK_SHA256_CTX* ctx, const void* buf) {
  uint32_t S0, S1, S2, S3, S4, S5, S6, S7, W[QUARK_SHA256_K_SIZE], t0, t1, t;
  int i;
  const uint8_t* p;

  /* Copy state into S */
  S0 = ctx->h[0];
  S1 = ctx->h[1];
  S2 = ctx->h[2];
  S3 = ctx->h[3];
  S4 = ctx->h[4];
  S5 = ctx->h[5];
  S6 = ctx->h[6];
  S7 = ctx->h[7];

  /*
   * We've been asked to perform the hash computation on this 512-bit string.
   * SHA256 interprets that as an array of 16 bigendian 32 bit numbers; copy
   * it, and convert it into 16 uint32_t's of the CPU's native format
   */
  p = buf;
  for (i = 0; i < 16; i++) {
    W[i] = readBigEndian(p, 4);
    p += 4;
  }

  /* fill W[16..63] */
  for (i = 16; i < QUARK_SHA256_K_SIZE; i++) {
    W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
  }

  /* Compress */
#define RND(a, b, c, d, e, f, g, h, i)                          \
    t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];     \
    t1 = Sigma0(a) + Maj(a, b, c);                      \
    d += t0;                                            \
    h  = t0 + t1;

  for (i = 0; i < QUARK_SHA256_K_SIZE; ++i) {
    RND(S0, S1, S2, S3, S4, S5, S6, S7, i);
    t = S7;
    S7 = S6;
    S6 = S5;
    S5 = S4;
    S4 = S3;
    S3 = S2;
    S2 = S1;
    S1 = S0;
    S0 = t;
  }
#undef RND

  /* feedback */
  ctx->h[0] += S0;
  ctx->h[1] += S1;
  ctx->h[2] += S2;
  ctx->h[3] += S3;
  ctx->h[4] += S4;
  ctx->h[5] += S5;
  ctx->h[6] += S6;
  ctx->h[7] += S7;
}

#else /* QUARK_USE_SHA256_C is NOT defined */
extern void quark_sha256_asm_compress(uint32_t *ctxH, uint8_t *ctxData);
#endif /* QUARK_USE_SHA256_C */

/**
 * Initializes a SHA256 context in preparation of performing a SHA256
 * operation.
 *
 * @param[out] ctx  Pointer to the context that will be initialized.
 *
 * @return void
 */
void quark_sha256_init(QUARK_SHA256_CTX* ctx) {
  ctx->Nl = 0;
  ctx->Nh = 0;
  ctx->num = 0;
  ctx->h[0] = 0x6A09E667UL;
  ctx->h[1] = 0xBB67AE85UL;
  ctx->h[2] = 0x3C6EF372UL;
  ctx->h[3] = 0xA54FF53AUL;
  ctx->h[4] = 0x510E527FUL;
  ctx->h[5] = 0x9B05688CUL;
  ctx->h[6] = 0x1F83D9ABUL;
  ctx->h[7] = 0x5BE0CD19UL;
}

/**
 * Performs incremental SHA256 hash operation.
 *
 * @param[out] ctx    Pointer to the context containing the current state
 *                    of the hashing operation, and may be updated if a
 *                    sufficient amount of source data is provided.
 * @param[in]  src    Pointer to the source data that will be processed
 *                    in this update.
 * @param[in]  count  Number of bytes of the source data that will be
 *                    added to the hash operation in this update.
 *
 * @return void
 */
void
quark_sha256_update(QUARK_SHA256_CTX* ctx, const void* src, uint32_t count) {
  uint32_t new_count = (ctx->Nl + (count << 3)) & 0xffffffff;
  if (new_count < ctx->Nl) {
    ctx->Nh += 1;
  }
  ctx->Nl = new_count;

  while (count) {
    uint32_t this_step = 64 - ctx->num;
    if (this_step > count) this_step = count;
    memcpy(ctx->data + ctx->num, src, this_step);

    if (this_step + ctx->num < 64) {
      ctx->num += this_step;
      break;
    }

    src = (const uint8_t*) src + this_step;
    count -= this_step;
    ctx->num = 0;

#ifdef QUARK_USE_SHA256_C
    quark_sha256_c_compress(ctx, ctx->data);
#else
    quark_sha256_asm_compress( ctx->h, ctx->data );
#endif
  }
}

/**
 * Finalizes the SHA256 operation pointed to by the context.
 *
 * @param[out] ctx     Pointer to the context containing the current state
 *                     of the hashing operation that will be finalized.
 * @param[out] digest  Pointer to where the result of the hash operation
 *                     will be written.
 *
 * @return void
 */
/*
 * Add padding and return the message digest.
 */
void quark_sha256_final(QUARK_SHA256_CTX* ctx, uint8_t* digest) {
  uint32_t i;
  uint8_t finalcount[QUARK_SHA256_FINALCOUNT_SIZE];

  writeBigEndian(&finalcount[0], ctx->Nh, 4);
  writeBigEndian(&finalcount[4], ctx->Nl, 4);

  quark_sha256_update(ctx, "\200", 1);

  if (ctx->num > 56) {
    quark_sha256_update(ctx, "\0\0\0\0\0\0\0\0", 8);
  }
  memset(ctx->data + ctx->num, 0, 56 - ctx->num);
  ctx->num = 56;
  quark_sha256_update(ctx,
                      finalcount,
                      QUARK_SHA256_FINALCOUNT_SIZE);  /* Should cause a sha256_compress() */

  /*
   * The final state is an array of uint32_t's; place them as a series
   * of bigendian 4-byte words onto the output
   */
  for (i = 0; i < 8; i++) {
    writeBigEndian(digest + 4 * i, ctx->h[i], 4);
  }
}
