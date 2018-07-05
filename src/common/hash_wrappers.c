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
 *  Description : All wrapper functions related to performing hashing.
 */

/**
 * @file
 * All wrapper functions related to performing hashing.
 *
 */
#include "hash_wrappers.h"


/**
 * Initializes the given context for the given hash algorithm.  We may want to
 * optimize this out since SHA256 is the only valid algorithm at this point.
 *
 * @param[in]  hashAlgorithm  Identifies the hash function to be used.
 * @param[out] ctx            Pointer to the hash context that is being initialized.
 *
 * @return void
 */
void quark_hashInit(
    uint32_t hashAlgorithm,
    union hash_ctx* ctx) {
  /* Ensure we have a valid context */
  if (ctx) {
    switch (hashAlgorithm) {
      case HASH_SHA256:
        quark_sha256_init(&ctx->sha256);
    }
  }
}


/**
 * Incremental hashing of the given source byte array and hash context.  We may
 * want to optimize this out since SHA256 is the only valid algorithm at this point.
 *
 * @param[in]  hashAlgorithm  Identifies the hash function to be used.
 * @param[out] ctx            Pointer to the hash context that is being updated.
 * @param[in]  src            Pointer to the byte vector that is being incrementally
 *                            hashed.
 * @param[in]  srcLen         Length in bytes of the source array being incrementally
 *                            hashed.
 *
 * @return void
 */
void quark_hashUpdate(
    uint32_t hashAlgorithm,
    union hash_ctx* ctx,
    const void* src,
    size_t srcLen) {
  if (ctx && src) {
    switch (hashAlgorithm) {
      case HASH_SHA256:
        quark_sha256_update(&ctx->sha256, src, srcLen);
        break;
    }
  }
}


/**
 * Finalizes the hash operation represented by the given context and writes the
 * result to the given destination array.  We may want to optimize this out since
 * SHA256 is the only valid algorithm at this point.
 *
 * @param[in]  hashAlgorithm  Identifies the hash function to be used.
 * @param[in]  ctx            Pointer to the hash context that is being finalized.
 * @param[out] dst            Pointer to where the hash result will be written.
 *
 * @return void
 */
void quark_hashFinal(
    uint32_t hashAlgorithm,
    union hash_ctx* ctx,
    void* dst) {
  if (ctx && dst) {
    switch (hashAlgorithm) {
      case HASH_SHA256:
        quark_sha256_final(&ctx->sha256, dst);
        break;
    }
  }
}


/**
 * A self-contained hash operation that abstracts away the init/update/final
 * operations such that it performs a complete hash on the source array, and
 * writes the result to the given destination.
 *
 * @param[in]  hashAlgorithm  Identifies the hash function to be used.
 * @param[out] ctx            Pointer to the hash context that is being finalized.
 * @param[out] dst            Pointer to where the hash result will be written.
 * @param[in]  src            Pointer to the byte vector that is being hashed.
 * @param[in]  srcLen         Length in bytes of the source array being hashed.
 *
 * @return void
 */
void quark_hash(
    uint32_t hashAlgorithm,
    union hash_ctx* ctx,
    void* dst,
    const void* src,
    size_t srcLen) {
  if (ctx && dst && src) {
    switch (hashAlgorithm) {
      case HASH_SHA256:
        quark_sha256_init(&ctx->sha256);
        quark_sha256_update(&ctx->sha256, src, srcLen);
        quark_sha256_final(&ctx->sha256, dst);
        break;
    }
  }
}
