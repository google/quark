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

#ifndef _QUARK_HASH_H_
#define _QUARK_HASH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "endian_utils.h"
#include "sha256.h"

/*----------------------------------------------------------------------------------------------------*/
/* Type Definitions */
/*----------------------------------------------------------------------------------------------------*/
enum {
  HASH_SHA256 = 1
};

union hash_ctx {
  QUARK_SHA256_CTX sha256;
};

/*----------------------------------------------------------------------------------------------------*/
/* Function Prototypes */
/*----------------------------------------------------------------------------------------------------*/
void quark_hashInit(uint32_t hashAlgorithm, union hash_ctx* ctx);
void quark_hashUpdate(uint32_t hashAlgorithm,
                      union hash_ctx* ctx,
                      const void* src,
                      size_t srcLen);
void quark_hashFinal(uint32_t hashAlgorithm, union hash_ctx* ctx, void* dst);
void quark_hash(uint32_t hashAlgorithm,
                union hash_ctx* ctx,
                void* dst,
                const void* src,
                size_t srcLen);

#ifdef __cplusplus
}
#endif

#endif /* _QUARK_HASH_H */
