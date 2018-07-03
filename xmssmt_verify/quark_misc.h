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
 *  Description : Miscellaneous functions used for debugging and development.
 */

#ifndef _QUARK_MISC_H_
#define _QUARK_MISC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "quark_verify.h"

#define  MAX_PREFIX_LEN   100

/*----------------------------------------------------------------------------------------------------*/
/* Function prototypes */
/*----------------------------------------------------------------------------------------------------*/
void printVector(char* prefix, uint8_t* src, int len, int lineLen);
void printAdrs(const uint32_t* adrs);
void printParams(const xmssmt_params_t* params);
void printXmssOid(const uint32_t oidVal);
void printXmssmtOid(const uint32_t oidVal);
sig_retcode_t compute(const uint8_t funcType,
                      uint8_t* out,
                      const uint8_t* key,
                      const uint32_t keyLen,
                      uint8_t* m0,
                      const uint8_t* m1,
                      const uint32_t mLen,
                      const xmssmt_params_t* params);
sig_retcode_t ltreeBig(uint8_t* pk0,
                       uint8_t* publicKey,
                       const uint8_t* SEED,
                       uint32_t* ADRS,
                       const xmssmt_params_t* params);
sig_retcode_t ltreeSmall(uint8_t* pk0,
                         uint8_t* publicKey,
                         const uint8_t* SEED,
                         uint32_t* ADRS,
                         const xmssmt_params_t* params);
sig_retcode_t otsPkFromSig(uint8_t* computedPk,
                           const uint8_t* message,
                           const uint8_t* signature,
                           const uint8_t* SEED,
                           uint32_t* ADRS,
                           const xmssmt_params_t* params);
sig_retcode_t otsVerifySignature(const void* message,
                                 size_t messageLen,
                                 const uint8_t* signature,
                                 size_t signatureLen,
                                 const uint8_t* publicKey,
                                 size_t publicKeyLen,
                                 const uint8_t* SEED,
                                 uint32_t* ADRS,
                                 const xmssmt_params_t* params);

#ifdef __cplusplus
}
#endif

#endif /* _QUARK_MISC_H */
