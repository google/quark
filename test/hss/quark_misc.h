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

#include "hss_verify.h"

#define  MAX_PREFIX_LEN   100

/*----------------------------------------------------------------------------------------------------*/
/* Function prototypes */
/*----------------------------------------------------------------------------------------------------*/
void printVector(char* str, uint8_t* v, size_t len, int lineLen);
void printLmsType(char* str, uint32_t typeCode);
void printOtsType(char* str, uint32_t typeCode);
void printOtsSignature(char* prefix, uint8_t* sig, uint32_t* n, uint32_t* p);
void printLmsPublicKey(char* prefix, uint8_t* key, uint32_t* n);
void printLmsSignature(char* prefix,
                       uint8_t* sig,
                       uint32_t* n,
                       uint32_t* p,
                       uint32_t* m,
                       uint32_t* h);
void printHssPublicKey(uint8_t* key);
void printHssSignature(uint8_t* sig);
sig_retcode_t otsVerifySignature(const void* message,
                                 size_t messageLen,
                                 const unsigned char* signature,
                                 size_t signatureLen,
                                 const unsigned char* publicKey,
                                 size_t publicKeyLen);
sig_retcode_t
lmsValidatePublicKey(const unsigned char* publicKey, size_t publicKeyLen);
sig_retcode_t
otsValidatePublicKey(const unsigned char* publicKey, size_t publicKeyLen);

#ifdef __cplusplus
}
#endif

#endif /* _QUARK_MISC_H_ */
