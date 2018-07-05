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
 *  Description : HSS verification methods and supporting functions
 */

#ifndef _QUARK_SHA256_H_
#define _QUARK_SHA256_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdint.h>
#include "endian_utils.h"


/* If QUARK_USE_SHA256_C is defined then the C-version of SHA256 compression     */
/* funtion will be used, otherwise the ASM-version of the compression function */
/* will be used.                                                               */
#define QUARK_USE_SHA256_C

/*----------------------------------------------------------------------------------------------------*/
/* Constant Definitions */
/*----------------------------------------------------------------------------------------------------*/

/* Length of a SHA256 hash */
#define QUARK_SHA256_LEN        32

/*----------------------------------------------------------------------------------------------------*/
/* Type Definitions */
/*----------------------------------------------------------------------------------------------------*/

/* SHA256 context. */
typedef struct {
  uint32_t h[8];                 /* state; this is in the CPU native format */
  uint32_t Nl, Nh;               /* number of bits processed so far */
  uint32_t num;                  /* number of bytes within the below buffer */
  uint8_t
      data[64];             /* input buffer.  This is in byte vector format */
} QUARK_SHA256_CTX;

/*----------------------------------------------------------------------------------------------------*/
/* Function prototypes */
/*----------------------------------------------------------------------------------------------------*/
void quark_sha256_init(QUARK_SHA256_CTX*);  /* context */

void quark_sha256_update(QUARK_SHA256_CTX*, /* context */
                         const void*,     /* input block */
                         uint32_t);        /* length of input block */

void quark_sha256_final(QUARK_SHA256_CTX*,  /* context */
                        uint8_t*);        /* output buffer where results will be written */

#ifdef __cplusplus
}
#endif

#endif /* _QUARK_SHA256_H_ */

