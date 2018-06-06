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

#ifndef _C4A_VERIFY_H_
#define _C4A_VERIFY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "c4a_sha256.h"
#include "c4a_hash.h"
#include "c4a_endian.h"

/*----------------------------------------------------------------------------------------------------*/
/* Constant Definitions */
/*----------------------------------------------------------------------------------------------------*/

/* Limit constants */
#define I_LEN                       16   // # of bytes to specify key identifier
#define q_LEN                       4    // # of bytes to specify node number q
#define D_LEN                       2    // # of bytes to specify D_PBLC/D_LEAF/D_MESG/D_INTR/etc.
#define p_LEN                       2    // # of bytes to specify p
#define i_LEN                       2    // # of bytes to specify outer W-OTS iteration count (i)
#define j_LEN                       1    // # of bytes to specify inner W-OTS iteration count (j)
#define L_LEN                       4    // # of bytes to specify multi-tree level count L
#define TYPE_LEN                    4    // # of bytes to specify otsType, lmsType, etc.
#define MAX_HASH_LEN                32   // Maximum # of bytes in hash function output
#define HSS_MAX_LEVELS              8    // Maximum number of levels in HSS format
#define HSS_MIN_LEVELS              1    // Minimum number of levels in HSS format

/*                                             Hash  m  h  */
/* Defined LM parameter sets (v8)             ------ -- -- */
#define LMS_SHA256_M32_H5           0x00000005  // SHA256 32  5
#define LMS_SHA256_M32_H10          0x00000006  // SHA256 32 10
#define LMS_SHA256_M32_H15          0x00000007  // SHA256 32 15
#define LMS_SHA256_M32_H20          0x00000008  // SHA256 32 20
#define LMS_SHA256_M32_H25          0x00000009  // SHA256 32 25

/*                                             Hash  n  w  p  ls */
/* LM-OTS registry (v8)                       ------ -- - --- -- */
#define LMOTS_SHA256_N32_W1         0x00000001  /* SHA256 32 1 265 7  */
#define LMOTS_SHA256_N32_W2         0x00000002  /* SHA256 32 2 133 6  */
#define LMOTS_SHA256_N32_W4         0x00000003  /* SHA256 32 4  67 4  */
#define LMOTS_SHA256_N32_W8         0x00000004  /* SHA256 32 8  34 0  */

/* OTS hash format */
#define OTS_I_OFFSET                0
#define OTS_q_OFFSET                I_LEN
#define OTS_i_OFFSET                ( I_LEN + q_LEN )
#define OTS_j_OFFSET                ( I_LEN + q_LEN + i_LEN )
#define OTS_TMP_OFFSET              ( I_LEN + q_LEN + i_LEN + j_LEN )
#define OTS_OFFSET( len )           ( OTS_TMP_OFFSET + ( len ) )
#define OTS_MAX_LEN                 OTS_OFFSET( MAX_HASH_LEN )

/* OTS Kc hash format (only need to specify D/Z locations as we'll be sharing */
/* the OTS hash buffer and the I q fields remain the same)                    */
#define OTS_D_OFFSET                ( I_LEN + q_LEN )
#define OTS_Z_OFFSET                ( I_LEN + q_LEN + D_LEN )

/* Merkle tree internal nodes hashing format */
#define TREEINT_I_OFFSET            0                      // unused
#define TREEINT_q_OFFSET            I_LEN                  // unused
#define TREEINT_D_OFFSET            ( I_LEN + q_LEN )      // unused
#define TREEINT_PK_OFFSET           ( I_LEN + q_LEN + D_LEN )
#define TREEINT_OFFSET( len )       ( TREEINT_PK_OFFSET + 2 * ( len ) )
#define TREEINT_MAX_LEN             TREEINT_OFFSET( MAX_HASH_LEN )

/* Merkle tree leaf nodes hashing format */
#define TREELEAF_I_OFFSET           0
#define TREELEAF_q_OFFSET           I_LEN
#define TREELEAF_D_OFFSET           ( I_LEN + q_LEN )
#define TREELEAF_PK_OFFSET          ( I_LEN + q_LEN + D_LEN )
#define TREELEAF_OFFSET( len )      ( TREELEAF_PK_OFFSET + ( len ) )
#define TREELEAF_MAX_LEN            TREELEAF_OFFSET( MAX_HASH_LEN )

/* Message hasing format */
#define MSG_I_OFFSET                0
#define MSG_q_OFFSET                I_LEN
#define MSG_D_OFFSET                ( I_LEN + q_LEN )
#define MSG_C_OFFSET                ( I_LEN + q_LEN + D_LEN )
#define MSG_MSG_OFFSET( len )       ( I_LEN + q_LEN + D_LEN + ( len ) )
#define MSG_MAX_LEN                 MSG_MSG_OFFSET( MAX_HASH_LEN )

/* OTS Public Key format */
#define OTS_KEY_TYPE_OFFSET         0
#define OTS_KEY_I_OFFSET            TYPE_LEN
#define OTS_KEY_q_OFFSET            ( TYPE_LEN + I_LEN )
#define OTS_KEY_K_OFFSET            ( TYPE_LEN + I_LEN + q_LEN )
#define OTS_KEY_OFFSET( n )         ( TYPE_LEN + I_LEN + q_LEN + ( n ) )

/* OTS Signature format */
#define OTS_SIG_TYPE_OFFSET         0
#define OTS_SIG_C_OFFSET            TYPE_LEN
#define OTS_SIG_Y_OFFSET( n )       ( TYPE_LEN + ( n ) )
#define OTS_SIG_OFFSET( n, p )      ( TYPE_LEN + ( n ) * ( ( p ) + 1 ) )

/* LMS Public Key format */
#define LMS_KEY_LMS_TYPE_OFFSET     0
#define LMS_KEY_OTS_TYPE_OFFSET     TYPE_LEN
#define LMS_KEY_I_OFFSET            ( TYPE_LEN + TYPE_LEN )
#define LMS_KEY_T1_OFFSET           ( TYPE_LEN + TYPE_LEN + I_LEN )

/* LMS Signature format */
#define LMS_SIG_q_OFFSET            0
#define LMS_SIG_OTS_SIG_OFFSET      q_LEN
#define LMS_SIG_TYPE_OFFSET( n, p ) ( q_LEN + OTS_SIG_OFFSET( ( n ), ( p ) ) )
#define LMS_SIG_P0_OFFSET( n, p )   ( LMS_SIG_TYPE_OFFSET( ( n ), ( p ) ) + TYPE_LEN )

/* HSS Public Key format */
#define HSS_KEY_LEVELS_OFFSET       0
#define HSS_KEY_LMS_KEY_OFFSET      L_LEN

/* HSS Signature format */
#define HSS_SIG_LEVELS_OFFSET       0
#define HSS_SIG_CHAIN_OFFSET        L_LEN

/* D contstants */
#define D_PBLC                      0x8080
#define D_MESG                      0x8181
#define D_LEAF                      0x8282
#define D_INTR                      0x8383


/*----------------------------------------------------------------------------------------------------*/
/* Type Definitions */
/*----------------------------------------------------------------------------------------------------*/
    typedef enum {
        SIG_OK = 0,
        SIG_INVALID_SIG,
        SIG_INVALID_PARAM,
        SIG_INVALID_LMS_KEY_LEN,
        SIG_INVALID_LMS_SIG_LEN,
        SIG_INVALID_LMS_TYPE,
        SIG_INVALID_LMS_NODE,
        SIG_INVALID_OTS_KEY_LEN,
        SIG_INVALID_OTS_SIG_LEN,
        SIG_INVALID_OTS_TYPE,
        SIG_INVALID_HSS_KEY_LEN,
        SIG_INVALID_HSS_SIG_LEN,
        SIG_INVALID_HSS_LEVELS,
        SIG_FLASH_READ_ERROR,
        SIG_INSUFFICIENT_MEMORY,
        SIG_UNSUPPORTED_OID,
        SIG_NUM_RETCODES
    } sig_retcode_t;

    typedef uint32_t merkle_index_t;
    typedef uint32_t param_set_t;
    typedef uint64_t sequence_t;

/* Define dummy enumerated data type and callback type */
    typedef enum
    {
        DEFAULT_FLASH = 0
    } nlflash_id_t;
    typedef void * nlloop_callback_fp;

/*----------------------------------------------------------------------------------------------------*/
/* Define global variables */
/*----------------------------------------------------------------------------------------------------*/
/* FLASH device definition */
#define C4A_FLASH_SIZE  65536
    uint8_t g_flashBuff[C4A_FLASH_SIZE];
    uint32_t g_flashCnt;

/* FLASH cache definition */
#define  C4A_USE_FLASH_CACHE
#define  C4A_CACHE_SIZE     256
    uint32_t g_cacheStart;
    uint32_t g_cacheEnd;
    uint8_t  g_cache[C4A_CACHE_SIZE];
    uint32_t g_flashBytesRead;

/* Scratch buffer definition */
#define  C4A_SCRATCH_SIZE   295

/*----------------------------------------------------------------------------------------------------*/
/* Function prototypes */
/*----------------------------------------------------------------------------------------------------*/

    size_t otsSignatureLen( param_set_t otsType );
    size_t otsPublicKeyLen( param_set_t otsType );
    uint32_t otsCoeff( const uint8_t *S, uint32_t i, uint32_t w );
    void otsComputeChecksum( uint8_t *checksum, uint8_t *value, uint32_t valueLen, uint32_t w, uint32_t ls );
    sig_retcode_t otsParameterLookup( param_set_t otsType, uint32_t *H, uint32_t *n, uint32_t *w, uint32_t *p, uint32_t *ls );
    sig_retcode_t otsComputeKc( uint8_t *computedKc, const uint8_t *I, merkle_index_t q, const void *message,
                                size_t messageLen, const uint8_t *signature, size_t signatureLen, param_set_t pubType );
    size_t lmsSignatureLen( param_set_t lmsType, param_set_t otsType );
    size_t lmsPublicKeyLen( param_set_t lmsType );
    sig_retcode_t lmsParameterLookup( param_set_t lmsType, uint32_t *H, uint32_t *m, uint32_t *h );
    sig_retcode_t lmsVerifySignature( const void *message, size_t messageLen, const uint8_t *signature,
                                      size_t signatureLen, const uint8_t *publicKey, size_t publicKeyLen );
    sig_retcode_t hssVerifySignature( const void *message, size_t messageLen, const uint8_t *signature,
                                      size_t signatureLen, const uint8_t *publicKey, size_t publicKeyLen );

/* Flash emulation and scratch buff based variants */
    int nlflash_read(nlflash_id_t flash_id, uint32_t from, size_t len, size_t *retlen, uint8_t *buf, nlloop_callback_fp callback);
#ifdef C4A_USE_FLASH_CACHE
    sig_retcode_t flashcpy_cached( uint8_t *buf, uint32_t offset, size_t len );
#else
    sig_retcode_t flashcpy( uint8_t *buf, uint32_t offset, size_t len );
#endif
    sig_retcode_t otsComputeKcFlash( uint8_t *computedKc, const uint8_t *I, merkle_index_t q, const void *message, size_t messageLen,
                                     uint32_t signatureOffset, size_t signatureLen, param_set_t pubType, uint8_t *scratchBuff, size_t scratchLen );
    sig_retcode_t lmsVerifySignatureFlash( const void *message, size_t messageLen, uint32_t signatureOffset, size_t signatureLen,
                                           const uint8_t *publicKey, size_t publicKeyLen, uint8_t *scratchBuff, size_t scratchLen );
    sig_retcode_t hssVerifySignatureFlash( const void *message, size_t messageLen, uint32_t signatureOffset, size_t signatureLen,
                                           const uint8_t *publicKey, size_t publicKeyLen, uint8_t *scratchBuff, size_t scratchLen );

#ifdef __cplusplus
}
#endif    

#endif /* _C4A_VERIFY_H_ */
