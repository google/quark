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

#ifndef _C4A_VERIFY_H_
#define _C4A_VERIFY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "c4a_sha256.h"
#include "c4a_endian.h"

/*----------------------------------------------------------------------------------------------------*/
/* Constant Definitions */
/*----------------------------------------------------------------------------------------------------*/

/* ADRS array offsets */
#define   ADRS_LAYER                   0
#define   ADRS_TREE1                   1
#define   ADRS_TREE0                   2
#define   ADRS_TYPE                    3
#define   ADRS_OTS_ADDR                4
#define   ADRS_LTREE_ADDR              4
#define   ADRS_PADDING                 4
#define   ADRS_CHAIN_ADDR              5
#define   ADRS_TREE_HEIGHT             5
#define   ADRS_HASH_ADDR               6
#define   ADRS_TREE_INDEX              6
#define   ADRS_KEY_MASK                7
#define   ADRS_WORD_COUNT              8

/* ADRS types */
#define   ADRS_TYPE_OTS                0
#define   ADRS_TYPE_LTREE              1
#define   ADRS_TYPE_LEAF               2

/* Define L-tree stack parameters */
#define   STACK_DEPTH                  8

/* Miscellaneous definitions */
#define   MAX_HASH_LEN                 32
#define   CHECKSUM_BYTE_COUNT          2
#define   IDX_LEN( x )                 ( ( ( x ) + 7 ) / 8 )
#define   MAX_HEIGHT                   60
#define   MAX_IDX_LEN                  ( IDX_LEN( MAX_HEIGHT ) )

/* Define XMSS identifiers for configurations that use SHA2-256    */
#define   XMSS_SHA2_10_256             0x00000001
#define   XMSS_SHA2_16_256             0x00000002
#define   XMSS_SHA2_20_256             0x00000003

/* Define XMSS OID strings corresponding to the above configurations */
#define   XMSS_SHA2_10_256_STR         "XMSS-SHA2_10_256"
#define   XMSS_SHA2_16_256_STR         "XMSS-SHA2_16_256"
#define   XMSS_SHA2_20_256_STR         "XMSS-SHA2_20_256"

/* Define XMSS-MT identifiers for configurations that use SHA2-256 */
#define   XMSSMT_SHA2_20_2_256         0x00000001
#define   XMSSMT_SHA2_20_4_256         0x00000002
#define   XMSSMT_SHA2_40_2_256         0x00000003
#define   XMSSMT_SHA2_40_4_256         0x00000004
#define   XMSSMT_SHA2_40_8_256         0x00000005
#define   XMSSMT_SHA2_60_3_256         0x00000006
#define   XMSSMT_SHA2_60_6_256         0x00000007
#define   XMSSMT_SHA2_60_12_256        0x00000008

/* Define XMSS-MT OID strings corresponding to the above configurations */
#define   XMSSMT_SHA2_20_2_256_STR     "XMSSMT-SHA2_20/2_256"
#define   XMSSMT_SHA2_20_4_256_STR     "XMSSMT-SHA2_20/4_256"
#define   XMSSMT_SHA2_40_2_256_STR     "XMSSMT-SHA2_40/2_256"
#define   XMSSMT_SHA2_40_4_256_STR     "XMSSMT-SHA2_40/4_256"
#define   XMSSMT_SHA2_40_8_256_STR     "XMSSMT-SHA2_40/8_256"
#define   XMSSMT_SHA2_60_3_256_STR     "XMSSMT-SHA2_60/3_256"
#define   XMSSMT_SHA2_60_6_256_STR     "XMSSMT-SHA2_60/6_256"
#define   XMSSMT_SHA2_60_12_256_STR    "XMSSMT-SHA2_60/12_256"

/* Define structure of the XMSS-MT public keys */
#define   XMSSMT_PUB_OID_OFFSET        0
#define   XMSSMT_OID_LEN               4
#define   XMSSMT_PUB_ROOT_OFFSET       XMSS_OID_LEN
#define   XMSSMT_PUB_SEED_OFFSET( n )  ( XMSS_PUB_ROOT_OFFSET + ( n ) )

/* Define structure of the XMSS public keys */
#define   XMSS_PUB_OID_OFFSET          0
#define   XMSS_OID_LEN                 4
#define   XMSS_PUB_ROOT_OFFSET         XMSS_OID_LEN
#define   XMSS_PUB_SEED_OFFSET( n )    ( XMSS_PUB_ROOT_OFFSET + ( n ) )

/* Define structure of the XMSS signature */
#define   XMSS_SIG_IDX_LEN             4
#define   XMSS_SIG_IDX_OFFSET          0
#define   XMSS_SIG_R_OFFSET            XMSS_SIG_IDX_LEN
#define   XMSS_SIG_OTS_SIG_OFFSET( n ) ( XMSS_SIG_IDX_LEN + ( n ) )
#define   XMSS_SIG_AUTH_OFFSET( n, p ) ( XMSS_SIG_OTS_SIG_OFFSET( ( n ) * ( ( p ) + 1 ) ) )


/*----------------------------------------------------------------------------------------------------*/
/* Type Definitions */
/*----------------------------------------------------------------------------------------------------*/

/* Define enumeration for mult-purpose compute() function */
    enum
    {
        COMPUTE_F,
        COMPUTE_H,
        COMPUTE_Hmsg,
        COMPUTE_PRF
    };


/* Define data structure to hold all possible XMSS-MT parameters */
/* including those for the underlying WOTS+ and XMSS mechanisms. */
/*                                                               */
/* Different approach than for HSS due to the fact they don't    */
/* include type fields in the individual components, choosing    */
/* instead to use a single OID that needs to be parsed at some   */
/* point.  That parsing will populate the fields of this struct  */
/* which then propagates to all associated functions to provide  */
/* the necessary run-time parameters                             */

    typedef struct {
        uint8_t H;          /* Enumerated value representing hash function to use          */
        uint8_t w;          /* Base used for interpreting OTS coefficients                 */
        uint8_t log2w;      /* log2(w) = # of bits per OTS coefficient                     */
        uint8_t p1;         /* # of base-w digits in hash function output                  */
        uint8_t p2;         /* # of base-w digits in checksum function output              */
        uint8_t p2Bytes;    /* # of bytes in checksum                                      */
        uint8_t ls;         /* # of bits to left-shift checksum result by to byte-align it */
        uint8_t p;          /* # of base-w digits in ???                                   */
        uint8_t h;          /* # of levels in XMSS tree (constant for all sub trees)       */
        uint8_t hTotal;     /* total # of levels in XMSS-MT configuration                  */
        uint8_t d;          /* # of trees in XMSS-MT                                       */
        uint8_t n;          /* # of bytes in hash function output                          */
        uint8_t idxLen;     /* length (in bytes) of idx values                             */
        size_t  otsSigLen;  /* length (in bytes) of WOTS+ signature                        */
        size_t  xmssSigLen; /* length (in bytes) of XMSS signature                         */
        size_t  pubKeyLen;  /* length (in bytes) of public key                             */
    } xmssmt_params_t;

    typedef enum {
        SIG_OK = 0,
        SIG_INVALID_SIG,
        SIG_INVALID_PARAM,
        SIG_INVALID_XMSS_KEY_LEN,
        SIG_INVALID_XMSS_SIG_LEN,
        SIG_INVALID_XMSS_TYPE,
        SIG_INVALID_XMSS_NODE,
        SIG_INVALID_OTS_KEY_LEN,
        SIG_INVALID_OTS_SIG_LEN,
        SIG_INVALID_OTS_TYPE,
        SIG_INVALID_XMSSMT_KEY_LEN,
        SIG_INVALID_XMSSMT_SIG_LEN,
        SIG_INVALID_XMSSMT_LEVELS,
        SIG_FLASH_READ_ERROR,
        SIG_INSUFFICIENT_MEMORY,
        SIG_UNSUPPORTED_OID,
        SIG_NUM_RETCODES
    } sig_retcode_t;

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
#define  C4A_CACHE_SIZE     512
    uint32_t g_cacheStart;
    uint32_t g_cacheEnd;
    uint8_t  g_cache[C4A_CACHE_SIZE];
    uint32_t g_flashBytesRead;

/* Scratch buffer definition */
#define  C4A_SCRATCH_SIZE   537

/*----------------------------------------------------------------------------------------------------*/
/* Function prototypes */
/*----------------------------------------------------------------------------------------------------*/

    sig_retcode_t convertAdrsToBytes( uint8_t *dst, uint32_t *ADRS );
    uint32_t otsCoeff( const uint8_t *S, uint32_t i, uint32_t log2w );
    sig_retcode_t otsComputeChecksum( uint8_t *dst, const uint8_t *value, const xmssmt_params_t *params );
    uint32_t readOidBytes( const uint8_t *oid, uint32_t oidLen );
    sig_retcode_t readOid( const char *oid, uint32_t *val );
    sig_retcode_t parseXmssMtOid( xmssmt_params_t *params, uint32_t oidVal );
    sig_retcode_t parseXmssOid( xmssmt_params_t *params, uint32_t oidVal );
    sig_retcode_t computeH( uint8_t *out, const uint8_t *key, const uint8_t *m, const xmssmt_params_t *params );
    sig_retcode_t computeHmsg( uint8_t *out, const uint8_t *r, const uint8_t *root, const uint64_t idx, const uint8_t *m,
                               const uint32_t mLen, const xmssmt_params_t *params );
    sig_retcode_t computePrf( uint8_t *out, const uint8_t *key, const uint8_t *m, const xmssmt_params_t *params );
    sig_retcode_t randHash( uint8_t *out, const uint8_t *left, const uint8_t *right, const uint8_t *SEED, uint32_t *ADRS,
                            const xmssmt_params_t *params );
    sig_retcode_t computeF( uint8_t *out, const uint8_t *key, uint8_t *m0, const uint8_t *m1, const xmssmt_params_t *params );
    sig_retcode_t computeChain( uint8_t *Y, const uint8_t *X, const uint32_t i, const uint32_t s, const uint8_t *SEED,
                                uint32_t *ADRS, const xmssmt_params_t *params );
    sig_retcode_t computeOtsPkI( uint8_t *otsPk, const uint8_t *otsSig, const uint32_t mVal, const uint8_t *SEED,
                                 uint32_t *ADRS, const uint32_t idx, const xmssmt_params_t *params );
    sig_retcode_t computeLeaf( uint8_t *computedLeaf, const uint8_t *message, const uint8_t *signature, const uint8_t *SEED,
                               uint32_t *adrsOts, uint32_t *adrsLtree, const xmssmt_params_t *params );
    sig_retcode_t computeRoot( uint8_t *computedRoot, uint8_t *leaf, const uint8_t *auth, const uint8_t *SEED,
                               uint32_t *ADRS, uint64_t idx, const xmssmt_params_t *params );
    sig_retcode_t xmssVerifySignature( const void *message, size_t messageLen, const uint8_t *signature, size_t signatureLen,
                                       const uint8_t *publicKey, size_t publicKeyLen );
    sig_retcode_t xmssMtVerifySignature( const void *message, size_t messageLen, const uint8_t *signature, size_t signatureLen,
                                         const uint8_t *publicKey, size_t publicKeyLen );
    sig_retcode_t xmssMtVerifySignatureCore( const void *message, size_t messageLen, const uint8_t *signature, size_t signatureLen,
                                             const uint8_t *publicKey, size_t publicKeyLen, xmssmt_params_t *params );

/* Flash emulation and scratch buff based variants */
    int nlflash_read(nlflash_id_t flash_id, uint32_t from, size_t len, size_t *retlen, uint8_t *buf, nlloop_callback_fp callback);
    sig_retcode_t flashcpy( uint8_t *buf, uint32_t offset, size_t len );
    sig_retcode_t computeHmsgFlash( uint8_t *out, const uint8_t *r, const uint8_t *root, const uint64_t idx, const uint8_t *m,
                                    const uint32_t mLen, uint8_t *scratchBuff, size_t scratchLen, const xmssmt_params_t *params );
    sig_retcode_t randHashFlash( uint8_t *out, const uint8_t *left, const uint8_t *right, const uint8_t *SEED, uint32_t *ADRS,
                                 uint8_t *scratchBuff, size_t scratchLen, const xmssmt_params_t *params );
    sig_retcode_t computeChainFlash( uint8_t *Y, uint32_t Xoffset, const uint32_t i, const uint32_t s, const uint8_t *SEED,
                                     uint32_t *ADRS, uint8_t *scratchBuff, size_t scratchLen, const xmssmt_params_t *params );
    sig_retcode_t computeOtsPkIFlash( uint8_t *otsPk, uint32_t otsSigOffset, const uint32_t mVal, const uint8_t *SEED,
                                      uint32_t *ADRS, const uint32_t idx, uint8_t *scratchBuff, size_t scratchLen, const xmssmt_params_t *params );
    sig_retcode_t computeLeafFlash( uint8_t *computedLeaf, const uint8_t *message, uint32_t signatureOffset, const uint8_t *SEED,
                                    uint32_t *adrsOts, uint32_t *adrsLtree, uint8_t *scratchBuff, size_t scratchLen, const xmssmt_params_t *params );
    sig_retcode_t computeRootFlash( uint8_t *computedRoot, uint8_t *leaf, uint32_t authOffset, const uint8_t *SEED,
                                    uint32_t *ADRS, uint64_t idx, uint8_t *scratchBuff, size_t scratchLen, const xmssmt_params_t *params );
    sig_retcode_t xmssVerifySignatureFlash( const void *message, size_t messageLen, uint32_t signatureOffset, size_t signatureLen,
                                            const uint8_t *publicKey, size_t publicKeyLen, uint8_t *scratchBuff, size_t scratchLen );
    sig_retcode_t xmssMtVerifySignatureFlash( const void *message, size_t messageLen, uint32_t signatureOffset, size_t signatureLen,
                                              const uint8_t *publicKey, size_t publicKeyLen, uint8_t *scratchBuff, size_t scratchLen );
    sig_retcode_t xmssMtVerifySignatureCoreFlash( const void *message, size_t messageLen, uint32_t signatureOffset, size_t signatureLen,
                                                  const uint8_t *publicKey, size_t publicKeyLen, uint8_t *scratchBuff, size_t scratchLen, xmssmt_params_t *params );

#ifdef __cplusplus
}
#endif    

#endif /* _C4A_VERIFY_H */
