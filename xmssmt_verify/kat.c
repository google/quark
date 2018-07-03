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
 *  Description : Simple Known-Answer-Test (KAT) interface.
 */

#include <stdlib.h>
#include <time.h>
#include "quark_verify.h"
#include "quark_misc.h"


/* List of header files containing XMSS reference vectors to be tested, please ensure    */
/* that one and only one of these is uncommented                                         */
#include "xmss_ref_10.h"
//#include "xmss_ref_16.h"
//#include "xmss_ref_20.h"
//#include "xmss_ref_001.h"

/* List of header files containing XMSS-MT reference vectors to be tested, please ensure */
/* that one and only one of these is uncommented                                         */
#include "xmssmt_ref_20_2.h"
//#include "xmssmt_ref_20_4.h"
//#include "xmssmt_ref_40_2.h"
//#include "xmssmt_ref_40_4.h"
//#include "xmssmt_ref_40_8.h"
//#include "xmssmt_ref_60_3.h"
//#include "xmssmt_ref_60_6.h"
//#include "xmssmt_ref_60_12.h"
//#include "xmssmt_ref_001.h"

/* Define the below value if you want to test out sub-functions but make */
/* sure you only use xmss_ref_001.h and xmssmt_ref_001.h vector sets in  */
/* this case.                                                            */
#undef _QUARK_TEST_REF_001_H_

/* Implements a quick-and-dirty known-answer-test (KAT) command line utility */
/* that allows you to check and see if your signature primitive is (still!)  */
/* working.  The reference vectors are passed in via header files, and each  */
/* test checks that it detects a valid signature on the raw data, as well as */
/* that it catches a single bit-flip on the message yielding an invalid      */
/* signature.  Pretty basic stuff...                                         */
int main(void) {
  sig_retcode_t result;

  g_cacheStart = 0;
  g_cacheEnd = 0;

  /* Initialize PRNG */
  srand(time(NULL));

#ifdef _QUARK_TEST_REF_001_H_
  /* Test ltreeSmall( ) vs ltreeBig( ) */
  if ( 0 )
  {
      uint32_t a0[ADRS_WORD_COUNT] = { 0 };
      uint32_t a1[ADRS_WORD_COUNT] = { 0 };
      uint8_t *pk0, *pk1;
      uint8_t seed[MAX_HASH_LEN], res0[MAX_HASH_LEN], res1[MAX_HASH_LEN];
      xmssmt_params_t params;
      int passCnt = 0;
      int failCnt = 0;
      int testCnt = 1000;

      /* Initialize params */
      parseXmssOid( &params, XMSS_SHA2_10_256 );

      /* Allocate public key arrays */
      pk0 = malloc( sizeof(uint8_t) * params.otsSigLen );
      pk1 = malloc( sizeof(uint8_t) * params.otsSigLen );
      if ( ( pk0 == NULL ) || ( pk1 == NULL ) )
      {
          free(pk0);
          free(pk1);
          printf( "[ERROR] Unable to allocate public key arrays\n" );
          return;
      }

      for ( int k = 0; k < testCnt; k++ )
      {
          /* Initialize seed */
          for ( int i = 0; i < MAX_HASH_LEN; i++ )
              seed[i] = rand( ) & 0xff;

          /* Initialize PK0 and PK1 */
          for ( int i = 0; i < params.otsSigLen; i++ )
              pk0[i] = rand( ) & 0xff;
          memcpy( pk1, pk0, params.otsSigLen );

          /* Compute ltree */
          ltreeBig( res0, pk0, seed, a0, &params );
          ltreeSmall( res1, pk1, seed, a1, &params );

          /* Compare results and update counters */
          if ( !memcmp( res0, res1, params.n ) )
              passCnt++;
          else
              failCnt++;
      }

      printf( "[RESULTS] Executed %d tests\n", testCnt );
      printf( "    PASS = %d\n", passCnt );
      printf( "    FAIL = %d\n", failCnt );
  }

  /* Test computeHmsg */
  if ( 0 )
  {
      uint32_t adrs[ADRS_WORD_COUNT] = { 0 };
      uint8_t messageHash[MAX_HASH_LEN];
      xmssmt_params_t params;
      uint64_t idx;

      parseXmssOid( &params, XMSS_SHA2_10_256 );
      idx = readBigEndian( sig, params.idxLen );
      printf( "-------------- Testing Compute Message Hash --------------\n" );
      result = computeHmsg(messageHash,
                           sig + params.idxLen,
                           pk + XMSS_PUB_ROOT_OFFSET,
                           idx,
                           msg,
                           2290,
                           &params);
      if ( !memcmp( messageHash, mhash, params.n ) && result )
          printf( "[RESULTS] message hash computation: PASSED\n" );
      else
          printf( "[RESULTS] message hash computation: FAILED\n" );
  }

  /* Test otsPkFromSig( ) */
  if ( 0 )
  {
      uint32_t adrs[ADRS_WORD_COUNT] = { 0 };
      uint8_t *computedPk;
      xmssmt_params_t params;

      adrs[ADRS_OTS_ADDR] = 257;
      parseXmssOid( &params, XMSS_SHA2_10_256 );
      computedPk = malloc( sizeof(uint8_t) * params.otsSigLen );
      if ( computedPk == NULL )
      {
          free(computedPk);
          printf( "[ERROR] Unable to allocate public key array\n" );
          return;
      }

      printf( "-------------- Testing WOTS Pk Computation --------------\n" );
      result = otsPkFromSig( computedPk,
                             mhash,
                             sig + XMSS_SIG_OTS_SIG_OFFSET( params.n ),
                             pk + XMSS_PUB_SEED_OFFSET( params.n ),
                             adrs,
                             &params);

      if ( !memcmp( computedPk, wots_pk, params.otsSigLen ) && result )
          printf( "[RESULTS] WOTS+ Pk computation: PASSED\n" );
      else
          printf( "[RESULTS] WOTS+ Pk computation: FAILED\n" );
  }

  /* Test ltree( ) */
  if ( 0 )
  {
      uint32_t adrs[ADRS_WORD_COUNT] = { 0 };
      uint8_t computedLeaf[MAX_HASH_LEN];
      xmssmt_params_t params;

      adrs[ADRS_OTS_ADDR] = 257;
      adrs[ADRS_TYPE]     = ADRS_TYPE_LTREE;
      parseXmssOid( &params, XMSS_SHA2_10_256 );

      printf( "-------------- Testing ltreeSmall( ) Computation --------------\n" );
      result = ltreeSmall( computedLeaf,
                           wots_pk,
                           pk + XMSS_PUB_SEED_OFFSET( params.n ),
                           adrs,
                           &params );
      if ( !memcmp( computedLeaf, leaf, params.n ) && result )
          printf( "[RESULTS] ltreeSmall computation: PASSED\n" );
      else
          printf( "[RESULTS] ltreeSmall computation: FAILED\n" );
  }

  /* Test computeRoot( ) */
  if ( 0 )
  {
      uint32_t adrs[ADRS_WORD_COUNT] = { 0 };
      uint8_t computedRoot[MAX_HASH_LEN];
      xmssmt_params_t params;
      uint64_t idx;

      adrs[ADRS_TYPE]     = ADRS_TYPE_LEAF;
      parseXmssOid( &params, XMSS_SHA2_10_256 );
      idx = readBigEndian( sig, params.idxLen );
      printf( "-------------- Testing computeRoot( ) Computation --------------\n" );
      result = computeRoot( computedRoot,
                            leaf,
                            sig + XMSS_SIG_AUTH_OFFSET( params.n, params.p ),
                            pk + XMSS_PUB_SEED_OFFSET( params.n ),
                            adrs,
                            idx,
                            &params );
      if ( !memcmp( computedRoot, root, params.n ) && result )
          printf( "[RESULTS] computeRoot computation: PASSED\n" );
      else
          printf( "[RESULTS] computeRoot computation: FAILED\n" );
  }

  /* Test new incremental leaf-generation routine against original approach */
  if ( 0 )
  {
      uint32_t adrs[ADRS_WORD_COUNT] = { 0 };
      uint32_t adrsOts[ADRS_WORD_COUNT] = { 0 };
      uint32_t adrsLtree[ADRS_WORD_COUNT] = { 0 };
      xmssmt_params_t params;

      parseXmssOid( &params, XMSS_SHA2_10_256 );

      /* Compute leaf value using original method */
      uint8_t oldPk[params.otsSigLen];
      uint8_t oldLeaf[params.n], newLeaf[params.n];
      uint8_t *SEED = pk + XMSS_PUB_SEED_OFFSET( params.n );
      adrs[ADRS_OTS_ADDR] = 257;
      printf( "-------------- Testing computeLeaf( ) --------------\n" );
      otsPkFromSig( oldPk,
                    mhash,
                    sig + XMSS_SIG_OTS_SIG_OFFSET( params.n ),
                    SEED,
                    adrs,
                    &params );
      adrs[ADRS_OTS_ADDR] = 257;
      adrs[ADRS_TYPE]     = ADRS_TYPE_LTREE;
      ltreeSmall( oldLeaf,
                  oldPk,
                  SEED,
                  adrs,
                  &params );

      adrsOts[ADRS_TYPE]       = ADRS_TYPE_OTS;
      adrsOts[ADRS_OTS_ADDR]   = 257;
      adrsLtree[ADRS_TYPE]     = ADRS_TYPE_LTREE;
      adrsLtree[ADRS_OTS_ADDR] = 257;
      computeLeaf( newLeaf,
                   mhash,
                   sig + XMSS_SIG_OTS_SIG_OFFSET( params.n ),
                   SEED,
                   adrsOts,
                   adrsLtree,
                   &params );
      if ( !memcmp( oldLeaf, newLeaf, params.n ) )
          printf( "[RESULTS] computeLeaf computation: PASSED\n" );
      else
          printf( "[RESULTS] computeLeaf computation: FAILED\n" );
  }
#endif  /* _QUARK_TEST_REF_001_H_ */

  /* Putting it all together to test xmssVerifySignature( ) */
  if (1) {
    printf("-------------- Testing xmssVerifySignature( ) --------------\n");
    result = xmssVerifySignature(msg,
                                 msgLen,
                                 sig,
                                 sigLen,
                                 pk,
                                 pkLen);
    if (SIG_OK == result)
      printf("[RESULTS] xmssVerifySignature computation: PASSED\n");
    else
      printf("[RESULTS] xmssVerifySignature computation: FAILED\n");

    /* Tweak the message by a single bit and do it again, taking care to */
    /* pass iff signature result is false since we've corrupted it       */
    msg[8] ^= 0x1;
    result = xmssVerifySignature(msg,
                                 msgLen,
                                 sig,
                                 sigLen,
                                 pk,
                                 pkLen);
    msg[8] ^= 0x1;
    if (SIG_OK == result)
      printf("[RESULTS] corrupted xmssVerifySignature computation: FAILED\n");
    else
      printf("[RESULTS] corrupted xmssVerifySignature computation: PASSED\n");
  }

  /* Putting it all together to test xmssVerifySignatureFlash( ) */
  if (1) {
    uint32_t signatureOffset = 0;
    size_t scratchLen = QUARK_SCRATCH_SIZE;
    uint8_t scratchBuff[scratchLen];

    // Copy signature info into the g_flashBuff
    memcpy(&g_flashBuff[signatureOffset], sig, sigLen);

    printf("-------------- Testing xmssVerifySignatureFlash( ) --------------\n");
    g_flashCnt = 0;
    g_flashBytesRead = 0;
    result = xmssVerifySignatureFlash(msg,
                                      msgLen,
                                      signatureOffset,
                                      sigLen,
                                      pk,
                                      pkLen,
                                      scratchBuff,
                                      scratchLen);
    if (SIG_OK == result)
      printf("[RESULTS] xmssVerifySignatureFlash computation: PASSED\n");
    else
      printf("[RESULTS] xmssVerifySignatureFlash computation: FAILED\n");

    /* Tweak the message by a single bit and do it again, taking care to */
    /* pass iff signature result is false since we've corrupted it       */
    msg[8] ^= 0x1;
    g_flashCnt = 0;
    g_flashBytesRead = 0;
    result = xmssVerifySignatureFlash(msg,
                                      msgLen,
                                      signatureOffset,
                                      sigLen,
                                      pk,
                                      pkLen,
                                      scratchBuff,
                                      scratchLen);
    msg[8] ^= 0x1;
    if (SIG_OK == result)
      printf(
          "[RESULTS] corrupted xmssVerifySignatureFlash computation: FAILED\n");
    else
      printf(
          "[RESULTS] corrupted xmssVerifySignatureFlash computation: PASSED\n");
  }

  /* Putting it all together to test xmssMtVerifySignature( ) */
  if (1) {
    printf("-------------- Testing xmssMtVerifySignature( ) --------------\n");
    result = xmssMtVerifySignature(msg_mt,
                                   msgLen_mt,
                                   sig_mt,
                                   sigLen_mt,
                                   pk_mt,
                                   pkLen_mt);
    if (SIG_OK == result)
      printf("[RESULTS] xmssMtVerifySignature computation: PASSED\n");
    else
      printf("[RESULTS] xmssMtVerifySignature computation: FAILED (%d)\n",
             result);

    /* Tweak the message by a single bit and do it again, taking care to */
    /* pass iff signature result is false since we've corrupted it       */
    msg_mt[8] ^= 0x1;
    result = xmssMtVerifySignature(msg_mt,
                                   msgLen_mt,
                                   sig_mt,
                                   sigLen_mt,
                                   pk_mt,
                                   pkLen_mt);
    msg_mt[8] ^= 0x1;
    if (SIG_OK == result)
      printf("[RESULTS] corrupted xmssMtVerifySignature computation: FAILED\n");
    else
      printf("[RESULTS] corrupted xmssMtVerifySignature computation: PASSED\n");
  }

  /* Putting it all together to test xmssMtVerifySignatureFlash( ) */
  if (1) {
    uint32_t signatureOffset = 0;
    size_t scratchLen = QUARK_SCRATCH_SIZE;
    uint8_t scratchBuff[scratchLen];

    // Copy signature info into the g_flashBuff
    memcpy(&g_flashBuff[signatureOffset], sig_mt, sigLen_mt);

    printf(
        "-------------- Testing xmssMtVerifySignatureFlash( ) --------------\n");
    g_flashCnt = 0;
    g_flashBytesRead = 0;
    result = xmssMtVerifySignatureFlash(msg_mt,
                                        msgLen_mt,
                                        signatureOffset,
                                        sigLen_mt,
                                        pk_mt,
                                        pkLen_mt,
                                        scratchBuff,
                                        scratchLen);
    if (SIG_OK == result)
      printf("[RESULTS] xmssMtVerifySignatureFlash computation: PASSED\n");
    else
      printf("[RESULTS] xmssMtVerifySignatureFlash computation: FAILED (%d)\n",
             result);

    msg_mt[8] ^= 0x1;
    g_flashCnt = 0;
    g_flashBytesRead = 0;
    result = xmssMtVerifySignatureFlash(msg_mt,
                                        msgLen_mt,
                                        signatureOffset,
                                        sigLen_mt,
                                        pk_mt,
                                        pkLen_mt,
                                        scratchBuff,
                                        scratchLen);
    msg_mt[8] ^= 0x1;
    if (SIG_OK == result)
      printf(
          "[RESULTS] corrupted xmssMtVerifySignatureFlash computation: FAILED\n");
    else
      printf(
          "[RESULTS] corrupted xmssMtVerifySignatureFlash computation: PASSED\n");
  }

  return 0;
}
