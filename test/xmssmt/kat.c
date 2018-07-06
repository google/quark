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
#include <test_vector.h>
#include "verify.h"
#include "macros.h"
#include "quark_misc.h"

/* List of header files containing XMSS reference vectors to be tested, please ensure    */
/* that one and only one of these is uncommented                                         */
#include "xmss_ref_10.h"
#include "xmss_ref_16.h"
#include "xmss_ref_20.h"
#include "xmss_ref_001.h"

/* List of header files containing XMSS-MT reference vectors to be tested, please ensure */
/* that one and only one of these is uncommented                                         */
#include "xmssmt_ref_20_2.h"
#include "xmssmt_ref_20_4.h"
#include "xmssmt_ref_40_2.h"
#include "xmssmt_ref_40_4.h"
#include "xmssmt_ref_40_8.h"
#include "xmssmt_ref_60_3.h"
#include "xmssmt_ref_60_6.h"
#include "xmssmt_ref_60_12.h"
#include "xmssmt_ref_001.h"

/** Define this to test subfunctions **/
#define _QUARK_TEST_XMSS_MT_SUB_FUNCTIONS_
void testSubfunctions();

/* Implements a quick-and-dirty known-answer-test (KAT) command line utility */
/* that allows you to check and see if your signature primitive is (still!)  */
/* working.  The reference vectors are passed in via header files, and each  */
/* test checks that it detects a valid signature on the raw data, as well as */
/* that it catches a single bit-flip on the message yielding an invalid      */
/* signature.  Pretty basic stuff...                                         */
int main(void) {
  g_cacheStart = 0;
  g_cacheEnd = 0;

  /* Initialize PRNG */
  srand(time(NULL));
  {
    printf("XMSS Tests\n");
    const test_vector testVectors[] = {
        xmss_vector_001,
        xmss_vector_10,
        xmss_vector_16,
        xmss_vector_20,
    };

    for (size_t v = 0; v < sizeof(testVectors) / sizeof(testVectors[0]); v++) {
      printf("-----Using Vector: %s-----\n", testVectors[v].name);

      uint8_t msg_corrupt[testVectors[v].msgLen];
      memcpy(msg_corrupt, testVectors[v].msg, testVectors[v].msgLen);
      msg_corrupt[8] ^= 0x1;

      /* Putting it all together to test xmssVerifySignature( ) */
      printf("Testing xmssVerifySignature");
      TEST("xmssVerifySignature", SIG_OK, xmssVerifySignature(testVectors[v].msg,
                                                              testVectors[v].msgLen,
                                                              testVectors[v].sig,
                                                              testVectors[v].sigLen,
                                                              testVectors[v].key,
                                                              testVectors[v].keyLen));

      /* Tweak the message by a single bit and do it again, taking care to */
      /* pass iff signature result is false since we've corrupted it       */
      TEST("xmssVerifySignature", SIG_INVALID_SIG, xmssVerifySignature(msg_corrupt,
                                                                       testVectors[v].msgLen,
                                                                       testVectors[v].sig,
                                                                       testVectors[v].sigLen,
                                                                       testVectors[v].key,
                                                                       testVectors[v].keyLen));
      IF_PASS_MSG

      /* Putting it all together to test xmssVerifySignatureFlash( ) */
      uint32_t signatureOffset = 0;
      size_t scratchLen = QUARK_SCRATCH_SIZE;
      uint8_t scratchBuff[scratchLen];

      // Copy signature info into the g_flashBuff
      memcpy(&g_flashBuff[signatureOffset], testVectors[v].sig, testVectors[v].sigLen);

      printf("Testing xmssVerifySignatureFlash");
      g_flashCnt = 0;
      g_flashBytesRead = 0;
      TEST("xmssVerifySignatureFlash", SIG_OK, xmssVerifySignatureFlash(testVectors[v].msg,
                                                                        testVectors[v].msgLen,
                                                                        signatureOffset,
                                                                        testVectors[v].sigLen,
                                                                        testVectors[v].key,
                                                                        testVectors[v].keyLen,
                                                                        scratchBuff,
                                                                        scratchLen));

      /* Tweak the message by a single bit and do it again, taking care to */
      /* pass iff signature result is false since we've corrupted it       */
      g_flashCnt = 0;
      g_flashBytesRead = 0;
      TEST("xmssVerifySignatureFlash", SIG_INVALID_SIG, xmssVerifySignatureFlash(msg_corrupt,
                                                                                 testVectors[v].msgLen,
                                                                                 signatureOffset,
                                                                                 testVectors[v].sigLen,
                                                                                 testVectors[v].key,
                                                                                 testVectors[v].keyLen,
                                                                                 scratchBuff,
                                                                                 scratchLen));
      IF_PASS_MSG
    }
  }

  {
    printf("XMSS_MT Tests");
#ifndef _QUARK_TEST_REF_001_H_
    const test_vector testVectors[] = {
        mt_vector_001,
        mt_vector_20_2,
        mt_vector_20_4,
        mt_vector_40_2,
        mt_vector_40_4,
        mt_vector_40_8,
        mt_vector_60_3,
        mt_vector_60_6,
        mt_vector_60_12
    };
#else
    const test_vector testVectors[] = {
        mt_vector_001,
    };
#endif
    for (size_t v = 0; v < sizeof(testVectors) / sizeof(testVectors[0]); v++) {
      printf("-----Using Vector: %s-----\n", testVectors[v].name);

      uint8_t msg_corrupt[testVectors[v].msgLen];
      memcpy(msg_corrupt, testVectors[v].msg, testVectors[v].msgLen);
      msg_corrupt[8] ^= 0x1;

      /* Putting it all together to test xmssMtVerifySignature( ) */
      printf("Testing xmssMtVerifySignature");
      TEST("xmssMtVerifySignature", SIG_OK, xmssMtVerifySignature(testVectors[v].msg,
                                                                  testVectors[v].msgLen,
                                                                  testVectors[v].sig,
                                                                  testVectors[v].sigLen,
                                                                  testVectors[v].key,
                                                                  testVectors[v].keyLen));

      /* Tweak the message by a single bit and do it again, taking care to */
      /* pass iff signature result is false since we've corrupted it       */
      TEST("xmssMtVerifySignature", SIG_INVALID_SIG, xmssMtVerifySignature(msg_corrupt,
                                                                           testVectors[v].msgLen,
                                                                           testVectors[v].sig,
                                                                           testVectors[v].sigLen,
                                                                           testVectors[v].key,
                                                                           testVectors[v].keyLen));
      IF_PASS_MSG
      /* Putting it all together to test xmssMtVerifySignatureFlash( ) */
      uint32_t signatureOffset = 0;
      size_t scratchLen = QUARK_SCRATCH_SIZE;
      uint8_t scratchBuff[scratchLen];

      // Copy signature info into the g_flashBuff
      memcpy(&g_flashBuff[signatureOffset], testVectors[v].sig, testVectors[v].sigLen);

      printf("Testing xmssMtVerifySignatureFlash");
      g_flashCnt = 0;
      g_flashBytesRead = 0;
      TEST("xmssMtVerifySignatureFlash", SIG_OK, xmssMtVerifySignatureFlash(testVectors[v].msg,
                                                                            testVectors[v].msgLen,
                                                                            signatureOffset,
                                                                            testVectors[v].sigLen,
                                                                            testVectors[v].key,
                                                                            testVectors[v].keyLen,
                                                                            scratchBuff,
                                                                            scratchLen));
      g_flashCnt = 0;
      g_flashBytesRead = 0;
      TEST("xmssMtVerifySignatureFlash", SIG_INVALID_SIG, xmssMtVerifySignatureFlash(msg_corrupt,
                                                                                     testVectors[v].msgLen,
                                                                                     signatureOffset,
                                                                                     testVectors[v].sigLen,
                                                                                     testVectors[v].key,
                                                                                     testVectors[v].keyLen,
                                                                                     scratchBuff,
                                                                                     scratchLen));
      IF_PASS_MSG
    }
  }

  testSubfunctions();

  if (g_numberOfTestFailures != 0) {
    printf("\n%d tests FAILED\n", g_numberOfTestFailures);
    return 1;
  }

  printf("\nAll tests PASSED\n");
  return 0;
}

void testSubfunctions() {
#ifdef _QUARK_TEST_XMSS_MT_SUB_FUNCTIONS_
  int result = 0;
  /* Test ltreeSmall( ) vs ltreeBig( ) */
  uint32_t a0[ADRS_WORD_COUNT] = {0};
  uint32_t a1[ADRS_WORD_COUNT] = {0};
  uint8_t *pk0, *pk1;
  uint8_t seed[MAX_HASH_LEN], res0[MAX_HASH_LEN], res1[MAX_HASH_LEN];
  xmssmt_params_t params;
  int passCnt = 0;
  int failCnt = 0;
  int testCnt = 1000;

  /* Initialize params */
  parseXmssOid(&params, XMSS_SHA2_10_256);

  /* Allocate public key arrays */
  pk0 = malloc(sizeof(uint8_t) * params.otsSigLen);
  pk1 = malloc(sizeof(uint8_t) * params.otsSigLen);
  if ((pk0 == NULL) || (pk1 == NULL)) {
    free(pk0);
    free(pk1);
    printf("[ERROR] Unable to allocate public key arrays\n");
    return;
  }

  for (int k = 0; k < testCnt; k++) {
    /* Initialize seed */
    for (int i = 0; i < MAX_HASH_LEN; i++)
      seed[i] = rand() & 0xff;

    /* Initialize PK0 and PK1 */
    for (size_t i = 0; i < params.otsSigLen; i++)
      pk0[i] = rand() & 0xff;
    memcpy(pk1, pk0, params.otsSigLen);

    /* Compute ltree */
    ltreeBig(res0, pk0, seed, a0, &params);
    ltreeSmall(res1, pk1, seed, a1, &params);

    /* Compare results and update counters */
    if (!memcmp(res0, res1, params.n))
      passCnt++;
    else
      failCnt++;
  }

  printf("[RESULTS] Executed %d tests\n", testCnt);
  printf("    PASS = %d\n", passCnt);
  printf("    FAIL = %d\n", failCnt);


    /* Test computeHmsg */
    uint32_t adrs[ADRS_WORD_COUNT] = {0};
    uint8_t messageHash[MAX_HASH_LEN];
    uint64_t idx;

    parseXmssOid(&params, XMSS_SHA2_10_256);
    idx = readBigEndian(sig_001, params.idxLen);
    printf("-------------- Testing Compute Message Hash --------------\n");
    result = computeHmsg(messageHash,
                         sig_001 + params.idxLen,
                         pk_001 + XMSS_PUB_ROOT_OFFSET,
                         idx,
                         msg_001,
                         2290,
                         &params);
    if (!memcmp(messageHash, mhash_001, params.n) && (SIG_OK == result))
      printf("[RESULTS] message hash computation: PASSED\n");
    else
      printf("[RESULTS] message hash computation: FAILED\n");


    /* Test otsPkFromSig( ) */
    memset(adrs, 0, sizeof(adrs));
    uint8_t *computedPk;

    adrs[ADRS_OTS_ADDR] = 257;
    parseXmssOid(&params, XMSS_SHA2_10_256);
    computedPk = malloc(sizeof(uint8_t) * params.otsSigLen);
    if (computedPk == NULL) {
      free(computedPk);
      printf("[ERROR] Unable to allocate public key array\n");
      return;
    }

    printf("-------------- Testing WOTS Pk Computation --------------\n");
    result = otsPkFromSig(computedPk,
                          mhash_001,
                          sig_001 + XMSS_SIG_OTS_SIG_OFFSET(params.n),
                          pk_001 + XMSS_PUB_SEED_OFFSET(params.n),
                          adrs,
                          &params);

    if (!memcmp(computedPk, wots_pk_001, params.otsSigLen) && (SIG_OK == result))
      printf("[RESULTS] WOTS+ Pk computation: PASSED\n");
    else
      printf("[RESULTS] WOTS+ Pk computation: FAILED\n");

    /* Test ltree( ) */
    memset(adrs, 0, sizeof(adrs));
    uint8_t computedLeaf[MAX_HASH_LEN];

    adrs[ADRS_OTS_ADDR] = 257;
    adrs[ADRS_TYPE] = ADRS_TYPE_LTREE;
    parseXmssOid(&params, XMSS_SHA2_10_256);

    printf("-------------- Testing ltreeSmall( ) Computation --------------\n");
    result = ltreeSmall(computedLeaf,
                        wots_pk_001,
                        pk_001 + XMSS_PUB_SEED_OFFSET(params.n),
                        adrs,
                        &params);
    if (!memcmp(computedLeaf, leaf_001, params.n) && (SIG_OK == result))
      printf("[RESULTS] ltreeSmall computation: PASSED\n");
    else
      printf("[RESULTS] ltreeSmall computation: FAILED\n");


    /* Test computeRoot( ) */
    memset(adrs, 0, sizeof(adrs));
    uint8_t computedRoot[MAX_HASH_LEN];

    adrs[ADRS_TYPE] = ADRS_TYPE_LEAF;
    parseXmssOid(&params, XMSS_SHA2_10_256);
    idx = readBigEndian(sig_001, params.idxLen);
    printf("-------------- Testing computeRoot( ) Computation --------------\n");
    result = computeRoot(computedRoot,
                         leaf_001,
                         sig_001 + XMSS_SIG_AUTH_OFFSET(params.n, params.p),
                         pk_001 + XMSS_PUB_SEED_OFFSET(params.n),
                         adrs,
                         idx,
                         &params);
    if (!memcmp(computedRoot, root_001, params.n) && (SIG_OK == result))
      printf("[RESULTS] computeRoot computation: PASSED\n");
    else
      printf("[RESULTS] computeRoot computation: FAILED\n");


    /* Test new incremental leaf-generation routine against original approach */
    memset(adrs, 0, sizeof(adrs));
    uint32_t adrsOts[ADRS_WORD_COUNT] = {0};
    uint32_t adrsLtree[ADRS_WORD_COUNT] = {0};

    parseXmssOid(&params, XMSS_SHA2_10_256);

    /* Compute leaf value using original method */
    uint8_t oldPk[params.otsSigLen];
    uint8_t oldLeaf[params.n], newLeaf[params.n];
    uint8_t SEED[sizeof(pk_001) - XMSS_PUB_SEED_OFFSET(params.n)];
    memcpy(SEED, &pk_001[XMSS_PUB_SEED_OFFSET(params.n)], sizeof(SEED));
    adrs[ADRS_OTS_ADDR] = 257;
    printf("-------------- Testing computeLeaf( ) --------------\n");
    otsPkFromSig(oldPk,
                 mhash_001,
                 sig_001 + XMSS_SIG_OTS_SIG_OFFSET(params.n),
                 SEED,
                 adrs,
                 &params);
    adrs[ADRS_OTS_ADDR] = 257;
    adrs[ADRS_TYPE] = ADRS_TYPE_LTREE;
    ltreeSmall(oldLeaf,
               oldPk,
               SEED,
               adrs,
               &params);

    adrsOts[ADRS_TYPE] = ADRS_TYPE_OTS;
    adrsOts[ADRS_OTS_ADDR] = 257;
    adrsLtree[ADRS_TYPE] = ADRS_TYPE_LTREE;
    adrsLtree[ADRS_OTS_ADDR] = 257;
    computeLeaf(newLeaf,
                mhash_001,
                sig_001 + XMSS_SIG_OTS_SIG_OFFSET(params.n),
                SEED,
                adrsOts,
                adrsLtree,
                &params);
    if (!memcmp(oldLeaf, newLeaf, params.n))
      printf("[RESULTS] computeLeaf computation: PASSED\n");
    else
      printf("[RESULTS] computeLeaf computation: FAILED\n");
#endif  /* _QUARK_TEST_XMSS_MT_SUB_FUNCTIONS_ */
}
