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
 *  Description : Basic testing functions for exercising failure paths.
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <test_vector.h>
#include <stdbool.h>
#include "verify.h"

#include "hss_vectors_001.h"
#include "hss_ref_20_2.h"
#include "hss_ref_20_4.h"
#include "hss_ref_40_2.h"
#include "hss_ref_40_4.h"
#include "hss_ref_40_8.h"
#include "hss_ref_60_3.h"
#include "hss_ref_60_6.h"
#include "test_vector.h"
#include "macros.h"

/* This was intended to be a test of the various failure paths that might be  */
/* exercised by the HSS verification primitives, but ultimately I ran out of  */
/* time to deliver an exhaustive test.  I will continue to develop this over  */
/* time to ensure it's relatively robust.  Until then, feel free to use it as */
/* a basic, incomplete, sanity test.                                          */
int main() {
  const test_vector testVectors[] = {
      vector_001,
      vector_20_2,
      vector_20_4,
      vector_40_2,
      vector_40_4,
      vector_40_8,
      vector_60_3,
      vector_60_6
  };

  uint8_t buff[1000];
  uint32_t m, h, n, p, otsType, lmsType, L;

  for (size_t v = 0; v < sizeof(testVectors) / sizeof(testVectors[0]); v++) {
    printf("-----Using Vector: %s-----\n", testVectors[v].name);

    uint8_t hssSig[testVectors[v].sigLen];
    memcpy(hssSig, testVectors[v].sig, testVectors[v].sigLen);

    uint8_t hssSigCorrupt[testVectors[v].sigLen];
    memcpy(hssSigCorrupt, testVectors[v].sig, testVectors[v].sigLen);
    hssSigCorrupt[0] ^= 0x01;

    uint8_t hssKey[testVectors[v].keyLen];
    memcpy(hssKey, testVectors[v].key, testVectors[v].keyLen);

    uint8_t hssKeyInvalidHssLevels[testVectors[v].keyLen];
    memcpy(hssKeyInvalidHssLevels, testVectors[v].key, testVectors[v].keyLen);
    hssKeyInvalidHssLevels[0] ^= 0x01;

    uint8_t hssKeyInvalidSig[testVectors[v].keyLen];
    memcpy(hssKeyInvalidSig, testVectors[v].key, testVectors[v].keyLen);
    hssKeyInvalidSig[12] ^= 0x01;

    uint8_t lmsKey[testVectors[v].keyLen - 4];
    memcpy(lmsKey, testVectors[v].key + 4, testVectors[v].keyLen - 4);

    uint8_t lmsSig[testVectors[v].sigLen - 4];
    memcpy(lmsSig, testVectors[v].sig + 4, testVectors[v].sigLen - 4);
    lmsType = readBigEndian(lmsKey, 4);
    lmsParameterLookup(lmsType, NULL, &m, &h);

    uint8_t otsSig[sizeof(lmsSig) - 4];
    memcpy(otsSig, lmsSig + 4, sizeof(lmsKey));
    otsType = readBigEndian(&lmsKey[4], 4);
    otsParameterLookup(otsType, NULL, &n, NULL, &p, NULL);

    /* Test out the various error checks within the library to ensure they do what they should! */

    /* ---------- Invalid parameters ---------- */
    printf("SIG_INVALID_PARAM tests: ");
    TEST("otsComputeKc", SIG_INVALID_PARAM, otsComputeKc(NULL, NULL, 0, NULL, 0, NULL, 0, -1));
    TEST("lmsVerifySignature", SIG_INVALID_PARAM, lmsVerifySignature(NULL, 0, NULL, 0, NULL, 0));
    TEST("hssVerifySignature", SIG_INVALID_PARAM, hssVerifySignature(NULL, 0, NULL, 0, NULL, 0));
    IF_PASS_MSG

    /* ---------- Invalid key lengths ---------- */
    printf("SIG_INVALID_{OTS,LMS,HSS}_KEY_LEN tests:");
    TEST("lmsVerifySignature", SIG_INVALID_LMS_KEY_LEN, lmsVerifySignature(testVectors[v].msg,
                                                                           testVectors[v].msgLen,
                                                                           lmsSig,
                                                                           12 + n * (p + 1)
                                                                               + m * h,
                                                                           lmsKey,
                                                                           0));
    TEST("lmsVerifySignature", SIG_INVALID_LMS_KEY_LEN, lmsVerifySignature(testVectors[v].msg,
                                                                           testVectors[v].msgLen,
                                                                           lmsSig,
                                                                           12 + n * (p + 1)
                                                                               + m * h,
                                                                           lmsKey,
                                                                           23 + m));
    TEST("hssVerifySignature", SIG_INVALID_HSS_KEY_LEN, hssVerifySignature(testVectors[v].msg,
                                                                           testVectors[v].msgLen,
                                                                           hssSig,
                                                                           testVectors[v].sigLen,
                                                                           hssKey,
                                                                           0));
    IF_PASS_MSG

    /* ---------- Invalid HSS levels ---------- */
    printf("SIG_INVALID_HSS_LEVELS tests:");
    TEST("hssVerifySignature", SIG_INVALID_HSS_LEVELS, hssVerifySignature(testVectors[v].msg,
                                                                          testVectors[v].msgLen,
                                                                          hssSigCorrupt,
                                                                          testVectors[v].sigLen,
                                                                          hssKey,
                                                                          testVectors[v].keyLen));
    TEST("hssVerifySignature", SIG_INVALID_HSS_LEVELS, hssVerifySignature(testVectors[v].msg,
                                                                          testVectors[v].msgLen,
                                                                          hssSig,
                                                                          testVectors[v].sigLen,
                                                                          hssKeyInvalidHssLevels,
                                                                          testVectors[v].keyLen));

    L = readBigEndian(hssKey, 4);
    writeBigEndian(hssKey, HSS_MAX_LEVELS + 1, 4);
    writeBigEndian(hssSig, HSS_MAX_LEVELS, 4);
    TEST("hssVerifySignature", SIG_INVALID_HSS_LEVELS, hssVerifySignature(testVectors[v].msg,
                                                                          testVectors[v].msgLen,
                                                                          hssSig,
                                                                          testVectors[v].sigLen,
                                                                          hssKey,
                                                                          testVectors[v].keyLen));
    writeBigEndian(hssKey, L, 4);
    writeBigEndian(hssSig, L - 1, 4);
    IF_PASS_MSG

    /* ---------- Invalid signature lengths ---------- */
    printf("SIG_INVALID_{OTS,LMS,HSS}_SIG_LEN tests:");
    TEST("lmsVerifySignature", SIG_INVALID_LMS_SIG_LEN, lmsVerifySignature(testVectors[v].msg,
                                                                           testVectors[v].msgLen,
                                                                           lmsSig,
                                                                           0,
                                                                           lmsKey,
                                                                           24 + m));
    TEST("lmsVerifySignature", SIG_INVALID_LMS_SIG_LEN, lmsVerifySignature(testVectors[v].msg,
                                                                           testVectors[v].msgLen,
                                                                           lmsSig,
                                                                           11 + n * (p + 1)
                                                                               + m * h,
                                                                           lmsKey,
                                                                           24 + m));
    TEST("otsComputeKc", SIG_INVALID_OTS_SIG_LEN, otsComputeKc(buff,
                                                               buff,
                                                               0,
                                                               testVectors[v].msg,
                                                               testVectors[v].msgLen,
                                                               otsSig,
                                                               3 + n * (p + 1),
                                                               otsType));

    IF_PASS_MSG


    /* ---------- Invalid types ---------- */
    printf("SIG_INVALID_{OTS,LMS}_TYPE tests:");
    TEST("otsParameterLookup", SIG_INVALID_OTS_TYPE, otsParameterLookup(-1, NULL, NULL, NULL, NULL, NULL));
    TEST("otsComputeKc", SIG_INVALID_OTS_TYPE, otsComputeKc(buff, buff, 0, buff, 100, buff, 100, -1));
    TEST("otsComputeKc", SIG_INVALID_OTS_TYPE, otsComputeKc(buff, buff, 0, buff, 100, buff, 100, 0));

    lmsSig[4] ^= 0x1;
    TEST("lmsVerifySignature", SIG_INVALID_OTS_TYPE, lmsVerifySignature(testVectors[v].msg,
                                                                        testVectors[v].msgLen,
                                                                        lmsSig,
                                                                        testVectors[v].sigLen,
                                                                        lmsKey,
                                                                        24 + m));

    lmsSig[4] ^= 0x1;
    TEST("lmsParameterLookup", SIG_INVALID_LMS_TYPE, lmsParameterLookup(-1, NULL, NULL, NULL));

    lmsKey[0] ^= 0x01;
    TEST("lmsVerifySignature", SIG_INVALID_LMS_TYPE, lmsVerifySignature(testVectors[v].msg,
                                                                        testVectors[v].msgLen,
                                                                        lmsSig,
                                                                        testVectors[v].sigLen - 4,
                                                                        lmsKey,
                                                                        24 + m));

    lmsKey[0] ^= 0x01;
    lmsSig[8 + n * (p + 1)] ^= 0x1;
    TEST("lmsVerifySignature", SIG_INVALID_LMS_TYPE, lmsVerifySignature(testVectors[v].msg,
                                                                        testVectors[v].msgLen,
                                                                        lmsSig,
                                                                        12 + n * (p + 1)
                                                                            + m * h,
                                                                        lmsKey,
                                                                        24 + m));
    lmsSig[8 + n * (p + 1)] ^= 0x1;
    IF_PASS_MSG

    /* ---------- Invalid LMS node number ---------- */
    printf("SIG_INVALID_LMS_NODE tests:");
    lmsSig[0] ^= 0x1;
    TEST("lmsVerifySignature", SIG_INVALID_LMS_NODE, lmsVerifySignature(testVectors[v].msg,
                                                                        testVectors[v].msgLen,
                                                                        lmsSig,
                                                                        12 + n * (p + 1)
                                                                            + m * h,
                                                                        lmsKey,
                                                                        24 + m));
    lmsSig[0] ^= 0x1;
    IF_PASS_MSG

    /* ---------- Invalid signature ---------- */
    printf("SIG_INVALID_SIG tests:");
    TEST("hssVerifySignature", SIG_INVALID_SIG, hssVerifySignature(testVectors[v].msg,
                                                                   testVectors[v].msgLen,
                                                                   hssSig,
                                                                   testVectors[v].sigLen,
                                                                   hssKeyInvalidSig,
                                                                   testVectors[v].keyLen));
    IF_PASS_MSG

    /* ---------- Valid signature ---------- */
    printf("SIG_OK tests:");
    TEST("hssVerifySignature", SIG_OK, hssVerifySignature(testVectors[v].msg,
                                                          testVectors[v].msgLen,
                                                          hssSig,
                                                          testVectors[v].sigLen,
                                                          hssKey,
                                                          testVectors[v].keyLen));
    IF_PASS_MSG
  }
  if(g_numberOfTestFailures != 0){
    printf("\n%d tests FAILED\n", g_numberOfTestFailures);
    return 1;
  }

  printf("\nAll tests PASSED\n");
  return 0;
}
