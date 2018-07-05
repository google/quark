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
#include "verify.h"

//#include "hss_vectors_001.h"
//#include "hss_ref_20_4.h"
//#include "hss_ref_20_2.h"
//#include "hss_ref_40_8.h"
//#include "hss_ref_40_4.h"
//#include "hss_ref_40_2.h"
//#include "hss_ref_60_6.h"
#include "hss_ref_60_3.h"



size_t keyLen = sizeof(hss_pubKey);
size_t msgLen = sizeof(hss_msg);
size_t sigLen = sizeof(hss_sig);

char* retcode_strings[SIG_NUM_RETCODES] = {
    "SIG_OK",
    "SIG_INVALID_SIG",
    "SIG_INVALID_PARAM",
    "SIG_INVALID_LMS_KEY_LEN",
    "SIG_INVALID_LMS_SIG_LEN",
    "SIG_INVALID_LMS_TYPE",
    "SIG_INVALID_LMS_NODE",
    "SIG_INVALID_OTS_KEY_LEN",
    "SIG_INVALID_OTS_SIG_LEN",
    "SIG_INVALID_OTS_TYPE",
    "SIG_INVALID_HSS_KEY_LEN",
    "SIG_INVALID_HSS_SIG_LEN",
    "SIG_INVALID_HSS_LEVELS",
    "SIG_FLASH_READ_ERROR",
    "SIG_INSUFFICIENT_MEMORY"
};


/* This was intended to be a test of the various failure paths that might be  */
/* exercised by the HSS verification primitives, but ultimately I ran out of  */
/* time to deliver an exhaustive test.  I will continue to develop this over  */
/* time to ensure it's relatively robust.  Until then, feel free to use it as */
/* a basic, incomplete, sanity test.                                          */
int main() {
  sig_retcode_t retVal;
  uint8_t buff[1000];
  uint32_t m, h, n, p, otsType, lmsType, L;
  int passed;

  uint8_t hssSig[sizeof(hss_sig)];
  memcpy(hssSig, hss_sig, sizeof(hssSig));

  uint8_t hssKey[sizeof(hss_pubKey)];
  memcpy(hssKey, hss_pubKey, sizeof(hssKey));

  uint8_t lmsKey[sizeof(hss_pubKey) - 4];
  memcpy(lmsKey, hss_pubKey + 4, sizeof(lmsKey));

  uint8_t lmsSig[sizeof(hss_sig) - 4];
  memcpy(lmsSig, hss_sig + 4, sizeof(lmsKey));
  lmsType = readBigEndian(lmsKey, 4);
  lmsParameterLookup(lmsType, NULL, &m, &h);

  uint8_t otsSig[sizeof(lmsSig) - 4];
  memcpy(otsSig, lmsSig + 4, sizeof(lmsKey));
  otsType = readBigEndian(&lmsKey[4], 4);
  otsParameterLookup(otsType, NULL, &n, NULL, &p, NULL);

  /* Test out the various error checks within the library to ensure they do what they should! */

  /* ---------- Invalid parameters ---------- */
  printf("SIG_INVALID_PARAM tests:\n");
  passed = 1;
  if (SIG_INVALID_PARAM
      != (retVal = otsComputeKc(NULL, NULL, 0, NULL, 0, NULL, 0, -1))) {
    printf("    FAIL (otsComputeKc): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  if (SIG_INVALID_PARAM
      != (retVal = lmsVerifySignature(NULL, 0, NULL, 0, NULL, 0))) {
    printf("    FAIL (lmsVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  if (SIG_INVALID_PARAM
      != (retVal = hssVerifySignature(NULL, 0, NULL, 0, NULL, 0))) {
    printf("    FAIL (hssVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  if (passed)
    printf("    PASSED\n");

  /* ---------- Invalid key lengths ---------- */
  printf("SIG_INVALID_{OTS,LMS,HSS}_KEY_LEN tests:\n");
  passed = 1;
  if (SIG_INVALID_LMS_KEY_LEN != (retVal = lmsVerifySignature(hss_msg,
                                                              msgLen,
                                                              lmsSig,
                                                              12 + n * (p + 1)
                                                                  + m * h,
                                                              lmsKey,
                                                              0))) {
    printf("    FAIL (lmsVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  if (SIG_INVALID_LMS_KEY_LEN != (retVal = lmsVerifySignature(hss_msg,
                                                              msgLen,
                                                              lmsSig,
                                                              12 + n * (p + 1)
                                                                  + m * h,
                                                              lmsKey,
                                                              23 + m))) {
    printf("    FAIL (lmsVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  if (SIG_INVALID_HSS_KEY_LEN != (retVal = hssVerifySignature(hss_msg,
                                                              msgLen,
                                                              hssSig,
                                                              sigLen,
                                                              hssKey,
                                                              0))) {
    printf("    FAIL (hssVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  if (passed)
    printf("    PASSED\n");

  /* ---------- Invalid HSS levels ---------- */
  printf("SIG_INVALID_HSS_LEVELS tests:\n");
  passed = 1;
  hssSig[0] ^= 0x1;
  if (SIG_INVALID_HSS_LEVELS != (retVal = hssVerifySignature(hss_msg,
                                                             msgLen,
                                                             hssSig,
                                                             sigLen,
                                                             hssKey,
                                                             keyLen))) {
    printf("    FAIL (hssVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  printf("4\n");

  hssSig[0] ^= 0x1;
  hssKey[0] ^= 0x1;
  if (SIG_INVALID_HSS_LEVELS != (retVal = hssVerifySignature(hss_msg,
                                                             msgLen,
                                                             hssSig,
                                                             sigLen,
                                                             hssKey,
                                                             keyLen))) {
    printf("    FAIL (hssVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  hssKey[0] ^= 0x1;
  L = readBigEndian(hssKey, 4);
  writeBigEndian(hssKey, HSS_MAX_LEVELS + 1, 4);
  writeBigEndian(hssSig, HSS_MAX_LEVELS, 4);
  if (SIG_INVALID_HSS_LEVELS != (retVal = hssVerifySignature(hss_msg,
                                                             msgLen,
                                                             hssSig,
                                                             sigLen,
                                                             hssKey,
                                                             keyLen))) {
    printf("    FAIL (hssVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  writeBigEndian(hssKey, L, 4);
  writeBigEndian(hssSig, L - 1, 4);
  if (passed)
    printf("    PASSED\n");

  /* ---------- Invalid signature lengths ---------- */
  printf("SIG_INVALID_{OTS,LMS,HSS}_SIG_LEN tests:\n");
  passed = 1;
  if (SIG_INVALID_LMS_SIG_LEN != (retVal = lmsVerifySignature(hss_msg,
                                                              msgLen,
                                                              lmsSig,
                                                              0,
                                                              lmsKey,
                                                              24 + m))) {
    printf("    FAIL (lmsVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  if (SIG_INVALID_LMS_SIG_LEN != (retVal = lmsVerifySignature(hss_msg,
                                                              msgLen,
                                                              lmsSig,
                                                              11 + n * (p + 1)
                                                                  + m * h,
                                                              lmsKey,
                                                              24 + m))) {
    printf("    FAIL (lmsVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  if (SIG_INVALID_OTS_SIG_LEN != (retVal = otsComputeKc(buff,
                                                        buff,
                                                        0,
                                                        hss_msg,
                                                        msgLen,
                                                        otsSig,
                                                        3 + n * (p + 1),
                                                        otsType))) {
    printf("    FAIL (otsComputeKc): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  if (passed)
    printf("    PASSED\n");


  /* ---------- Invalid types ---------- */
  printf("SIG_INVALID_{OTS,LMS}_TYPE tests:\n");
  passed = 1;
  if (SIG_INVALID_OTS_TYPE
      != (retVal = otsParameterLookup(-1, NULL, NULL, NULL, NULL, NULL))) {
    printf("    FAIL (otsParameterLookup): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  if (SIG_INVALID_OTS_TYPE
      != (retVal = otsComputeKc(buff, buff, 0, buff, 100, buff, 100, -1))) {
    printf("    FAIL (otsComputeKc): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  if (SIG_INVALID_OTS_TYPE
      != (retVal = otsComputeKc(buff, buff, 0, buff, 100, buff, 100, 0))) {
    printf("    FAIL (otsComputeKc): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  lmsSig[4] ^= 0x1;
  if (SIG_INVALID_OTS_TYPE != (retVal = lmsVerifySignature(hss_msg,
                                                           msgLen,
                                                           lmsSig,
                                                           sigLen,
                                                           lmsKey,
                                                           24 + m))) {
    printf("    FAIL (lmsVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  lmsSig[4] ^= 0x1;
  if (SIG_INVALID_LMS_TYPE
      != (retVal = lmsParameterLookup(-1, NULL, NULL, NULL))) {
    printf("    FAIL (lmsParameterLookup): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  lmsKey[0] ^= 0x01;
  if (SIG_INVALID_LMS_TYPE != (retVal = lmsVerifySignature(hss_msg,
                                                           msgLen,
                                                           lmsSig,
                                                           sigLen - 4,
                                                           lmsKey,
                                                           24 + m))) {
    printf("    FAIL (lmsVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  lmsKey[0] ^= 0x01;
  lmsSig[8 + n * (p + 1)] ^= 0x1;
  if (SIG_INVALID_LMS_TYPE != (retVal = lmsVerifySignature(hss_msg,
                                                           msgLen,
                                                           lmsSig,
                                                           12 + n * (p + 1)
                                                               + m * h,
                                                           lmsKey,
                                                           24 + m))) {
    printf("    FAIL (lmsVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  lmsSig[8 + n * (p + 1)] ^= 0x1;
  if (passed)
    printf("    PASSED\n");

  /* ---------- Invalid LMS node number ---------- */
  printf("SIG_INVALID_LMS_NODE tests:\n");
  passed = 1;
  lmsSig[0] ^= 0x1;
  if (SIG_INVALID_LMS_NODE != (retVal = lmsVerifySignature(hss_msg,
                                                           msgLen,
                                                           lmsSig,
                                                           12 + n * (p + 1)
                                                               + m * h,
                                                           lmsKey,
                                                           24 + m))) {
    printf("    FAIL (lmsVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  lmsSig[0] ^= 0x1;
  if (passed)
    printf("    PASSED\n");

  /* ---------- Invalid signature ---------- */
  printf("SIG_INVALID_SIG tests:\n");
  passed = 1;
  hssKey[12] ^= 0x1;
  if (SIG_INVALID_SIG != (retVal = hssVerifySignature(hss_msg,
                                                      msgLen,
                                                      hssSig,
                                                      sigLen,
                                                      hssKey,
                                                      keyLen))) {
    printf("    FAIL (hssVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  hssKey[12] ^= 0x1;
  if (passed)
    printf("    PASSED\n");

  /* ---------- Valid signature ---------- */
  printf("SIG_OK tests:\n");
  passed = 1;
  if (SIG_OK != (retVal = hssVerifySignature(hss_msg,
                                             msgLen,
                                             hssSig,
                                             sigLen,
                                             hssKey,
                                             keyLen))) {
    printf("    FAIL (hssVerifySignature): %s\n", retcode_strings[retVal]);
    passed = 0;
  }
  if (passed)
    printf("    PASSED\n");

  return 0;
}
