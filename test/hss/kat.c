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

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "verify.h"

/* List of header files containing reference vectors to be tested, please ensure */
/* that one and only one of these is uncommented                                 */
#include "hss_vectors_001.h"
#include "hss_ref_20_4.h"
#include "hss_ref_20_2.h"
#include "hss_ref_40_8.h"
#include "hss_ref_40_4.h"
#include "hss_ref_40_2.h"
#include "hss_ref_60_6.h"
#include "hss_ref_60_3.h"
#include "test_vector.h"
#include "macros.h"
#include "ret_code_strings.h"

#define FILE_INCREMENT 20000


/* Implements a quick-and-dirty known-answer-test (KAT) command line utility */
/* that allows you to check and see if your signature primitive is (still!)  */
/* working.  The reference vectors are passed in via header files, and each  */
/* test checks that it detects a valid signature on the raw data, as well as */
/* that it catches a single bit-flip on the message yielding an invalid      */
/* signature.  Pretty basic stuff...                                         */
int main(void) {

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

  g_cacheStart = 0;
  g_cacheEnd = 0;

  for (size_t v = 0; v < sizeof(testVectors) / sizeof(testVectors[0]); v++) {
    printf("-----Using Vector: %s-----\n", testVectors[v].name);

    uint8_t hss_msg_corrupt[testVectors[v].msgLen];
    memcpy(hss_msg_corrupt, testVectors[v].msg, testVectors[v].msgLen);
    hss_msg_corrupt[8] ^= 0x1;
    printf("HSS Verify Sig tests:");


    TEST("hssVerifySignature", SIG_OK, hssVerifySignature(testVectors[v].msg,
                                                                     testVectors[v].msgLen,
                                                                     testVectors[v].sig,
                                                                     testVectors[v].sigLen,
                                                                     testVectors[v].key,
                                                                     testVectors[v].keyLen));

    TEST("hssVerifySignature", SIG_INVALID_SIG, hssVerifySignature(hss_msg_corrupt,
                                                          testVectors[v].msgLen,
                                                          testVectors[v].sig,
                                                          testVectors[v].sigLen,
                                                          testVectors[v].key,
                                                          testVectors[v].keyLen));
    IF_PASS_MSG

    printf("HSS Verify Flash Sig tests:");

    uint32_t signatureOffset = 0;
    size_t scratchLen = QUARK_SCRATCH_SIZE;
    uint8_t scratchBuff[scratchLen];

    // Copy signature info into the g_flashBuff
    memcpy(&g_flashBuff[signatureOffset], testVectors[v].sig, testVectors[v].sigLen);

    g_flashCnt = 0;
    g_flashBytesRead = 0;
    TEST("hssVerifySignatureFlash", SIG_OK, hssVerifySignatureFlash(testVectors[v].msg,
                                                              testVectors[v].msgLen,
                                                              signatureOffset,
                                                              testVectors[v].sigLen,
                                                              testVectors[v].key,
                                                              testVectors[v].keyLen,
                                                              scratchBuff,
                                                              scratchLen));

    g_flashCnt = 0;
    g_flashBytesRead = 0;
    TEST("hssVerifySignatureFlash", SIG_INVALID_SIG, hssVerifySignatureFlash(hss_msg_corrupt,
                                                                        testVectors[v].msgLen,
                                                                        signatureOffset,
                                                                        testVectors[v].sigLen,
                                                                        testVectors[v].key,
                                                                        testVectors[v].keyLen,
                                                                        scratchBuff,
                                                                        scratchLen));
    IF_PASS_MSG
  }

  if(g_numberOfTestFailures != 0){
    printf("\n%d tests FAILED\n", g_numberOfTestFailures);
    return 1;
  }

  printf("\nAll tests PASSED\n");
  return 0;
}
