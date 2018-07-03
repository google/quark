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
 *  Description : Command line interface used for batch verification.
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "quark_verify.h"

/* Determines whether we use the flash emulation-based functions */
#define USE_FLASH_EMULATION    1


/* Implements a simple little command line XMSS/XMSS-MT signature verification utility */
/* that reads in a XMSS/XMSS-MT public key from the <keyFile> file, and then uses it   */
/* to test the signature in <sigFile> for the message in <msgFile>.                    */
/*                                                                                     */
/* Note that this is a bit of a quick-and-dirty hack to build a debug utility so it is */
/* pretty rough around the edges, and aborts the minute something isn't as expected.   */
/*                                                                                     */
/* Once the check is completed it will either print out "Signature verified" or        */
/* "Signature invalid" depending on the result of the verification check.              */
int main(int argc, char** argv) {
  FILE* keyFile;
  FILE* sigFile;
  FILE* msgFile;
  size_t keyLen;
  size_t sigLen;
  size_t msgLen;
  uint8_t* msg;
  uint8_t* key;
  uint8_t* sig;
  sig_retcode_t result;

  /* Initialize PRNG */
  srand(time(NULL));

  if (argc < 4) {
    printf("SYNTAX: %s <msgFile> <keyFile> <sigFile>\n", argv[0]);
    return -1;
  }

  /* Handle the message */
  msgFile = fopen(argv[1], "rb");
  if (NULL == msgFile) {
    printf("[ERROR] unable to open %s\n", argv[1]);
    return 0;
  }
  fseek(msgFile, 0, SEEK_END);
  msgLen = ftell(msgFile);
  if (NULL == (msg = malloc(msgLen))) {
    printf("[ERROR] unable to allocate %lu bytes of memory\n", msgLen);
    return 0;
  }
  fseek(msgFile, 0, SEEK_SET);
  fread(msg, 1, msgLen, msgFile);

  /* Handle the key file */
  keyFile = fopen(argv[2], "rb");
  if (NULL == keyFile) {
    printf("[ERROR] unable to open %s\n", argv[2]);
    return 0;
  }
  fseek(keyFile, 0, SEEK_END);
  keyLen = ftell(keyFile);
  if (NULL == (key = malloc(keyLen))) {
    printf("[ERROR] unable to allocate %lu bytes of memory\n", keyLen);
    return 0;
  }
  fseek(keyFile, 0, SEEK_SET);
  fread(key, 1, keyLen, keyFile);


  /* Handle the signature */
  sigFile = fopen(argv[3], "rb");
  if (NULL == sigFile) {
    printf("[ERROR] unable to open %s\n", argv[3]);
    return 0;
  }
  fseek(sigFile, 0, SEEK_END);
  sigLen = ftell(sigFile);
  if (NULL == (sig = malloc(sigLen))) {
    printf("[ERROR] unable to allocate %lu bytes of memory\n", sigLen);
    return 0;
  }
  fseek(sigFile, 0, SEEK_SET);
  fread(sig, 1, sigLen, sigFile);

  if (USE_FLASH_EMULATION) {
    /* Putting it all together to test xmssVerifySignatureFlash( )/xmssMtVerifySignatureFlash( ) */
    size_t sigOffset = 0;
    size_t scratchLen = QUARK_SCRATCH_SIZE;
    uint8_t scratchBuff[scratchLen];
    memcpy(g_flashBuff + sigOffset, sig, sigLen);
    if (NULL != strstr(argv[1], "xmssmt")) {
      result = xmssMtVerifySignatureFlash(msg,
                                          msgLen,
                                          sigOffset,
                                          sigLen,
                                          key,
                                          keyLen,
                                          scratchBuff,
                                          scratchLen);
    } else {
      result = xmssVerifySignatureFlash(msg,
                                        msgLen,
                                        sigOffset,
                                        sigLen,
                                        key,
                                        keyLen,
                                        scratchBuff,
                                        scratchLen);
    }
  } else {
    /* Putting it all together to test xmssVerifySignature( )/xmssMtVerifySignature( ) */
    if (NULL != strstr(argv[1], "xmssmt")) {
      result = xmssMtVerifySignature(msg, msgLen, sig, sigLen, key, keyLen);
    } else {
      result = xmssVerifySignature(msg, msgLen, sig, sigLen, key, keyLen);
    }
  }

  if (SIG_OK == result)
    printf("Signature verified\n");
  else
    printf("Signature invalid\n");

  free(msg);
  free(key);
  free(sig);
  return 0;
}
