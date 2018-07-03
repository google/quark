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
#include "quark_verify.h"

//#include "hss_vectors_001.h"
//#include "hss_ref_20_4.h"
//#include "hss_ref_20_2.h"
//#include "hss_ref_40_8.h"
//#include "hss_ref_40_4.h"
//#include "hss_ref_40_2.h"
//#include "hss_ref_60_6.h"
#include "hss_ref_60_3.h"

#define FILE_INCREMENT         20000
#define USE_FLASH_EMULATION    1

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

/*  *********************************************************
 *  *** THIS FUNCTION IS COPIED FROM hash-sigs-quark/demo.c ***
 *  *** AND THEN TWEAKED TO MEET OUR NEEDS.               ***
 *  *********************************************************
 *
 * This will read in the file into a malloc'ed area
 * The hss routines assume that everything public keys, auxilary data and
 * signatures are in contiguous memory; this is used to read them in.
 *
 * This isn't used to read in the files being signed/verified; we read
 * those in chunks within the sign()/verify() routines below.
 */
void* read_file(const char* filename, size_t* len) {
  FILE* f = fopen(filename, "r");
  if (!f)
    return 0;

  unsigned alloc_len = FILE_INCREMENT;
  uint8_t* p = malloc(alloc_len);
  if (!p)
    return 0;

  unsigned cur_len = 0;
  for (;;) {
    unsigned delta = alloc_len - cur_len;
    if (delta == 0) {
      uint8_t* q = realloc(p, alloc_len + FILE_INCREMENT);
      if (!q) {
        free(p);
        return 0;
      }
      p = q;
      alloc_len += FILE_INCREMENT;
      delta = FILE_INCREMENT;
    }
    int n = fread(p + cur_len, 1, delta, f);
    if (n <= 0)
      break;
    cur_len += n;
  }

  if (len)
    *len = cur_len;
  return p;
}


/*  *********************************************************
 *  *** THIS FUNCTION IS COPIED FROM hash-sigs-quark/demo.c ***
 *  *** AND THEN TWEAKED TO MEET OUR NEEDS.               ***
 *  *********************************************************
 *
 * This function implements the 'verify' command; this reads the public key,
 * and then for each file, reads the file and the signature from disk, and
 * attempts to verify the signature.
 */
static int verify(const char* keyname, char** files) {
  /* Step 1: read in the public key */
  char public_key_filename[strlen(keyname) + sizeof ".pub" + 1];
  size_t pub_len;
  sprintf(public_key_filename, "%s.pub", keyname);
  uint8_t* pub = read_file(public_key_filename, &pub_len);
  if (!pub) {
    printf("Error: unable to read %s\n", public_key_filename);
    return 0;
  }

  for (int i = 0; files[i]; i++) {
    printf("Verifying %s\n", files[i]);

    /* Read in the signature */
    char sig_file_name[strlen(files[i]) + sizeof(".sig") + 1];
    sprintf(sig_file_name, "%s.sig", files[i]);
    size_t sig_len;
    void* sig = read_file(sig_file_name, &sig_len);
    if (!sig) {
      printf("    %s: unable to read signature file %s\n",
             files[i],
             sig_file_name);
      continue;
    }

    /* Read in the file */
    size_t msg_len;
    void* msg = read_file(files[i], &msg_len);
    if (!msg) {
      printf("    %s: unable to read\n", files[i]);
      continue;
    }

    sig_retcode_t status;
    if (USE_FLASH_EMULATION) {
      size_t sig_off = 0;
      size_t scratchLen = 384;
      uint8_t scratchBuff[scratchLen];
      memcpy(g_flashBuff + sig_off, sig, sig_len);
      status = hssVerifySignatureFlash(msg,
                                       msg_len,
                                       sig_off,
                                       sig_len,
                                       pub,
                                       pub_len,
                                       scratchBuff,
                                       scratchLen);
    } else {
      status = hssVerifySignature(msg, msg_len, sig, sig_len, pub, pub_len);
    }

    free(sig);
    free(msg);

    if (SIG_OK == status) {
      printf("    Signature verified\n");
    } else {
      printf("    Signature NOT verified (retCode = %s)\n",
             retcode_strings[status]);
    }
  }

  return 1;
}

/* Implements a simple little command line HSS signature verification utility that  */
/* reads in a HSS public key from the <keyname> file, and then uses it to test one  */
/* or more signatures for the files specified using <sig1> ... <sigN>.              */
/*                                                                                  */
/* Note that this is a bit of a quick-and-dirty hack to build a debug utility so we */
/* have used the reference implementation's verify( ) function and its syntax which */
/* is a bit odd.  For example:                                                      */
/*   1) The public key is assumed to be stored in a file called "<keyname>.pub" so  */
/*      if your public key is in the file "hss_key.pub" then <keyname> = "hss_key"  */
/*   2) The file whose signature is being checked is passed in using <sig>, and     */
/*      the program assumes its corresponding signature can be found in a file      */
/*      named "<sig>.sig" so if you wanted to verify the signature for a file named */
/*      "signme.txt" then <sig> = "signme.txt" and you need to ensure the signature */
/*      can be found in a file named "signme.txt.sig", which needs to be present in */
/*      the same directory as "signme.txt".                                         */
/*   3) If all of the necessary files are present then the signature will be        */
/*      validated with either "Signature verified" or "Signature NOT verified"      */
/*      being printed onscreen.  In the event of a failure it will also return the  */
/*      error code so that you can check if it makes sense.                         */
int main(int argc, char** argv) {
  if (argc < 3) {
    printf("SYNTAX: demo <keyname> <sig1> ... <sigN>\n");
    return 0;
  }
  if (!verify(argv[1], &argv[2])) {
    printf("ERROR verifying\n");
  }

  return 0;
}
