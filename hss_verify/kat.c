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
#include "c4a_verify.h"

/* List of header files containing reference vectors to be tested, please ensure */
/* that one and only one of these is uncommented                                 */
//#include "hss_vectors_001.h"
//#include "hss_ref_20_4.h"
//#include "hss_ref_20_2.h"
//#include "hss_ref_40_8.h"
//#include "hss_ref_40_4.h"
//#include "hss_ref_40_2.h"
//#include "hss_ref_60_6.h"
#include "hss_ref_60_3.h"

#define FILE_INCREMENT 20000

char *retcode_strings[SIG_NUM_RETCODES] = {
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

/* Implements a quick-and-dirty known-answer-test (KAT) command line utility */
/* that allows you to check and see if your signature primitive is (still!)  */
/* working.  The reference vectors are passed in via header files, and each  */
/* test checks that it detects a valid signature on the raw data, as well as */
/* that it catches a single bit-flip on the message yielding an invalid      */
/* signature.  Pretty basic stuff...                                         */
int main( int argc, char **argv )
{
    sig_retcode_t result;

    g_cacheStart = 0;
    g_cacheEnd   = 0;

    if ( 1 )
    {
        result = hssVerifySignature( hss_msg,
                                     msgLen,
                                     hss_sig,
                                     sigLen,
                                     hss_pubKey,
                                     keyLen );
        if ( SIG_OK == result )
            printf( "[RESULTS] hssVerifySignature computation: PASSED (%s)\n", retcode_strings[result] );
        else
            printf( "[RESULTS] hssVerifySignature computation: FAILED (%s)\n", retcode_strings[result] );

        hss_msg[8] ^= 0x1;
        result = hssVerifySignature( hss_msg,
                                     msgLen,
                                     hss_sig,
                                     sigLen,
                                     hss_pubKey,
                                     keyLen );
        hss_msg[8] ^= 0x1;
        if ( SIG_OK != result )
            printf( "[RESULTS] corrupted hssVerifySignature computation: PASSED (%s)\n", retcode_strings[result] );
        else
            printf( "[RESULTS] corrupted hssVerifySignature computation: FAILED (%s)\n", retcode_strings[result] );
    }

    if ( 1 )
    {
        uint32_t signatureOffset = 0;
        size_t   scratchLen      = C4A_SCRATCH_SIZE;
        uint8_t  scratchBuff[scratchLen];

        // Copy signature info into the g_flashBuff
        memcpy(&g_flashBuff[signatureOffset], hss_sig, sigLen);

        g_flashCnt = 0;
        g_flashBytesRead = 0;
        result = hssVerifySignatureFlash( hss_msg,
                                          msgLen,
                                          signatureOffset,
                                          sigLen,
                                          hss_pubKey,
                                          keyLen,
                                          scratchBuff,
                                          scratchLen );
        if ( SIG_OK == result )
            printf( "[RESULTS] hssVerifySignature computation: PASSED (%s)\n", retcode_strings[result] );
        else
            printf( "[RESULTS] hssVerifySignature computation: FAILED (%s)\n", retcode_strings[result] );
//        printf("g_flashCnt = %u (%u bytes)\n", g_flashCnt, g_flashBytesRead);

        hss_msg[8] ^= 0x1;
        g_flashCnt = 0;
        g_flashBytesRead = 0;
        result = hssVerifySignatureFlash( hss_msg,
                                          msgLen,
                                          signatureOffset,
                                          sigLen,
                                          hss_pubKey,
                                          keyLen,
                                          scratchBuff,
                                          scratchLen );
        hss_msg[8] ^= 0x1;
        if ( SIG_OK != result )
            printf( "[RESULTS] corrupted hssVerifySignature computation: PASSED (%s)\n", retcode_strings[result] );
        else
            printf( "[RESULTS] corrupted hssVerifySignature computation: FAILED (%s)\n", retcode_strings[result] );
//        printf("g_flashCnt = %u (%u bytes)\n", g_flashCnt, g_flashBytesRead);

    }

    return 0;
}
