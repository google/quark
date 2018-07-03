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
 *  Description : Miscellaneous functions used for debugging and development.
 */

/**
 * @file
 * Miscellaneous functions used for debugging and development.  Not intended to
 * be part of a final release.
 */
#include "quark_misc.h"


/**
 * Prints out given byte vector in a pretty-print format, using the prefix
 * string as an initial header, and aligning the data nicely.
 *
 * @param[in] prefix   Null-terminated string that will serve as the prefix to
 *                     the byte value printed to the screen.
 * @param[in] src      Pointer to the byte array that will be printed to the screen.
 * @param[in] len      Number of bytes of src that will be printed to the screen.
 * @param[in] lineLen  Number of bytes to print out on each line of the screen.
 *
 * @return void
 */
void printVector(char* prefix, uint8_t* src, size_t len, int lineLen) {
  size_t prefixLength;

  if (prefix && src) {
    prefixLength = strlen(prefix);
    printf("%s", prefix);
    for (int i = 0; i < len; i++) {
      if ((i != 0) && ((i % lineLen) == 0)) {
        printf("\n");
        for (int j = 1; j < prefixLength; j++)
          printf(" ");
      }
      printf("%02x", src[i]);
    }
    printf("\n");
  }
}


/**
 * Prints out string describing the given LMS type value.
 *
 * @param[in] prefix    Null-terminated string that will serve as the prefix to
 *                      the LMS type value string printed to the screen.
 * @param[in] typeCode  LMS type code that will be parsed.
 *
 * @return void
 */
void printLmsType(char* prefix, uint32_t typeCode) {
  printf("%s", prefix);
  switch (typeCode) {
    case LMS_SHA256_M32_H5:
      printf("LMS_SHA256_M32_H5\n");
      break;
    case LMS_SHA256_M32_H10:
      printf("LMS_SHA256_M32_H10\n");
      break;
    case LMS_SHA256_M32_H15:
      printf("LMS_SHA256_M32_H15\n");
      break;
    case LMS_SHA256_M32_H20:
      printf("LMS_SHA256_M32_H20\n");
      break;
    case LMS_SHA256_M32_H25:
      printf("LMS_SHA256_M32_H25\n");
      break;
    default:
      printf("UNKNOWN\n");
  }
}


/**
 * Prints out string describing the given OTS type value.
 *
 * @param[in] prefix    Null-terminated string that will serve as the prefix to
 *                      the OTS type value string printed to the screen.
 * @param[in] typeCode  OTS type code that will be parsed.
 *
 * @return void
 */
void printOtsType(char* prefix, uint32_t typeCode) {
  printf("%s", prefix);
  switch (typeCode) {
    case LMOTS_SHA256_N32_W1:
      printf("LMOTS_SHA256_N32_W1\n");
      break;
    case LMOTS_SHA256_N32_W2:
      printf("LMOTS_SHA256_N32_W2\n");
      break;
    case LMOTS_SHA256_N32_W4:
      printf("LMOTS_SHA256_N32_W4\n");
      break;
    case LMOTS_SHA256_N32_W8:
      printf("LMOTS_SHA256_N32_W8\n");
      break;
    default:
      printf("UNKNOWN\n");
  }
}


/**
 * Pretty-prints the given OTS signature and its components {type, C, Y[i]}
 *
 * @param[in]  prefix   Null-terminated string that will serve as the prefix to
 *                      the OTS type value string printed to the screen.
 * @param[in]  sig      Pointer to the OTS signature that will be printed to
 *                      the screen.
 * @param[out] n        Pointer to where the n parameter that is used to interpret
 *                      the contents of the OTS signature will be written.
 * @param[out] p        Pointer to where the p parameter that is used to interpret
 *                      the contents of the OTS signature will be written.
 *
 * @return void
 */
void printOtsSignature(char* prefix, uint8_t* sig, uint32_t* n, uint32_t* p) {
  uint32_t otsType;
  char str[MAX_PREFIX_LEN];
  if (prefix && sig && p && n && (MAX_PREFIX_LEN < strlen(prefix))) {
    otsType = readBigEndian(sig + OTS_SIG_TYPE_OFFSET, TYPE_LEN);
    otsParameterLookup(otsType, NULL, n, NULL, p, NULL);
    sprintf(str, "%s OTS type = ", prefix);
    printOtsType(str, otsType);
    sprintf(str, "%s        C = ", prefix);
    printVector(str, sig + OTS_SIG_C_OFFSET, *n, 32);
    for (int i = 0; i < (*p); i++) {
      sprintf(str, "%s   Y[%3d] = ", prefix, i);
      printVector(str, sig + OTS_SIG_Y_OFFSET(*n) + i * (*n), *n, 32);
    }
  }
}


/**
 * Pretty-prints the given LMS public key and its components {typeLMS, typeOTS,
 * I, T[1]}.
 *
 * @param[in] prefix    Null-terminated string that will serve as the prefix to
 *                      the OTS type value string printed to the screen.
 * @param[in] key       Pointer to the LMS public key that will be printed to
 *                      the screen.
 * @param[out] n        Pointer to where the n parameter that is used to interpret
 *                      the contents of the LMS public key will be written.
 *
 * @return void
 */
void printLmsPublicKey(char* prefix, uint8_t* key, uint32_t* n) {
  param_set_t otsType, lmsType;
  char str[MAX_PREFIX_LEN];
  if (prefix && key && n && (MAX_PREFIX_LEN < strlen(prefix))) {
    lmsType = readBigEndian(key + LMS_KEY_LMS_TYPE_OFFSET, TYPE_LEN);
    otsType = readBigEndian(key + LMS_KEY_OTS_TYPE_OFFSET, TYPE_LEN);
    otsParameterLookup(otsType, NULL, n, NULL, NULL, NULL);
    sprintf(str, "%sLMS Type = ", prefix);
    printLmsType(str, lmsType);
    sprintf(str, "%sOTS Type = ", prefix);
    printOtsType(str, otsType);
    sprintf(str, "%s       I = ", prefix);
    printVector(str, key + LMS_KEY_I_OFFSET, I_LEN, 32);
    sprintf(str, "%s    T[1] = ", prefix);
    printVector(str, key + LMS_KEY_T1_OFFSET, (*n), 32);
  }
}


/**
 * Pretty-prints the given LMS signature and its components {q, sigOTS, typeLMS, 
 * path[i]}
 *
 * @param[in]  prefix   Null-terminated string that will serve as the prefix to
 *                      the OTS type value string printed to the screen.
 * @param[in]  sig      Pointer to the LMS signature that will be printed to the
 *                      screen.
 * @param[out] n        Pointer to where the n parameter that is used to interpret
 *                      the contents of the LMS signature will be written.
 * @param[out] p        Pointer to where the p parameter that is used to interpret
 *                      the contents of the LMS signature will be written.
 * @param[out] m        Pointer to where the m parameter that is used to interpret
 *                      the contents of the LMS signature will be written.
 * @param[out] h        Pointer to where the h parameter that is used to interpret
 *                      the contents of the LMS signature will be written.
 *
 * @return void
 */
void printLmsSignature(char* prefix,
                       uint8_t* sig,
                       uint32_t* n,
                       uint32_t* p,
                       uint32_t* m,
                       uint32_t* h) {
  param_set_t otsType, lmsType;
  char str[MAX_PREFIX_LEN];
  if (prefix && sig && p && n && m && h && (MAX_PREFIX_LEN < strlen(prefix))) {
    otsType = readBigEndian(sig + LMS_SIG_OTS_SIG_OFFSET + OTS_SIG_TYPE_OFFSET,
                            TYPE_LEN);
    otsParameterLookup(otsType, NULL, n, NULL, p, NULL);
    lmsType = readBigEndian(sig + LMS_SIG_TYPE_OFFSET(*n, *p), TYPE_LEN);
    lmsParameterLookup(lmsType, NULL, m, h);
    printf("%s         q = %d\n",
           prefix,
           (int) readBigEndian(sig + LMS_SIG_q_OFFSET, q_LEN));
    sprintf(str, "%s ", prefix);
    printOtsSignature(str, sig + LMS_SIG_OTS_SIG_OFFSET, n, p);
    sprintf(str, "%s  LMS type = ", prefix);
    printLmsType(str, lmsType);
    sig += LMS_SIG_P0_OFFSET(*n, *p);
    for (int i = 0; i < *h; i++) {
      sprintf(str, "%s     P[%2d] = ", prefix, i);
      printVector(str, sig + i * (*m), *m, 32);
    }
  }
}


/**
 * Pretty-prints the given HSS public key and its components {L, keyLMS}.
 *
 * @param[in]  key  Pointer to the HSS public key that will be printed to the screen.
 *
 * @return void
 */
void printHssPublicKey(uint8_t* key) {
  param_set_t n;
  if (key) {
    printf(
        "----------------------------------------------------------------------\n");
    printf("HSS Public Key:\n");
    printf("   Levels = %d\n",
           (int) readBigEndian(key + HSS_KEY_LEVELS_OFFSET, L_LEN));
    printLmsPublicKey(" ", key + HSS_KEY_LMS_KEY_OFFSET, &n);
  }
}


/**
 * Pretty-prints the given HSS signature and its components {(L-1), 
 * sigLMS[0], keyLMS[1], sigLMS[1], ...}
 *
 * @param[in]  sig  Pointer to the HSS signature that will be printed
 *                  to the screen.
 *
 * @return void
 */
void printHssSignature(uint8_t* sig) {
  uint32_t lMinus1;
  param_set_t n, p, m, h;
  int i;
  if (sig) {
    lMinus1 = readBigEndian(sig + HSS_SIG_LEVELS_OFFSET, L_LEN);
    printf(
        "----------------------------------------------------------------------\n");
    printf("HSS Signature:\n");
    printf("  Levels - 1 = %d\n", (int) lMinus1);
    /* Re-align signature pointer to point to start of {SIG, KEY, ..., SIG} segment */
    sig += L_LEN;
    for (i = 0; i < lMinus1; i++) {
      printf("  --- LMS Signature %d ---\n", i);
      printLmsSignature("    ", sig, &n, &p, &m, &h);
      sig += 12 + n * (p + 1) + m * h;
      printf("\n  --- LMS Public Key %d ---\n", i + 1);
      printLmsPublicKey("    ", sig, &n);
      sig += 24 + n;
    }
    /* Print out final LMS Signature */
    printf("\n  --- LMS Signature %d ---\n", i);
    printLmsSignature("    ", sig, &n, &p, &m, &h);
  }
}


/**
 * Performs OTS signature verfication on the given {message, signature, key} using
 * the method outlined in section 4.7 of the current IETF draft.
 *
 * @param[in] message       Pointer to the message (or fingerprint of the message)
 *                          that the signature corresponds to.
 * @param[in] messageLen    Length in bytes of the message.
 * @param[in] signature     Offset in bytes from the start of the flash where the
 *                          signature resides.
 * @param[in] signatureLen  Length in bytes of the signature.
 * @param[in] publicKey     Pointer to the public key corresponding to the given
 *                          signature.
 * @param[in] publicKeyLen  Length in bytes of the public key.
 *
 * @return SIG_OK iff the signature is valid for the given {message, signature, key},
 *         relevant error code othewise
 */
sig_retcode_t otsVerifySignature(const void* message,
                                 size_t messageLen,
                                 const uint8_t* signature,
                                 size_t signatureLen,
                                 const uint8_t* publicKey,
                                 size_t publicKeyLen) {
  sig_retcode_t retVal = SIG_INVALID_PARAM;
  param_set_t pubType;          // Parameter set for public key
  const uint8_t* I;                // Pointer to I component of public key
  merkle_index_t q;                // Key identifier (node number)
  uint8_t Kc[MAX_HASH_LEN]; // Computed Kc value
  uint32_t
      n;                // Length (in bytes) of hash function output and K/Kc


  /* Check input parameters */
  if (message && signature && publicKey) {
    /* Validate public key length by extracting its type to derive it's */
    /* length parameter (n), and use that in the validation             */
    if (TYPE_LEN > publicKeyLen) {
      retVal = SIG_INVALID_OTS_KEY_LEN;
    } else {
      pubType = readBigEndian(publicKey + OTS_KEY_TYPE_OFFSET, TYPE_LEN);
      if (publicKeyLen != otsPublicKeyLen(pubType)) {
        retVal = SIG_INVALID_OTS_KEY_LEN;
      }
    }

    if (SIG_OK == retVal) {
      /* Extract key parameters {I, q} from the public key for computation */
      /* of the Kc value                                                   */
      I = publicKey + OTS_KEY_I_OFFSET;
      q = readBigEndian(publicKey + OTS_KEY_q_OFFSET, q_LEN);

      /* Compute Kc value from the given signature */
      retVal = otsComputeKc(Kc,
                            I,
                            q,
                            message,
                            messageLen,
                            signature,
                            signatureLen,
                            pubType);
    }

    if (SIG_OK == retVal) {
      /* Verify signature by comparing K of public key to computed Kc (need */
      /* to extract n value first though!)                                  */
      otsParameterLookup(pubType, NULL, &n, NULL, NULL, NULL);
      retVal = (0 == memcmp(Kc, publicKey + OTS_KEY_K_OFFSET, n)) ? SIG_OK
                                                                  : SIG_INVALID_SIG;
    }
  }

  return retVal;
}


/**
 * Validates the length of the given LMS public key.
 *
 * @param[in] publicKey     Pointer to the public key that is to be validated.
 * @param[in] publicKeyLen  Length in bytes of the public key.
 *
 * @return SIG_OK iff the public key is valid and the correct length, relevant
 *         error code othewise
 */
sig_retcode_t
lmsValidatePublicKey(const uint8_t* publicKey, size_t publicKeyLen) {
  sig_retcode_t retVal = SIG_INVALID_PARAM;
  param_set_t lmsType;
  size_t lmsKeyLen;

  if (publicKey) {
    /* Extract the LMS type from the given key */
    if (TYPE_LEN > publicKeyLen) {
      retVal = SIG_INVALID_LMS_KEY_LEN;
    } else {
      lmsType = readBigEndian(publicKey + LMS_KEY_LMS_TYPE_OFFSET, TYPE_LEN);

      /* Compute the expected key length and validate it */
      if (publicKeyLen != lmsPublicKeyLen(lmsType)) {
        retVal = SIG_INVALID_LMS_KEY_LEN;
      } else {
        retVal = SIG_OK;
      }
    }
  }

  return retVal;
}


/**
 * Validates the length of the given OTS public key.
 *
 * @param[in] publicKey     Pointer to the public key that is to be validated.
 * @param[in] publicKeyLen  Length in bytes of the public key.
 *
 * @return SIG_OK iff the public key is valid and the correct length, relevant
 *         error code othewise
 */
sig_retcode_t
otsValidatePublicKey(const uint8_t* publicKey, size_t publicKeyLen) {
  sig_retcode_t retVal = SIG_INVALID_PARAM;
  param_set_t otsType;
  size_t otsKeyLen;

  if (publicKey) {
    /* Extract the OTS type from the given key */
    if (TYPE_LEN > publicKeyLen) {
      retVal = SIG_INVALID_OTS_KEY_LEN;
    } else {
      otsType = readBigEndian(publicKey + OTS_KEY_TYPE_OFFSET, TYPE_LEN);

      /* Compute the expected key length and validate it */
      if (publicKeyLen != otsPublicKeyLen(otsType)) {
        retVal = SIG_INVALID_OTS_KEY_LEN;
      } else {
        retVal = SIG_OK;
      }
    }
  }

  return retVal;
}
