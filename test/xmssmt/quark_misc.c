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
 * Miscellaneous functions used for debugging and development.
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
void printVector(char* prefix, uint8_t* src, int len, int lineLen) {
  int prefixLen;

  if (prefix && src) {
    prefixLen = strlen(prefix);
    printf("%s", prefix);
    for (int i = 0; i < len; i++) {
      if ((i != 0) && ((i % lineLen) == 0)) {
        printf("\n");
        for (int j = 0; j < prefixLen; j++)
          printf(" ");
      }
      printf("%02x ", src[i]);
    }
    printf("\n");
  }
}


/**
 * Pretty-prints the given ADRS data structure.
 *
 * @param[in] adrs   Pointer to the ADRS data structure that will be printed
 *                   to the screen.
 *
 * @return void
 */
void printAdrs(const uint32_t* adrs) {
  if (adrs) {
    if (adrs[3] == 0)
      printf("[INFO] ADRS_OTS\n");
    else if (adrs[3] == 1)
      printf("[INFO] ADRS_LTREE\n");
    else if (adrs[3] == 2)
      printf("[INFO] ADRS_HTREE\n");
    printf("\tadrs.layer_addr  = %d\n", adrs[0]);
    printf("\tadrs.tree1_addr  = %d\n", adrs[1]);
    printf("\tadrs.tree0_addr  = %d\n", adrs[2]);
    printf("\tadrs.type        = %d\n", adrs[3]);
    if (adrs[3] == 0) {
      printf("\tadrs.ots_addr    = %d\n", adrs[4]);
      printf("\tadrs.chain_addr  = %d\n", adrs[5]);
      printf("\tadrs.hash_addr   = %d\n", adrs[6]);
    } else if (adrs[3] == 1) {
      printf("\tadrs.ltree_addr  = %d\n", adrs[4]);
      printf("\tadrs.tree_height = %d\n", adrs[5]);
      printf("\tadrs.tree_index  = %d\n", adrs[6]);
    } else if (adrs[3] == 2) {
      printf("\tadrs.padding     = %d\n", adrs[4]);
      printf("\tadrs.tree_height = %d\n", adrs[5]);
      printf("\tadrs.tree_index  = %d\n", adrs[6]);
    }
    printf("\tadrs.key_&_mask  = %d\n", adrs[7]);
  }
}


/**
 * Prints out a string representation of the given XMSS OID value
 *
 * @param[in] oidVal  Value that will be translated to a string
 *
 * @return void
 */
void printXmssOid(const uint32_t oidVal) {
  switch (oidVal) {
    case XMSS_SHA2_10_256:
      printf("XMSS-SHA2_10_256\n");
      break;
    case XMSS_SHA2_16_256:
      printf("XMSS-SHA2_16_256\n");
      break;
    case XMSS_SHA2_20_256:
      printf("XMSS-SHA2_20_256\n");
      break;
    default:
      printf("[ERROR] UNKNOWN XMSS OID\n");
  }
}


/**
 * Prints out a string representation of the given XMSS-MT OID value
 *
 * @param[in] oidVal  Value that will be translated to a string
 *
 * @return void
 */
void printXmssmtOid(const uint32_t oidVal) {
  switch (oidVal) {
    case XMSSMT_SHA2_20_2_256:
      printf("XMSSMT-SHA2_20/2_256\n");
      break;
    case XMSSMT_SHA2_20_4_256:
      printf("XMSSMT-SHA2_20/4_256\n");
      break;
    case XMSSMT_SHA2_40_2_256:
      printf("XMSSMT-SHA2_40/2_256\n");
      break;
    case XMSSMT_SHA2_40_4_256:
      printf("XMSSMT-SHA2_40/4_256\n");
      break;
    case XMSSMT_SHA2_40_8_256:
      printf("XMSSMT-SHA2_40/8_256\n");
      break;
    case XMSSMT_SHA2_60_3_256:
      printf("XMSSMT-SHA2_60/3_256\n");
      break;
    case XMSSMT_SHA2_60_6_256:
      printf("XMSSMT-SHA2_60/6_256\n");
      break;
    case XMSSMT_SHA2_60_12_256:
      printf("XMSSMT-SHA2_60/12_256\n");
      break;
    default:
      printf("[ERROR] UNKNOWN XMSS-MT OID\n");
  }
}


/**
 * Pretty-prints the given params data structure.
 *
 * @param[in] params   Pointer to the params data structure that
 *                     will be printed to the screen.
 *
 * @return void
 */
void printParams(const xmssmt_params_t* params) {
  printf("[INFO] params: \n");
  printf("\t      params.H = %d\n", params->H);
  printf("\t      params.w = %d\n", params->w);
  printf("\t  params.log2w = %d\n", params->log2w);
  printf("\t     params.p1 = %d\n", params->p1);
  printf("\t     params.p2 = %d\n", params->p2);
  printf("\tparams.p2Bytes = %d\n", params->p2Bytes);
  printf("\t     params.ls = %d\n", params->ls);
  printf("\t      params.p = %d\n", params->p);
  printf("\t      params.h = %d\n", params->h);
  printf("\t params.hTotal = %d\n", params->hTotal);
  printf("\t      params.d = %d\n", params->d);
  printf("\t      params.n = %d\n", params->n);
  printf("\t params.idxLen = %d\n", params->idxLen);
  printf("\tparams.oSigLen = %lu\n", params->otsSigLen);
  printf("\tparams.xSigLen = %lu\n", params->xmssSigLen);
  printf("\tparams.pKeyLen = %lu\n", params->pubKeyLen);
}


/**
 * Generic compute function that performs one of the following computations:
 *   funcType = COMPUTE_F ----> out = H( 0[31:0] || key[n-1:0] || (m0[n-1:0] ^ m1[n-1:0]) )
 *   funcType = COMPUTE_H ----> out = H( 1[31:0] || key[n-1:0] || m0[2*n-1:0] )
 *   funcType = COMPUTE_Hmsg -> out = H( 2[31:0] || key[3*n-1:0] || m[?] )
 *   funcType = COMPUTE_PRF --> out = H( 3[31:0] || key[n-1:0] || m0[31:0] )
 *
 * @param[in]  funcType  Pointer to the params data structure that
 *                       will be printed to the screen.
 * @param[out] out       Pointer to where the computation result will be written.
 * @param[in]  key       Pointer to where the key value will be read from.
 * @param[in]  keyLen    Length in bytes of the key value vector.
 * @param[in]  m0        Pointer to where the m0 value will be read from.
 * @param[in]  m1        Pointer to where the m1 value will be read from.
 * @param[in]  mLen      Length in bytes of the m0/m1 value vectors.
 * @param[in]  params    Pointer to a data structure containing the pertinent
 *                       XMSS/XMSS-MT parameters.
 *
 * @return SIG_OK iff computation was completed without issues, relevant
 *         error code otherwise.
 */
sig_retcode_t compute(const uint8_t funcType,
                      uint8_t* out,
                      const uint8_t* key,
                      const uint32_t keyLen,
                      uint8_t* m0,
                      const uint8_t* m1,
                      const uint32_t mLen,
                      const xmssmt_params_t* params) {
  sig_retcode_t retVal = SIG_INVALID_PARAM;

  /* Validate parameters */
  if (out && key && params && m0) {
    QUARK_SHA256_CTX ctx;

    retVal = SIG_OK;

    /* Initialize context as per F/H/Hmsg/PRF definition */
    quark_sha256_init(&ctx);
    ctx.Nl = 256;
    ctx.num = 32;
    memset(ctx.data, 0, 32);

    if (COMPUTE_F == funcType) {
      for (uint32_t i = 0; i < mLen; i++)
        m0[i] = m0[i] ^ m1[i];
    } else if (COMPUTE_H == funcType) {
      ctx.data[31] = 0x01;
    } else if (COMPUTE_Hmsg == funcType) {
      ctx.data[31] = 0x02;
    } else if (COMPUTE_PRF == funcType) {
      ctx.data[31] = 0x03;
    } else {
      retVal = SIG_INVALID_PARAM;
    }

    if (SIG_OK == retVal) {
      /* Compute hash component of the function */
      quark_sha256_update(&ctx, key, keyLen);
      quark_sha256_update(&ctx, m0, mLen);
      quark_sha256_final(&ctx, out);
    }
  }

  return retVal;
}


/**
 * Computes Ltree assuming no memory constraints so entire tree can
 * be computed in place.
 *
 * @param[out] pk0        Pointer to where the computed root node of the Ltree
 *                        will be written.
 * @param[in]  publicKey  Pointer to where the public key will be read from.
 * @param[in]  SEED       Pointer to where the SEED data structure will be read
 *                        from.
 * @param[in]  ADRS       Pointer to where the ADRS data structure will be read
 *                        from.
 * @param[in]  params     Pointer to a data structure containing the pertinent
 *                        XMSS/XMSS-MT parameters.
 *
 * @return SIG_OK iff computation was completed without issues, relevant
 *         error code otherwise.
 */
sig_retcode_t ltreeBig(uint8_t* pk0,
                       uint8_t* publicKey,
                       const uint8_t* SEED,
                       uint32_t* ADRS,
                       const xmssmt_params_t* params) {
  sig_retcode_t retVal = SIG_INVALID_PARAM;

  /* Validate parameters */
  if (pk0 && publicKey && SEED && ADRS && params) {
    uint32_t len = params->p;

    ADRS[ADRS_TREE_HEIGHT] = 0;
    while (len > 1) {
      for (uint32_t i = 0; i < (len >> 1); i++) {
        ADRS[ADRS_TREE_INDEX] = i;
        retVal = randHash(publicKey + i * params->n,
                          publicKey + (2 * i) * params->n,
                          publicKey + (2 * i + 1) * params->n,
                          SEED,
                          ADRS,
                          params);
        if (SIG_OK != retVal) {
          break;
        }
      }
      if (len & 0x1) {
        memcpy(publicKey + (len >> 1) * params->n,
               publicKey + (len - 1) * params->n,
               params->n);
      }
      len = (len + 1) >> 1;
      ADRS[ADRS_TREE_HEIGHT]++;
      if (SIG_OK != retVal) {
        break;
      }
    }

    if (SIG_OK == retVal) {
      /* Write result to destination */
      memcpy(pk0, publicKey, params->n);
    }
  }

  return retVal;
}


/**
 * Computes Ltree assuming memory constraints so tree is computed on an as-
 * needed basis using a stack to store the intermediate values.
 *
 * @param[out] pk0        Pointer to where the computed root node of the Ltree
 *                        will be written.
 * @param[in]  publicKey  Pointer to where the public key will be read from.
 * @param[in]  SEED       Pointer to where the SEED data structure will be read
 *                        from.
 * @param[in]  ADRS       Pointer to where the ADRS data structure will be read
 *                        from.
 * @param[in]  params     Pointer to a data structure containing the pertinent
 *                        XMSS/XMSS-MT parameters.
 *
 * @return SIG_OK iff computation was completed without issues, relevant
 *         error code otherwise.
 */
sig_retcode_t ltreeSmall(uint8_t* pk0,
                         uint8_t* publicKey,
                         const uint8_t* SEED,
                         uint32_t* ADRS,
                         const xmssmt_params_t* params) {
  sig_retcode_t retVal = SIG_INVALID_PARAM;

  /* Validate parameters */
  if (pk0 && publicKey && SEED && ADRS && params) {
    /* Stack storage */
    uint8_t stack[STACK_DEPTH][MAX_HASH_LEN];

    /* Tracks where top of stack is, points to first available */
    /* location, and indicates current stack depth             */
    uint8_t stackIdx = 0;

    /* treeIndex[0] = index for pk[i]            */
    /* treeIndex[1] = index for treeHeight = 0   */
    /* ...                                       */
    /* treeIndex[i] = index for treeHeight = i-1 */
    uint8_t treeIndex[STACK_DEPTH + 1] = {0};

    /* treeHeight[i] = treeHeight of element stored at stack location i */
    uint8_t treeHeight[STACK_DEPTH] = {0};

    /* Push the first two public key elements onto the stack to get things started */
    treeHeight[stackIdx] = 0;
    memcpy(&stack[stackIdx++][0],
           publicKey + (treeIndex[0]++) * params->n,
           params->n);
    treeHeight[stackIdx] = 0;
    memcpy(&stack[stackIdx++][0],
           publicKey + (treeIndex[0]++) * params->n,
           params->n);

    /* Perform L-tree compression until we've processed all of the public key elements */
    /* combining two distinct processing phases:                                       */
    /*    1) While all elements of public key haven't yet been processed               */
    /*    2) While combining all intermediate results to reach final value             */
    while ((treeIndex[0] < params->p) ||
        ((treeIndex[0] >= params->p) && (stackIdx > 1))) {
      /* Check if the two top-most elements of the stack have the same tree height,  */
      /* OR check if we've processed all of the public key elements and still have   */
      /* intermediate results on the stack to process to get the final result        */
      if (((treeIndex[0] < params->p) && (stackIdx >= 2)
          && (treeHeight[stackIdx - 1] == treeHeight[stackIdx - 2])) ||
          ((treeIndex[0] >= params->p) && (stackIdx > 1))) {
        /* Pop off top two elements, perform RAND_HASH and then push result back onto */
        /* the stack with updated treeHeight[] and treeIndex[] information            */

        /* Setup ADRS.treeIndex using treeIndex[i+1], where i is the value stored */
        /* in the treeHeight[] array for the elements (which should be the same)  */
        ADRS[ADRS_TREE_INDEX] =
            (uint32_t) treeIndex[treeHeight[stackIdx - 2] + 1]++;

        /* Result written to [stackIdx - 2] so its height gets incremented */
        ADRS[ADRS_TREE_HEIGHT] = (uint32_t) treeHeight[stackIdx - 2]++;

        /* Perform RAND_HASH operation using top elements of the stack */
        retVal = randHash(&stack[stackIdx - 2][0],
                          &stack[stackIdx - 2][0],
                          &stack[stackIdx - 1][0],
                          SEED,
                          ADRS,
                          params);
        if (SIG_OK != retVal) {
          break;
        }
        /* Update stack index to reflect that we consumed top two elements   */
        /* and then wrote back result (i.e., net change is one less element) */
        stackIdx = stackIdx - 1;
      }
        /* Need to push next element onto the stack (if any still unprocessed) */
      else if (treeIndex[0] < params->p) {
        treeHeight[stackIdx] = 0;
        memcpy(&stack[stackIdx++][0],
               publicKey + (treeIndex[0]++) * params->n,
               params->n);
      }
    }

    if (SIG_OK == retVal) {
      /* At this point pk0 is sitting at the top of the stack so copy */
      /* it to the destination                                        */
      memcpy(pk0, &stack[0][0], params->n);
    }
  }

  return retVal;
}


/**
 * Computes expected public key value from the given OTS signature and
 * message.
 *
 * @param[out] computedPk  Pointer to where the computed public key value
 *                         will be written.
 * @param[in]  message     Pointer to where the message that was signed will be
 *                         read from.
 * @param[in]  message     Pointer to where the signature that will be checked
 *                         will be read from.
 * @param[in]  SEED        Pointer to where the SEED data structure will be read
 *                         from.
 * @param[in]  ADRS        Pointer to where the ADRS data structure will be read
 *                         from.
 * @param[in]  params      Pointer to a data structure containing the pertinent
 *                         XMSS/XMSS-MT parameters.
 *
 * @return SIG_OK iff computation was completed without issues, relevant
 *         error code otherwise.
 */
sig_retcode_t otsPkFromSig(uint8_t* computedPk,
                           const uint8_t* message,
                           const uint8_t* signature,
                           const uint8_t* SEED,
                           uint32_t* ADRS,
                           const xmssmt_params_t* params) {
  sig_retcode_t retVal = SIG_INVALID_PARAM;

  /* Validate parameters */
  if (message && signature && params) {
    uint8_t chksumBytes[params->p2Bytes];

    /* Compute checksum */
    retVal = otsComputeChecksum(chksumBytes,
                                message,
                                params);
    if (SIG_OK == retVal) {
      /* Compute Pk candidate values using Algorithm 6 defined in the */
      /* XMSS specification                                           */
      for (int i = 0; i < params->p; i++) {
        /* Pick off the next coefficient, taking care to pull it from */
        /* the checksum when you reach the end of the message data    */
        uint32_t a = (i < params->p1) ?
                     otsCoeff(message, i, params->log2w) :
                     otsCoeff(chksumBytes, i - params->p1, params->log2w);

        /* Compute the next Pk candidate */
        ADRS[ADRS_CHAIN_ADDR] = i;
        retVal = computeChain(computedPk + i * params->n,
                              signature + i * params->n,
                              a,
                              params->w - 1 - a,
                              SEED,
                              ADRS,
                              params);
        if (SIG_OK != retVal) {
          break;
        }
      }
    }

  }

  return retVal;
}


/**
 * Performs OTS signature verfication on the given {message, signature, key} using
 * the method defined in the current IETF draft.
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
 * @param[in]  SEED         Pointer to where the SEED data structure will be read
 *                          from.
 * @param[in]  ADRS         Pointer to where the ADRS data structure will be read
 *                          from.
 * @param[in]  params       Pointer to a data structure containing the pertinent
 *                          XMSS/XMSS-MT parameters.
 *
 * @return SIG_OK iff the signature is valid for the given {message, signature, key},
 *         relevant error code othewise
 */
sig_retcode_t otsVerifySignature(const void* message,
                                 size_t messageLen,
                                 const uint8_t* signature,
                                 size_t signatureLen,
                                 const uint8_t* publicKey,
                                 size_t publicKeyLen,
                                 const uint8_t* SEED,
                                 uint32_t* ADRS,
                                 const xmssmt_params_t* params) {
  sig_retcode_t retVal = SIG_INVALID_PARAM;

  /* Validate parameters */
  if (message && signature && publicKey && params) {
    uint8_t chksumBytes[CHECKSUM_BYTE_COUNT];
    uint8_t tmpPk[MAX_HASH_LEN];

    /* Verify parameter lengths */
    if ((messageLen != params->n) ||
        (signatureLen != (params->n * params->p)) ||
        (publicKeyLen != (params->n * params->p))) {
      retVal = SIG_INVALID_PARAM;
    } else {
      /* Verify the signature, starting by computing checksum */
      retVal = otsComputeChecksum(chksumBytes,
                                  message,
                                  params);

      if (SIG_OK == retVal) {
        /* Verify signature one Pk candidate at a time, exiting the */
        /* minute there is a discrepancy                            */
        for (int i = 0; i < params->p; i++) {
          /* Pick off the next coefficient, taking care to pull it from */
          /* the checksum when you reach the end of the message data    */
          uint32_t a = (i < params->p1) ?
                       otsCoeff(message, i, params->log2w) :
                       otsCoeff(chksumBytes, i - params->p1, params->log2w);

          /* Compute the next Pk candidate and verify it matches the */
          /* given public key component                              */
          ADRS[ADRS_CHAIN_ADDR] = i;
          retVal = computeChain(tmpPk,
                                signature + i * params->n,
                                a,
                                params->w - 1 - a,
                                SEED,
                                ADRS,
                                params);
          if (SIG_OK != retVal) {
            break;
          }

          if (!memcmp(tmpPk, publicKey + i * params->n, params->n)) {
            retVal = SIG_INVALID_SIG;
            break;
          }
        }
      }
    }
  }

  return retVal;
}
