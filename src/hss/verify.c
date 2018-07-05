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
  Description : HSS verification methods and supporting functions
*/

/**
 * @file
 * All functions related to computation of HSS signature verifications.
 *
 * Includes all functions needed to perform HSS signature verificiation other
 * than endian handling and core SHA256 computations.  This file contains two
 * variants of the computation, one that assumes an emulated flash-based
 * interface for storing the signature in a virtual flash and utilizes a scratch
 * memory pool that gets allocated at initialization and passed in for storing
 * larger data structures (e.g., arrays, stacks, etc.).
 */
#include "verify.h"


/**
 * A dummy placeholder function that emulates the physical hardware's interface to FLASH memory.
 *
 * @param[in]  flash_id  An enum that specifis which flash ID to read from (ignore from now).
 * @param[in]  from      Offset (in bytes) from the start of flash where to begin reading from.
 * @param[in]  len       Number of bytes requested to be read from flash.
 * @param[out] retlen    Pointer to where the actual number of bytes read from flash will be stored.
 * @param[out] buf       Pointer to a RAM buffer where we'll store the retrieved bytes.
 * @param[in]  callback  Pointer to a function called in long running operations to do things
 *                       like kick the watchdog.  Just use NULL in this case.
 *
 * @return 0 iff read was successful, negative number otherwise
 */
int nlflash_read(uint32_t from,
                 size_t len,
                 size_t* retlen,
                 uint8_t* buf) {
  int retVal = -1;

  if (retlen && buf) {
    if (QUARK_FLASH_SIZE < (len + from)) {
      len = QUARK_FLASH_SIZE - from;
    }

    /* Dummy out the FLASH read operation using memcpy( ) to push data to buf[] and update *retLen */
    memcpy(buf, &g_flashBuff[from], len);
    *retlen = len;
    g_flashBytesRead += len;
    g_flashCnt++;

    retVal = 0;
  }

  return retVal;
}


#ifdef QUARK_USE_FLASH_CACHE
/**
 * A wrapper for the nlflash_read( ) function that we've abstracted to mimic memcpy( ),
 * and utilizes a global buffer (g_cache) to emulate a sort of cache to avoid the cost
 * of accessing flash.
 *
 * @param[out] buf     Pointer to RAM buffer where the value read from flash will be stored.
 * @param[in]  offset  Offset (in bytes) from the start of flash where to begin reading from.
 * @param[in]  len     Number of bytes requested to be read from flash.
 *
 * @return SIG_OK iff the requested bytes were read from flash, SIG_FLASH_READ_ERROR otherwise
 */
sig_retcode_t flashcpy_cached(uint8_t* buf, uint32_t offset, size_t len) {
  sig_retcode_t retVal = SIG_FLASH_READ_ERROR;
  size_t retlen;

  /* Check if requested element is in the cache in which case we can just */
  /* memcpy it to the destination                                         */
  if ((offset >= g_cacheStart) &&
      ((offset + len) <= g_cacheEnd)) {
    memcpy(buf, g_cache + (offset - g_cacheStart), len);
    retVal = SIG_OK;
  }
    /* If we can fit this item in the cache then replace the cache contents */
    /* with the flash data starting at the given offset                     */
  else if (len <= QUARK_CACHE_SIZE) {
    /* Initiate the flash read and check if it was able to read         */
    /* anything back                                                    */
    if (0 != nlflash_read(offset,
                          QUARK_CACHE_SIZE,
                          &retlen,
                          g_cache)) {
      g_cacheStart = 0;
      g_cacheEnd = 0;
    }
      /* We got something so check if it's enough or signal an error      */
    else if (retlen < len) {
      g_cacheStart = offset;
      g_cacheEnd = offset + retlen;
    }
      /* Item is now in the cache so memcpy it out to the destination     */
    else {
      g_cacheStart = offset;
      g_cacheEnd = offset + retlen;
      memcpy(buf, g_cache + (offset - g_cacheStart), len);
      retVal = SIG_OK;
    }
  }

  return retVal;
}

#else /* QUARK_USE_FLASH_CACHE */

/**
 * A wrapper for the nlflash_read( ) function that we've abstracted to mimic memcpy( ).
 *
 * @param[out] buf     Pointer to RAM buffer where the value read from flash will be stored.
 * @param[in]  offset  Offset (in bytes) from the start of flash where to begin reading from.
 * @param[in]  len     Number of bytes requested to be read from flash.
 *
 * @return SIG_OK iff the requested bytes were read from flash, SIG_FLASH_READ_ERROR otherwise
 */
sig_retcode_t flashcpy( uint8_t *buf, uint32_t offset, size_t len )
{
    sig_retcode_t retVal = SIG_OK;
    size_t        retlen;

    /* Check that the FLASH read occurred without error, and that the number */
    /* of bytes read is the number that were requested                       */
    if ( ( 0 != nlflash_read( offset, len, &retlen, buf ) ) ||
         ( retlen != len ) )
    {
        retVal = SIG_FLASH_READ_ERROR;
    }

    return retVal;
}
#endif /* QUARK_USE_FLASH_CACHE */


/**
 * Performs HSS signature verification.  This implementation emulates scratch
 * memory pool and flash-based signature storage.
 *
 * @param[in] message          Pointer to the message (or fingerprint of the message)
 *                             that the signature corresponds to.
 * @param[in] messageLen       Length in bytes of the message.
 * @param[in] signatureOffset  Offset in bytes from the start of the flash where the
 *                             signature resides.
 * @param[in] signatureLen     Length in bytes of the signature.
 * @param[in] publicKey        Pointer to the public key corresponding to the given
 *                             signature.
 * @param[in] publicKeyLen     Length in bytes of the public key.
 * @param[in] scratchBuff      Pointer to scratch memory that is used to allocate
 *                             temporary data structures.
 * @param[in] scratchLen       Length in bytes of the scratch memory pool.
 *
 * @return SIG_OK iff the signature is valid for the given {message, signature, key},
 *         relevant error code othewise
 */
sig_retcode_t hssVerifySignatureFlash(const void* message,
                                      size_t messageLen,
                                      uint32_t signatureOffset,
                                      size_t signatureLen,
                                      const uint8_t* publicKey,
                                      size_t publicKeyLen,
                                      uint8_t* scratchBuff,
                                      size_t scratchLen) {
  sig_retcode_t retVal = SIG_OK;
  uint32_t iterSigOffset;
  uint8_t* iterKey = scratchBuff;
  uint8_t* iterMsg;
  param_set_t lmsType;
  param_set_t otsType;
  uint32_t sigLevels;
  uint32_t pubLevels;
  size_t lmsKeyLen;
  size_t lmsSigLen;
  size_t iterMsgLen;
  size_t initScratchLen = scratchLen;

  /* Scratch Buffer allocation:                                                  */
  /*     iterKey[lmsKeyLen]                                                      */
  /*     iterMsg[messageLen]                                                     */
  /*     ... rest is unallocated at this level ...                               */

  /* Check input parameters */
  if (message && publicKey && scratchBuff) {
    /* Determine the number of levels in the tree chain (don't forget that the */
    /* signature stores the value (L - 1) and not L), verify that the key and  */
    /* signature values are consistent, and within the range of allowed values */
    if (L_LEN > signatureLen) {
      retVal = SIG_INVALID_HSS_SIG_LEN;
    } else {
      if (L_LEN > publicKeyLen) {
        retVal = SIG_INVALID_HSS_KEY_LEN;
      }
    }

    if (SIG_OK == retVal) {
      if (scratchLen < L_LEN) {
        retVal = SIG_INSUFFICIENT_MEMORY;
      } else {
#ifdef QUARK_USE_FLASH_CACHE
        retVal = flashcpy_cached(scratchBuff,
                                 signatureOffset + HSS_SIG_LEVELS_OFFSET,
                                 L_LEN);
#else
        retVal = flashcpy( scratchBuff, signatureOffset + HSS_SIG_LEVELS_OFFSET, L_LEN );
#endif
      }
    }

    if (SIG_OK == retVal) {
      sigLevels = readBigEndian(scratchBuff, L_LEN);
      pubLevels = readBigEndian(publicKey + HSS_KEY_LEVELS_OFFSET, L_LEN);
      if (((sigLevels + 1) != pubLevels) ||
          (HSS_MAX_LEVELS < pubLevels) ||
          (HSS_MIN_LEVELS > pubLevels)) {
        retVal = SIG_INVALID_HSS_LEVELS;
      }
    }

    if (SIG_OK == retVal) {
      /* Skip over the L-values in the signature and public key so that we've     */
      /* got raw signature/key values being pointed to by their associated        */
      /* pointers, taking care to also reduce their corresponding lengths         */
      signatureOffset += L_LEN;
      signatureLen -= L_LEN;
      publicKey += L_LEN;
      publicKeyLen -= L_LEN;

      /* Use the iteration signature and key pointers to track our progress so    */
      /* point them to the start of the embedded LMS signature/value and LMS      */
      /* public key in the HSS signature and public key respectively              */
      iterSigOffset = signatureOffset;

      /* The HSS validation is essentially a chain of LMS signature verifications */
      /* where we start with the HSS public key to validate the first public key  */
      /* in the chain against the first signature in the chain.  If that is valid */
      /* we use the validated public key to validate the next public key in the   */
      /* chain against the next signature in the chain, etc.                      */
      /*                                                                          */
      /* This continues until we reach the end of the chain at which point we use */
      /* the most recently validated public key to validate the message against   */
      /* the last signature in the chain.                                         */
      /*                                                                          */
      /* Start processing the chain which we assume has the format:               */
      /*                                                                          */
      /*              HSS_MSG                    (i = 0)                          */
      /*              HSS_KEY                                                     */
      /*              |                                                           */
      /*  publicKey --+                                                           */
      /*    HSS_SIG = LMS_SIG[0], LMS_KEY[1], LMS_SIG[1], LMS_KEY[2], ...         */
      /*              |           |                                               */
      /*  signature --+           |                                               */
      /*  message ----------------+                                               */
      /*                                                                          */
      /* After the first iteration we basically consume the chain by setting the  */
      /* new publicKey to point to the verified LMS_KEY[i+1], and move signature  */
      /* to point to LMS_SIG[i+1], and message to point to LMS_KEY[i+2].          */
      /*                                                                          */
      /*              HSS_MSG                    (i = 1, ..., L-2)                */
      /*              HSS_KEY                                                     */
      /*    HSS_SIG = LMS_SIG[0], LMS_KEY[1], LMS_SIG[1], LMS_KEY[2], ...         */
      /*                          |           |           |                       */
      /*  publicKey --------------+           |           |                       */
      /*  signature --------------------------+           |                       */
      /*  message ----------------------------------------+                       */
      /*                                                                          */
      /* This continues for (L - 2) iterations which brings us to the end of the  */
      /* chain where we set publicKey to point to LMS_KEY[L-1], signature to      */
      /* point to LMS_SIG[L-1] (which is the end of the chain), and message       */
      /* to point to HSS_MSG (message passed into the verification function)      */
      /* The result of this final iteration (assuming we haven't already failed)  */
      /* is the overall signature result.                                         */
      /*                                                                          */
      /*              HSS_MSG                                                     */
      /*              |                          (i = L-1)                        */
      /*  message ----+                                                           */
      /*              HSS_KEY                                                     */
      /*    HSS_SIG = LMS_SIG[0], ..., LMS_SIG[L-2], LMS_KEY[L-1], LMS_SIG[L-1]   */
      /*                                             |             |              */
      /*  publicKey ---------------------------------+             |              */
      /*  signature -----------------------------------------------+              */
      /*                                                                          */
      /* Special case if L = 1 sees us doing a single iteration of the form:      */
      /*                                                                          */
      /*              HSS_MSG                                                     */
      /*              |                          (L = 1)                          */
      /*  message ----+                                                           */
      /*              HSS_KEY                                                     */
      /*              |                                                           */
      /*  publicKey --+                                                           */
      /*              HSS_SIG = LMS_SIG[0]                                        */
      /*                        |                                                 */
      /*  signature ------------+                                                 */
      /*                                                                          */
      /* Combine all iterations into a single loop, detecting the final iteration */
      /* to tweak the LMS signature verification inputs to utilize the input      */
      /* message and its length instead of the next LMS public key in the chain   */
      for (uint32_t i = 0; i <= sigLevels; i++) {
        /* The key can either be stored in memory if its the first iteration, */
        /* or in the current message array.  Note that in the latter case we  */
        /* can't guarantee that the source (iterMsg[]) and destination        */
        /* (iterKey[]) won't overlap so we need to use memmove() instead of   */
        /* memcpy()                                                           */
        if (0 == i) {
          if (scratchLen < publicKeyLen) {
            retVal = SIG_INSUFFICIENT_MEMORY;
          } else {
            memcpy(scratchBuff, publicKey, publicKeyLen);
            scratchBuff += publicKeyLen;
            scratchLen -= publicKeyLen;
          }
        } else {
          if (scratchLen < iterMsgLen) {
            retVal = SIG_INSUFFICIENT_MEMORY;
          } else {
            memmove(iterKey, iterMsg, iterMsgLen);
            scratchBuff = iterKey + iterMsgLen;
            scratchLen = initScratchLen - iterMsgLen;
          }
        }

        if (SIG_OK != retVal) {
          break;
        }

        /* Validate that the current signature chain contains the necessary   */
        /* information                                                        */
        lmsType = readBigEndian(iterKey + LMS_KEY_LMS_TYPE_OFFSET, TYPE_LEN);
        otsType = readBigEndian(iterKey + LMS_KEY_OTS_TYPE_OFFSET, TYPE_LEN);
        lmsSigLen = lmsSignatureLen(lmsType, otsType);
        lmsKeyLen = lmsPublicKeyLen(lmsType);
        if ((0 == lmsSigLen) ||
            /* If it's the final iteration we don't include lmsKeyLen in the */
            /* check as we're at the end of the chain and there are no more  */
            /* public keys appended to the end since the message is now the  */
            /* actual input message and NOT the next public key              */
            ((lmsSigLen + (i != sigLevels) * lmsKeyLen) > signatureLen)) {
          retVal = SIG_INVALID_HSS_SIG_LEN;
          break;
        }

        /* The message can either be stored in memory that is passed in if it's  */
        /* the final iteration, or FLASH if it's an intermediate iteration where */
        /* we're validating the next public key in the chain.  In the latter     */
        /* case we need to fetch it from FLASH and store it in the scratch       */
        /* buffer.                                                               */
        if (i == sigLevels) {
          /* Use message passed in via memory pointer */
          iterMsg = (uint8_t*) message;
          iterMsgLen = messageLen;
        } else {
          /* Message stored in FLASH so copy it to the scratch buffer */
          if (scratchLen < lmsKeyLen) {
            retVal = SIG_INSUFFICIENT_MEMORY;
          } else {
#ifdef QUARK_USE_FLASH_CACHE
            retVal = flashcpy_cached(scratchBuff,
                                     iterSigOffset + lmsSigLen,
                                     lmsKeyLen);
#else
            retVal = flashcpy( scratchBuff, iterSigOffset + lmsSigLen, lmsKeyLen );
#endif
            if (SIG_OK == retVal) {
              iterMsg = scratchBuff;
              iterMsgLen = lmsKeyLen;
              scratchBuff += iterMsgLen;
              scratchLen -= iterMsgLen;
            }
          }
        }

        if (SIG_OK == retVal) {
          /* Verify the next public key along the chain */
          retVal = lmsVerifySignatureFlash(iterMsg,
                                           iterMsgLen,
                                           iterSigOffset,
                                           lmsSigLen,
                                           iterKey,
                                           lmsKeyLen,
                                           scratchBuff,
                                           scratchLen);
        }

        /* Break out of the loop if something is amiss */
        if (SIG_OK != retVal) {
          break;
        }

        /* Update iteration pointers (ignore range checking as we'll bail out */
        /* before it becomes an issue)                                        */
        iterSigOffset += lmsSigLen + lmsKeyLen;
        signatureLen -= lmsSigLen;
      }
    }
  } else {
    retVal = SIG_INVALID_PARAM;
  }

  return retVal;
}


/**
 * Performs HSS signature verification.
 *
 * @param[in] message          Pointer to the message (or fingerprint of the message)
 *                             that the signature corresponds to.
 * @param[in] messageLen       Length in bytes of the message.
 * @param[in] signatureOffset  Offset in bytes from the start of the flash where the
 *                             signature resides.
 * @param[in] signatureLen     Length in bytes of the signature.
 * @param[in] publicKey        Pointer to the public key corresponding to the given
 *                             signature.
 * @param[in] publicKeyLen     Length in bytes of the public key.
 *
 * @return SIG_OK iff the signature is valid for the given {message, signature, key},
 *         relevant error code othewise
 */
sig_retcode_t hssVerifySignature(const void* message,
                                 size_t messageLen,
                                 const uint8_t* signature,
                                 size_t signatureLen,
                                 const uint8_t* publicKey,
                                 size_t publicKeyLen) {
  sig_retcode_t retVal = SIG_OK;
  const uint8_t* iterSig;
  const uint8_t* iterKey;
  const uint8_t* iterMsg;
  param_set_t lmsType;
  param_set_t otsType;
  uint32_t sigLevels;
  uint32_t pubLevels;
  size_t lmsKeyLen;
  size_t lmsSigLen;
  size_t iterMsgLen;

  /* Check input parameters */
  if (message && signature && publicKey) {
    /* Determine the number of levels in the tree chain (don't forget that the */
    /* signature stores the value (L - 1) and not L), verify that the key and  */
    /* signature values are consistent, and within the range of allowed values */
    if (L_LEN > signatureLen) {
      retVal = SIG_INVALID_HSS_SIG_LEN;
    } else {
      if (L_LEN > publicKeyLen) {
        retVal = SIG_INVALID_HSS_KEY_LEN;
      }
    }

    if (SIG_OK == retVal) {
      sigLevels = readBigEndian(signature + HSS_SIG_LEVELS_OFFSET, L_LEN);
      pubLevels = readBigEndian(publicKey + HSS_KEY_LEVELS_OFFSET, L_LEN);
      if (((sigLevels + 1) != pubLevels) ||
          (HSS_MAX_LEVELS < pubLevels) ||
          (HSS_MIN_LEVELS > pubLevels)) {
        retVal = SIG_INVALID_HSS_LEVELS;
      }
    }

    if (SIG_OK == retVal) {
      /* Skip over the L-values in the signature and public key so that we've     */
      /* got raw signature/key values being pointed to by their associated        */
      /* pointers, taking care to also reduce their corresponding lengths         */
      signature += L_LEN;
      signatureLen -= L_LEN;
      publicKey += L_LEN;
      publicKeyLen -= L_LEN;

      /* Use the iteration signature and key pointers to track our progress so    */
      /* point them to the start of the embedded LMS signature/value and LMS      */
      /* public key in the HSS signature and public key respectively              */
      iterSig = signature;
      iterKey = publicKey;

      /* The HSS validation is essentially a chain of LMS signature verifications */
      /* where we start with the HSS public key to validate the first public key  */
      /* in the chain against the first signature in the chain.  If that is valid */
      /* we use the validated public key to validate the next public key in the   */
      /* chain against the next signature in the chain, etc.                      */
      /*                                                                          */
      /* This continues until we reach the end of the chain at which point we use */
      /* the most recently validated public key to validate the message against   */
      /* the last signature in the chain.                                         */
      /*                                                                          */
      /* Start processing the chain which we assume has the format:               */
      /*                                                                          */
      /*              HSS_MSG                    (i = 0)                          */
      /*              HSS_KEY                                                     */
      /*              |                                                           */
      /*  publicKey --+                                                           */
      /*    HSS_SIG = LMS_SIG[0], LMS_KEY[1], LMS_SIG[1], LMS_KEY[2], ...         */
      /*              |           |                                               */
      /*  signature --+           |                                               */
      /*  message ----------------+                                               */
      /*                                                                          */
      /* After the first iteration we basically consume the chain by setting the  */
      /* new publicKey to point to the verified LMS_KEY[i+1], and move signature  */
      /* to point to LMS_SIG[i+1], and message to point to LMS_KEY[i+2].          */
      /*                                                                          */
      /*              HSS_MSG                    (i = 1, ..., L-2)                */
      /*              HSS_KEY                                                     */
      /*    HSS_SIG = LMS_SIG[0], LMS_KEY[1], LMS_SIG[1], LMS_KEY[2], ...         */
      /*                          |           |           |                       */
      /*  publicKey --------------+           |           |                       */
      /*  signature --------------------------+           |                       */
      /*  message ----------------------------------------+                       */
      /*                                                                          */
      /* This continues for (L - 2) iterations which brings us to the end of the  */
      /* chain where we set publicKey to point to LMS_KEY[L-1], signature to      */
      /* point to LMS_SIG[L-1] (which is the end of the chain), and message       */
      /* to point to HSS_MSG (message passed into the verification function)      */
      /* The result of this final iteration (assuming we haven't already failed)  */
      /* is the overall signature result.                                         */
      /*                                                                          */
      /*              HSS_MSG                                                     */
      /*              |                          (i = L-1)                        */
      /*  message ----+                                                           */
      /*              HSS_KEY                                                     */
      /*    HSS_SIG = LMS_SIG[0], ..., LMS_SIG[L-2], LMS_KEY[L-1], LMS_SIG[L-1]   */
      /*                                             |             |              */
      /*  publicKey ---------------------------------+             |              */
      /*  signature -----------------------------------------------+              */
      /*                                                                          */
      /* Special case if L = 1 sees us doing a single iteration of the form:      */
      /*                                                                          */
      /*              HSS_MSG                                                     */
      /*              |                          (L = 1)                          */
      /*  message ----+                                                           */
      /*              HSS_KEY                                                     */
      /*              |                                                           */
      /*  publicKey --+                                                           */
      /*              HSS_SIG = LMS_SIG[0]                                        */
      /*                        |                                                 */
      /*  signature ------------+                                                 */
      /*                                                                          */
      /* Combine all iterations into a single loop, detecting the final iteration */
      /* to tweak the LMS signature verification inputs to utilize the input      */
      /* message and its length instead of the next LMS public key in the chain   */
      for (uint32_t i = 0; i <= sigLevels; i++) {
        /* Validate that the chain contains the necessary information */
        lmsType = readBigEndian(iterKey + LMS_KEY_LMS_TYPE_OFFSET, TYPE_LEN);
        otsType = readBigEndian(iterKey + LMS_KEY_OTS_TYPE_OFFSET, TYPE_LEN);
        lmsSigLen = lmsSignatureLen(lmsType, otsType);
        lmsKeyLen = lmsPublicKeyLen(lmsType);
        if ((0 == lmsSigLen) ||
            /* If it's the final iteration we don't include lmsKeyLen in the */
            /* check as we're at the end of the chain and there are no more  */
            /* public keys appended to the end since the message is now the  */
            /* actual input message and NOT the next public key              */
            ((lmsSigLen + (i != sigLevels) * lmsKeyLen) > signatureLen)) {
          retVal = SIG_INVALID_HSS_SIG_LEN;
          break;
        }

        /* Update the message pointer to point to the next public key in the */
        /* chain (we already checked that the data being pointed to exists)  */
        iterMsg = (i == sigLevels) ? message : iterSig + lmsSigLen;
        iterMsgLen = (i == sigLevels) ? messageLen : lmsKeyLen;

        /* Verify the next public key along the chain */
        retVal = lmsVerifySignature(iterMsg,
                                    iterMsgLen,
                                    iterSig,
                                    lmsSigLen,
                                    iterKey,
                                    lmsKeyLen);
        if (SIG_OK != retVal) {
          break;
        }

        /* Update iteration pointers */
        iterKey = iterMsg;
        iterSig = iterMsg + lmsKeyLen;
        signatureLen -= lmsSigLen;
      }
    }
  } else {
    retVal = SIG_INVALID_PARAM;
  }

  return retVal;
}


/**
 * Performs LMS signature verification, which is a main component of HSS signature
 * verification.  This implementation emulates scratch memory pool and flash-based
 * signature storage.
 *
 * @param[in] message          Pointer to the message (or fingerprint of the message)
 *                             that the signature corresponds to.
 * @param[in] messageLen       Length in bytes of the message.
 * @param[in] signatureOffset  Offset in bytes from the start of the flash where the
 *                             signature resides.
 * @param[in] signatureLen     Length in bytes of the signature.
 * @param[in] publicKey        Pointer to the public key corresponding to the given
 *                             signature.
 * @param[in] publicKeyLen     Length in bytes of the public key.
 * @param[in] scratchBuff      Pointer to scratch memory that is used to allocate
 *                             temporary data structures.
 * @param[in] scratchLen       Length in bytes of the scratch memory pool.
 *
 * @return SIG_OK iff the signature is valid for the given {message, signature, key},
 *         relevant error code othewise
 */
sig_retcode_t lmsVerifySignatureFlash(const void* message,
                                      size_t messageLen,
                                      uint32_t signatureOffset,
                                      size_t signatureLen,
                                      const uint8_t* publicKey,
                                      size_t publicKeyLen,
                                      uint8_t* scratchBuff,
                                      size_t scratchLen) {
  sig_retcode_t retVal = SIG_OK;
  uint8_t*
      tmp;                  /* Scratch buffer used during T[i] computations       */
  const uint8_t*
      I;                    /* Pointer to I value in public key                   */
  const uint8_t*
      T1;                   /* Pointer to T[1] value in public key                */
  const uint8_t*
      sigBuff;              /* Pointer to {typeOts} storage in scratchBuff        */
  param_set_t
      pubLmsType;           /* LMS type embedded in LMS public key                */
  param_set_t
      pubOtsType;           /* OTS type embedded in LMS public key                */
  param_set_t
      sigLmsType;           /* LMS type embedded in LMS signature                 */
  param_set_t
      sigOtsType;           /* OTS type embedded in LMS signature                 */
  union hash_ctx
      ctx;                  /* Hash context used for computing T[i] values        */
  uint32_t
      H_lms;                /* LMS-related hash function                          */
  uint32_t
      m;                    /* LMS-related node data width                        */
  uint32_t
      h;                    /* LMS-related tree height                            */
  uint32_t
      q;                    /* OTS-related node value                             */
  uint32_t
      n;                    /* OTS-related hash function output width             */
  uint32_t
      p;                    /* OTS-related element length                         */
  merkle_index_t
      nodeNum;              /* Merkle tree node number that tracks our tree climb */

  /* Scratch Buffer allocation:                                                  */
  /*     tmp[TREEINT_MAX_LEN]                                                    */
  /*     q[4]                                                                    */
  /*     otsType[4]                                                              */
  /*     ... rest is unallocated at this level ...                               */

  /* Check input parameters */
  if (message && publicKey && scratchBuff) {
    /* First attempt to allocate the storage for the tmp[] buffer              */
    if (scratchLen < TREEINT_MAX_LEN) {
      retVal = SIG_INSUFFICIENT_MEMORY;
    } else {
      tmp = scratchBuff;
      scratchBuff += TREEINT_MAX_LEN;
      scratchLen -= TREEINT_MAX_LEN;
    }

    if (SIG_OK == retVal) {
      /* Slight deviation from the spec in that there are two type fields in the */
      /* public key so pull them out both now rather than just one now and one   */
      /* later                                                                   */
      if ((TYPE_LEN + TYPE_LEN) > publicKeyLen) {
        retVal = SIG_INVALID_LMS_KEY_LEN;
      } else {
        /* Extract the LMS and OTS types from the public key and use them to       */
        /* extract the LMS and OTS parameters                                      */
        pubLmsType =
            readBigEndian(publicKey + LMS_KEY_LMS_TYPE_OFFSET, TYPE_LEN);
        pubOtsType =
            readBigEndian(publicKey + LMS_KEY_OTS_TYPE_OFFSET, TYPE_LEN);
        if (SIG_OK != lmsParameterLookup(pubLmsType, &H_lms, &m, &h)) {
          retVal = SIG_INVALID_LMS_TYPE;
        } else if (SIG_OK
            != otsParameterLookup(pubOtsType, NULL, &n, NULL, &p, NULL)) {
          retVal = SIG_INVALID_OTS_TYPE;
        }
      }
    }

    if (SIG_OK == retVal) {
      /* Validate exact public key length */
      if (publicKeyLen != (24 + m)) {
        retVal = SIG_INVALID_LMS_KEY_LEN;
      } else {
        /* Extract I and T[1] values from public key */
        I = publicKey + LMS_KEY_I_OFFSET;
        T1 = publicKey + LMS_KEY_T1_OFFSET;

        /* Compute the candidate Tc by extracting the necessary information from */
        /* the signature, computing Kc, and then traversing the Merkle tree back */
        /* up to the root                                                        */
        if ((TYPE_LEN + TYPE_LEN) > signatureLen) {
          retVal = SIG_INVALID_LMS_SIG_LEN;
        }
      }
    }

    if (SIG_OK == retVal) {
      /* Extract values from FLASH which we'll need to process the LMS */
      /* signature, storing them into the scratch buffer using the     */
      /* aforementioned allocation map                                 */
      if ((q_LEN + TYPE_LEN) > scratchLen) {
        retVal = SIG_INSUFFICIENT_MEMORY;
      } else {
#ifdef QUARK_USE_FLASH_CACHE
        retVal =
            flashcpy_cached(scratchBuff, signatureOffset, q_LEN + TYPE_LEN);
#else
        retVal = flashcpy( scratchBuff, signatureOffset, q_LEN + TYPE_LEN );
#endif
        if (SIG_OK == retVal) {
          /* Extract node value (q) */
          q = readBigEndian(scratchBuff, q_LEN);
          sigBuff = scratchBuff + q_LEN;
          scratchBuff += q_LEN + TYPE_LEN;
          scratchLen -= q_LEN + TYPE_LEN;
        }
      }
    }

    if (SIG_OK == retVal) {
      /* Extract OTS type from sigBuff, validate that it matches the type */
      /* stored in the public key                                         */
      sigOtsType = readBigEndian(sigBuff + OTS_SIG_TYPE_OFFSET, TYPE_LEN);
      if (sigOtsType != pubOtsType) {
        retVal = SIG_INVALID_OTS_TYPE;
      } else {
        /* Validate signature is right length */
        if (signatureLen != (12 + n * (p + 1) + m * h)) {
          retVal = SIG_INVALID_LMS_SIG_LEN;
        }
      }
    }

    if (SIG_OK == retVal) {
      /* Extract the LMS type from the signature and verify that it matches the  */
      /* value we extracted from the public key (re-use sigBuff[] so we can skip */
      /* memory space check                                                      */
#ifdef QUARK_USE_FLASH_CACHE
      if (SIG_OK != flashcpy_cached((uint8_t*) sigBuff,
                                    signatureOffset + LMS_SIG_TYPE_OFFSET(n, p),
                                    TYPE_LEN))
#else
        if ( SIG_OK != flashcpy( (uint8_t *)sigBuff, signatureOffset + LMS_SIG_TYPE_OFFSET( n, p), TYPE_LEN ) )
#endif
      {
        retVal = SIG_FLASH_READ_ERROR;
      } else {
        sigLmsType = readBigEndian(sigBuff, TYPE_LEN);
        if (sigLmsType != pubLmsType) {
          retVal = SIG_INVALID_LMS_TYPE;
        }
      }
    }

    if (SIG_OK == retVal) {
      /* Validate that node (q) is valid */
      if (q >= ((uint32_t) 1 << h)) {
        retVal = SIG_INVALID_LMS_NODE;
      } else {
        /* Compute Kc and then update signature pointer/length to move on to the   */
        /* start of the path component of the signature                            */
        /*                                                                         */
        /* Store the result into the tmp[] buffer where we will do the Merkle tree */
        /* climb                                                                   */
        retVal = otsComputeKcFlash(tmp + TREELEAF_PK_OFFSET,
                                   I,
                                   q,
                                   message,
                                   messageLen,
                                   signatureOffset + LMS_SIG_OTS_SIG_OFFSET,
                                   OTS_SIG_OFFSET(n, p),
                                   sigOtsType,
                                   scratchBuff,
                                   scratchLen);
      }
    }

    if (SIG_OK == retVal) {
      /* Increment the offsets pointing into the signature stored in FLASH and */
      /* decrement the corresponding signature length as it is consumed        */
      signatureOffset += LMS_SIG_P0_OFFSET(n, p);
      signatureLen -= LMS_SIG_P0_OFFSET(n, p);

      /* Compute Tc using the method described in the standard, with a slight tweak     */
      /* in that we try to do everything using a single statically-defined buffer (tmp) */
      nodeNum = q + (1 << h);
      memcpy(tmp + TREELEAF_I_OFFSET, I, I_LEN);
      writeBigEndian(tmp + TREELEAF_q_OFFSET, nodeNum, q_LEN);
      writeBigEndian(tmp + TREELEAF_D_OFFSET, D_LEAF, D_LEN);
      if (nodeNum & 0x1) {
        quark_hash(H_lms,
                   &ctx,
                   tmp + TREEINT_PK_OFFSET + n,
                   tmp,
                   TREELEAF_OFFSET(n));
#ifdef QUARK_USE_FLASH_CACHE
        retVal = flashcpy_cached(tmp + TREELEAF_PK_OFFSET, signatureOffset, n);
#else
        retVal = flashcpy( tmp + TREELEAF_PK_OFFSET, signatureOffset, n );
#endif
      } else {
        quark_hash(H_lms,
                   &ctx,
                   tmp + TREEINT_PK_OFFSET,
                   tmp,
                   TREELEAF_OFFSET(n));
#ifdef QUARK_USE_FLASH_CACHE
        retVal =
            flashcpy_cached(tmp + TREELEAF_PK_OFFSET + n, signatureOffset, n);
#else
        retVal = flashcpy( tmp + TREELEAF_PK_OFFSET + n, signatureOffset, n );
#endif
      }
      writeBigEndian(tmp + TREELEAF_D_OFFSET, D_INTR, D_LEN);
    }

    if (SIG_OK == retVal) {
      /* Start ascending the tree until we're back at the root */
      while (nodeNum > 1) {
        nodeNum /= 2;
        signatureOffset += n;
        writeBigEndian(tmp + TREELEAF_q_OFFSET, nodeNum, q_LEN);
        if (nodeNum & 0x1) {
          quark_hash(H_lms,
                     &ctx,
                     tmp + TREELEAF_PK_OFFSET + n,
                     tmp,
                     TREEINT_OFFSET(n));
#ifdef QUARK_USE_FLASH_CACHE
          retVal =
              flashcpy_cached(tmp + TREELEAF_PK_OFFSET, signatureOffset, n);
#else
          retVal = flashcpy( tmp + TREELEAF_PK_OFFSET, signatureOffset, n);
#endif
        } else {
          quark_hash(H_lms,
                     &ctx,
                     tmp + TREELEAF_PK_OFFSET,
                     tmp,
                     TREEINT_OFFSET(n));
#ifdef QUARK_USE_FLASH_CACHE
          retVal =
              flashcpy_cached(tmp + TREELEAF_PK_OFFSET + n, signatureOffset, n);
#else
          retVal = flashcpy( tmp + TREELEAF_PK_OFFSET + n, signatureOffset, n);
#endif
        }
        if (SIG_OK != retVal) {
          break;
        }
      }
    }

    if (SIG_OK == retVal) {
      /* At this point the potential Tc is stored in tmp[] at either: */
      /* tmp[TREELEAF_PK_OFFSET]      if (nodeNum & 0x1 == 0)         */
      /* tmp[TREELEAF_PK_OFFSET + n]  if (nodeNum & 0x1 == 1)         */
      /*                                                              */
      /* So we just need to compare it to the expected value T[1] to  */
      /* get the final signature result                               */
      if (nodeNum & 0x1) {
        retVal = (0 == memcmp(T1, tmp + TREELEAF_PK_OFFSET + n, n)) ? SIG_OK
                                                                    : SIG_INVALID_SIG;
      } else {
        retVal = (0 == memcmp(T1, tmp + TREELEAF_PK_OFFSET, n)) ? SIG_OK
                                                                : SIG_INVALID_SIG;
      }
    }
  } else {
    retVal = SIG_INVALID_PARAM;
  }

  return retVal;
}


/**
 * Performs LMS signature verification, which is a main component of HSS signature
 * verification.
 *
 * @param[in] message       Pointer to the message (or fingerprint of the message)
 *                          that the signature corresponds to.
 * @param[in] messageLen    Length in bytes of the message.
 * @param[in] signature     Pointer to the signature that will be verified.
 * @param[in] signatureLen  Length in bytes of the signature.
 * @param[in] publicKey     Pointer to the public key corresponding to the given
 *                          signature.
 * @param[in] publicKeyLen  Length in bytes of the public key.
 *
 * @return SIG_OK iff the signature is valid for the given {message, signature, key},
 *         relevant error code othewise
 */
sig_retcode_t lmsVerifySignature(const void* message,
                                 size_t messageLen,
                                 const uint8_t* signature,
                                 size_t signatureLen,
                                 const uint8_t* publicKey,
                                 size_t publicKeyLen) {
  sig_retcode_t retVal = SIG_OK;
  uint8_t tmp[TREEINT_MAX_LEN
  ]; /* Scratch buffer used during T[i] computations       */
  const uint8_t*
      I;                    /* Pointer to I value in public key                   */
  const uint8_t*
      T1;                   /* Pointer to T[1] value in public key                */
  param_set_t
      pubLmsType;           /* LMS type embedded in LMS public key                */
  param_set_t
      pubOtsType;           /* OTS type embedded in LMS public key                */
  param_set_t
      sigLmsType;           /* LMS type embedded in LMS signature                 */
  param_set_t
      sigOtsType;           /* OTS type embedded in LMS signature                 */
  union hash_ctx
      ctx;                  /* Hash context used for computing T[i] values        */
  uint32_t
      H_lms;                /* LMS-related hash function                          */
  uint32_t
      m;                    /* LMS-related node data width                        */
  uint32_t
      h;                    /* LMS-related tree height                            */
  uint32_t
      q;                    /* OTS-related node value                             */
  uint32_t
      n;                    /* OTS-related hash function output width             */
  uint32_t
      p;                    /* OTS-related element length                         */
  merkle_index_t
      nodeNum;              /* Merkle tree node number that tracks our tree climb */

  /* Check input parameters */
  if (message && signature && publicKey) {
    /* Slight deviation from the spec in that there are two type fields in the */
    /* public key so pull them out both now rather than just one now and one   */
    /* later                                                                   */
    if ((TYPE_LEN + TYPE_LEN) > publicKeyLen) {
      retVal = SIG_INVALID_LMS_KEY_LEN;
    } else {
      /* Extract the LMS and OTS types from the public key and use them to       */
      /* extract the LMS parameters                                              */
      pubLmsType = readBigEndian(publicKey + LMS_KEY_LMS_TYPE_OFFSET, TYPE_LEN);
      pubOtsType = readBigEndian(publicKey + LMS_KEY_OTS_TYPE_OFFSET, TYPE_LEN);
      if (SIG_OK != lmsParameterLookup(pubLmsType, &H_lms, &m, &h)) {
        retVal = SIG_INVALID_LMS_TYPE;
      }
    }

    if (SIG_OK == retVal) {
      /* Validate exact public key length */
      if (publicKeyLen != (24 + m)) {
        retVal = SIG_INVALID_LMS_KEY_LEN;
      } else {
        /* Extract I and T[1] values from public key */
        I = publicKey + LMS_KEY_I_OFFSET;
        T1 = publicKey + LMS_KEY_T1_OFFSET;

        /* Compute the candidate Tc by extracting the necessary information from  */
        /* the signature, computing Kc, and then traversing the Merkle tree back  */
        /* up to the root                                                         */
        if ((TYPE_LEN + TYPE_LEN) > signatureLen) {
          retVal = SIG_INVALID_LMS_SIG_LEN;
        }
      }
    }

    if (SIG_OK == retVal) {
      /* Extract node value (q) and then re-align signature pointer/length to   */
      /* point to the embedded LM-OTS signature which we will use to compute Tc */
      q = readBigEndian(signature + LMS_SIG_q_OFFSET, q_LEN);

      /* Extract OTS type from signature, validate that it matches the type     */
      /* stored in the public key, and use it to extract the OTS parameters     */
      sigOtsType = readBigEndian(
          signature + LMS_SIG_OTS_SIG_OFFSET + OTS_SIG_TYPE_OFFSET, TYPE_LEN);
      if ((sigOtsType != pubOtsType) ||
          (SIG_OK
              != otsParameterLookup(pubOtsType, NULL, &n, NULL, &p, NULL))) {
        retVal = SIG_INVALID_OTS_TYPE;
      } else {
        /* Validate signature is right length                                     */
        if (signatureLen != (12 + n * (p + 1) + m * h)) {
          return SIG_INVALID_LMS_SIG_LEN;
        }
      }
    }

    if (SIG_OK == retVal) {
      /* Extract the LMS type from the signature and verify that it matches the  */
      /* value we extracted from the public key                                  */
      sigLmsType =
          readBigEndian(signature + LMS_SIG_TYPE_OFFSET(n, p), TYPE_LEN);
      if (sigLmsType != pubLmsType) {
        retVal = SIG_INVALID_LMS_TYPE;
      } else {
        /* Validate that node (q) is valid                                        */
        if (q >= ((uint32_t) 1 << h)) {
          retVal = SIG_INVALID_LMS_NODE;
        }
      }
    }

    if (SIG_OK == retVal) {
      /* Compute Kc and then update signature pointer/length to move on to the   */
      /* start of the path component of the signature                            */
      /*                                                                         */
      /* Store the result into the tmp[] buffer where we will do the Merkle tree */
      /* climb                                                                   */
      retVal = otsComputeKc(tmp + TREELEAF_PK_OFFSET,
                            I,
                            q,
                            message,
                            messageLen,
                            signature + LMS_SIG_OTS_SIG_OFFSET,
                            OTS_SIG_OFFSET(n, p),
                            sigOtsType);
    }

    if (SIG_OK == retVal) {
      signature += LMS_SIG_P0_OFFSET(n, p);
      signatureLen -= LMS_SIG_P0_OFFSET(n, p);

      /* Compute Tc using the method described in the standard, with a slight tweak     */
      /* in that we try to do everything using a single statically-defined buffer (tmp) */
      nodeNum = q + (1 << h);
      memcpy(tmp + TREELEAF_I_OFFSET, I, I_LEN);
      writeBigEndian(tmp + TREELEAF_q_OFFSET, nodeNum, q_LEN);
      writeBigEndian(tmp + TREELEAF_D_OFFSET, D_LEAF, D_LEN);
      if (nodeNum & 0x1) {
        quark_hash(H_lms,
                   &ctx,
                   tmp + TREEINT_PK_OFFSET + n,
                   tmp,
                   TREELEAF_OFFSET(n));
        memcpy(tmp + TREELEAF_PK_OFFSET, signature, n);
      } else {
        quark_hash(H_lms,
                   &ctx,
                   tmp + TREEINT_PK_OFFSET,
                   tmp,
                   TREELEAF_OFFSET(n));
        memcpy(tmp + TREELEAF_PK_OFFSET + n, signature, n);
      }
      writeBigEndian(tmp + TREELEAF_D_OFFSET, D_INTR, D_LEN);

      /* Start ascending the tree until we're back at the root */
      while (nodeNum > 1) {
        nodeNum /= 2;
        signature += n;
        writeBigEndian(tmp + TREELEAF_q_OFFSET, nodeNum, q_LEN);
        if (nodeNum & 0x1) {
          quark_hash(H_lms,
                     &ctx,
                     tmp + TREELEAF_PK_OFFSET + n,
                     tmp,
                     TREEINT_OFFSET(n));
          memcpy(tmp + TREELEAF_PK_OFFSET, signature, n);
        } else {
          quark_hash(H_lms,
                     &ctx,
                     tmp + TREELEAF_PK_OFFSET,
                     tmp,
                     TREEINT_OFFSET(n));
          memcpy(tmp + TREELEAF_PK_OFFSET + n, signature, n);
        }
      }

      /* At this point the potential Tc is stored in tmp[] at either: */
      /* tmp[TREELEAF_PK_OFFSET]      if (nodeNum & 0x1 == 0)         */
      /* tmp[TREELEAF_PK_OFFSET + n]  if (nodeNum & 0x1 == 1)         */
      /*                                                              */
      /* So we just need to compare it to the expected value T[1] to  */
      /* get the final signature result                               */
      if (nodeNum & 0x1) {
        retVal = (0 == memcmp(T1, tmp + TREELEAF_PK_OFFSET + n, n)) ? SIG_OK
                                                                    : SIG_INVALID_SIG;
      } else {
        retVal = (0 == memcmp(T1, tmp + TREELEAF_PK_OFFSET, n)) ? SIG_OK
                                                                : SIG_INVALID_SIG;
      }
    }
  } else {
    retVal = SIG_INVALID_PARAM;
  }

  return retVal;
}


/**
 * Computes the expected OTS signature length given the OTS type.
 *
 * @param[in] otsType  Value representing the given OTS signature's type.
 *
 * @return Length in bytes of the OTS' signature for the given type.
 */
size_t otsSignatureLen(param_set_t otsType) {
  size_t retVal = 0;
  uint32_t n;
  uint32_t p;

  /* Ensure type is valid */
  if (SIG_OK == otsParameterLookup(otsType, NULL, &n, NULL, &p, NULL)) {
    retVal = TYPE_LEN + n * (p + 1);
  }

  return retVal;
}


/**
 * Computes the expected OTS public key length given the OTS type.
 *
 * @param[in] otsType  Value representing the given OTS signature's type.
 *
 * @return Length in bytes of the OTS' public key for the given type.
 */
size_t otsPublicKeyLen(param_set_t otsType) {
  size_t retVal = 0;
  uint32_t n;

  /* Ensure type is valid */
  if (SIG_OK == otsParameterLookup(otsType, NULL, &n, NULL, NULL, NULL)) {
    retVal = (TYPE_LEN + I_LEN + q_LEN + n);
  }

  return retVal;
}


/**
 * Computes the expected LMS signature length given the LMS type.
 *
 * @param[in] otsType  Value representing the given LMS signature's type.
 *
 * @return Length in bytes of the LMS' signature for the given type.
 */
size_t lmsSignatureLen(param_set_t lmsType,
                       param_set_t otsType) {
  size_t retVal = 0;
  uint32_t h;
  uint32_t m;

  /* Ensure types are valid */
  if ((SIG_OK == lmsParameterLookup(lmsType, NULL, &m, &h)) &&
      (SIG_OK == otsParameterLookup(otsType, NULL, NULL, NULL, NULL, NULL))) {
    retVal = TYPE_LEN + q_LEN + otsSignatureLen(otsType) + m * h;
  }

  return retVal;
}


/**
 * Computes the expected LMS public key length given the LMS type.
 *
 * @param[in] otsType  Value representing the given LMS signature's type.
 *
 * @return Length in bytes of the LMS' public key for the given type.
 */
size_t lmsPublicKeyLen(param_set_t lmsType) {
  size_t retVal = 0;
  uint32_t m;

  /* Ensure type is valid */
  if (SIG_OK == lmsParameterLookup(lmsType, NULL, &m, NULL)) {
    retVal = (TYPE_LEN + TYPE_LEN + I_LEN + m);
  }

  return retVal;
}


/**
 * Computes OTS public key candidate for the given message and signature, as
 * per Algorithm 4b in the current IETF draft.  This implementation emulates
 * scratch memory pool and flash-based signature storage.
 *
 * @param[out] computedKc       Pointer to where the computed public key candidate
 *                              will be stored.
 * @param[in]  I                Pointer to the given OTS public key's LMS key
 *                              identifier array.
 * @param[in]  q                Node index value.
 * @param[in]  message          Pointer to the message (or fingerprint of the message)
 *                              that the signature corresponds to.
 * @param[in]  messageLen       Length in bytes of the message.
 * @param[in]  signatureOffset  Offset in bytes from the start of the flash where the
 *                              signature resides.
 * @param[in]  signatureLen     Length in bytes of the signature.
 * @param[in]  sigType          Expected OTS signature type value.
 * @param[in]  scratchBuff      Pointer to scratch memory that is used to allocate
 *                              temporary data structures.
 * @param[in]  scratchLen       Length in bytes of the scratch memory pool.
 *
 * @return SIG_OK iff the public key candidate value was computed successfully,
 *         relevant error code othewise
 */
sig_retcode_t otsComputeKcFlash(uint8_t* computedKc,
                                const uint8_t* I,
                                merkle_index_t q,
                                const void* message,
                                size_t messageLen,
                                uint32_t signatureOffset,
                                size_t signatureLen,
                                param_set_t sigType,
                                uint8_t* scratchBuff,
                                size_t scratchLen) {
  sig_retcode_t retVal = SIG_OK;
  uint32_t
      H;         /* Hash function identifier                                        */
  uint32_t
      n;         /* Length of hash function output in bytes                         */
  uint32_t
      w;         /* Winternitz value that dictates                                  */
  uint32_t
      p;         /* Number of w-bit digits that need to be processed                */
  uint32_t
      ls;        /* Left shift index for aligning checksum                          */
  uint32_t
      maxDigit;  /* Value 2^w-1 used during Kc computation                          */
  uint8_t*
      Q;         /* Array to hold hash output with 2-byte checksum                  */
  uint8_t*
      tmp;       /* Array to hold iteration values                                  */
  union hash_ctx
      ctx;       /* Hashing context for computing Z[i] and Kc values                */

  /* Scratch Buffer allocation:                                                  */
  /*     tmp[OTS_MAX_LEN]                                                        */
  /*     Q[MAX_HASH_LEN + 2]                                                     */
  /*     ... rest is unallocated at this level ...                               */

  /* Validate input parameters */
  if (computedKc && I && message && scratchBuff) {
    /* First attempt to allocate storage for the Q[] and tmp[] buffers */
    if (scratchLen < (OTS_MAX_LEN + MAX_HASH_LEN + 2)) {
      retVal = SIG_INSUFFICIENT_MEMORY;
    } else {
      tmp = scratchBuff;
      Q = scratchBuff + OTS_MAX_LEN;
      scratchBuff += OTS_MAX_LEN + MAX_HASH_LEN + 2;
      scratchLen -= OTS_MAX_LEN + MAX_HASH_LEN + 2;
    }

    if (SIG_OK == retVal) {
      /* Validate signature length */
      if (TYPE_LEN > signatureLen) {
        retVal = SIG_INVALID_OTS_SIG_LEN;
      }
    }

    if (SIG_OK == retVal) {
      /* Extract OTS signature parameters from the sigType */
      retVal = otsParameterLookup(sigType, &H, &n, &w, &p, &ls);
    }

    if (SIG_OK == retVal) {
      /* Validate signature length */
      if (signatureLen != (4 + n * (p + 1))) {
        retVal = SIG_INVALID_OTS_SIG_LEN;
      }
    }

    if (SIG_OK == retVal) {
      /* Extract C from the signature, write it to message hash prefix    */
      /* vector tmp[] and advance signature pointer to Y[0]               */
#ifdef QUARK_USE_FLASH_CACHE
      retVal =
          flashcpy_cached(tmp + MSG_C_OFFSET, signatureOffset + TYPE_LEN, n);
#else
      retVal = flashcpy( tmp + MSG_C_OFFSET, signatureOffset + TYPE_LEN, n );
#endif
      if (SIG_OK == retVal) {
        signatureOffset += TYPE_LEN + n;
      }
    }

    if (SIG_OK == retVal) {
      /* Compute Kc */
      /* Step 1: compute hash of message and its randomized prefix */

      /* Copy the rest of the message hash prefix to the tmp[] vector */
      memcpy(tmp + MSG_I_OFFSET, I, I_LEN);
      writeBigEndian(tmp + MSG_q_OFFSET, q, q_LEN);
      writeBigEndian(tmp + MSG_D_OFFSET, D_MESG, D_LEN);

      /* First hash the prefix w/o the message */
      quark_hashInit(H, &ctx);
      quark_hashUpdate(H, &ctx, tmp, MSG_MSG_OFFSET(n));
      quark_hashUpdate(H, &ctx, message, messageLen);
      quark_hashFinal(H, &ctx, Q);

      /* Step 2: compute checksum and write it to to the end of the hash */
      otsComputeChecksum(&Q[n], Q, n, w, ls);

      /* Step 3: Compute the Kc value in a staggered fashion where we generate Z[i] */
      /*         values and then mix them into the final calculation of Kc as they  */
      /*         become available so that we don't need to allocate a lot of        */
      /*         memory.  Store the result context in ctx, and use iterCtx to track */
      /*         the loop computations                                              */

      /* Setup the outer (result) context and hash its prefix, taking care to       */
      /* use the same tmp buffer as we'll use for the Z[i] hashing                  */
      quark_hashInit(H, &ctx);
      memcpy(tmp + OTS_I_OFFSET, I, I_LEN);
      writeBigEndian(tmp + OTS_q_OFFSET, q, q_LEN);
      writeBigEndian(tmp + OTS_D_OFFSET, D_PBLC, D_LEN);
      quark_hashUpdate(H, &ctx, tmp, OTS_Z_OFFSET);

      /* Compute the Z[i] component and mix it into the outer context*/
      maxDigit = (1 << w) - 1;
      for (uint32_t i = 0; i < p; i++) {
        /* Compute Z[i], using the fact we don't need to reload the start of the */
        /* tmp buffer since it is the same ( I || q ) as what we setup before.   */
        writeBigEndian(tmp + OTS_i_OFFSET, i, i_LEN);

        /* Fetch Y[i] and update the signature flash offset to point to Y[i+1] */
#ifdef QUARK_USE_FLASH_CACHE
        retVal = flashcpy_cached(tmp + OTS_TMP_OFFSET, signatureOffset, n);
#else
        retVal = flashcpy( tmp + OTS_TMP_OFFSET, signatureOffset, n );
#endif
        if (SIG_OK != retVal) {
          break;
        }
        signatureOffset += n;

        /* Compute Z[i] */
        uint32_t a = otsCoeff(Q, i, w);
        for (uint32_t j = a; j < maxDigit; j++) {
          union hash_ctx iterCtx;
          tmp[OTS_j_OFFSET] = j;
          quark_hash(H, &iterCtx, tmp + OTS_TMP_OFFSET, tmp, OTS_OFFSET(n));
        }

        /* Mix Z[i] into the computation of Kc */
        quark_hashUpdate(H, &ctx, tmp + OTS_TMP_OFFSET, n);
      }

      /* Complete the Kc computation */
      quark_hashFinal(H, &ctx, computedKc);
      retVal = SIG_OK;
    }
  } else {
    retVal = SIG_INVALID_PARAM;
  }

  return retVal;
}


/**
 * Computes public key candidate for the given message and signature, as
 * per Algorithm 4b in the current IETF draft.  This implementation emulates
 * scratch memory pool and flash-based signature storage.
 *
 * @param[out] computedKc    Pointer to where the computed public key candidate
 *                           will be stored.
 * @param[in]  I             Pointer to the given OTS public key's LMS key
 *                           identifier array.
 * @param[in]  q             Node index value.
 * @param[in]  message       Pointer to the message (or fingerprint of the message)
 *                           that the signature corresponds to.
 * @param[in]  messageLen    Length in bytes of the message.
 * @param[in]  signature     Pointer to the OTS signature.
 * @param[in]  signatureLen  Length in bytes of the signature.
 * @param[in]  sigType       Expected OTS signature type value.
 *
 * @return SIG_OK iff the public key candidate value was computed successfully,
 *         relevant error code othewise
 */
sig_retcode_t otsComputeKc(uint8_t* computedKc,
                           const uint8_t* I,
                           merkle_index_t q,
                           const void* message,
                           size_t messageLen,
                           const uint8_t* signature,
                           size_t signatureLen,
                           param_set_t pubType) {
  sig_retcode_t retVal = SIG_OK;
  param_set_t
      sigType;             /* Signature type extracted from signature itself         */
  uint32_t
      H;                   /* Hash function identifier                               */
  uint32_t
      n;                   /* Length of hash function output in bytes                */
  uint32_t
      w;                   /* Winternitz value that dictates                         */
  uint32_t
      p;                   /* Number of w-bit digits that need to be processed       */
  uint32_t
      ls;                  /* Left shift index for aligning checksum                 */
  uint32_t
      maxDigit;            /* Value 2^w-1 used during Kc computation                 */
  const uint8_t*
      C;                   /* Pointer to n-byte randomizer vector in signature       */
  const uint8_t*
      Y;                   /* Pointer to beginning of Y[0], ..., Y[p-1] in signature */
  uint8_t Q[MAX_HASH_LEN + 2
  ]; /* Array to hold hash output with 2-byte checksum         */
  uint8_t tmp[OTS_MAX_LEN
  ];    /* Array to hold iteration values                         */
  union hash_ctx
      ctx;                 /* Hashing context for computing Z[i] and Kc values       */

  /* Validate input parameters */
  if (computedKc && I && message && signature) {
    /* Validate signature length */
    if (TYPE_LEN > signatureLen) {
      retVal = SIG_INVALID_OTS_SIG_LEN;
    }

    if (SIG_OK == retVal) {
      /* Validate extracted signature type */
      sigType = readBigEndian(signature + OTS_SIG_TYPE_OFFSET, TYPE_LEN);
      if (sigType != pubType) {
        retVal = SIG_INVALID_OTS_TYPE;
      } else {
        /* Extract OTS signature parameters from the pubType (could use sigType too) */
        if (SIG_OK != otsParameterLookup(pubType, &H, &n, &w, &p, &ls)) {
          retVal = SIG_INVALID_OTS_TYPE;
        }
      }
    }

    if (SIG_OK == retVal) {
      /* Validate signature length */
      if (signatureLen != (4 + n * (p + 1))) {
        retVal = SIG_INVALID_OTS_SIG_LEN;
      } else {
        /* Extract C and Y[0] from the signature */
        C = signature + TYPE_LEN;
        Y = C + n;

        /* Compute Kc */
        /* Step 1: compute hash of message and its randomized prefix */
        quark_hashInit(H, &ctx);
        {
          /* First hash the prefix w/o the message */
          uint8_t buff[MSG_MAX_LEN];
          memcpy(buff + MSG_I_OFFSET, I, I_LEN);
          writeBigEndian(buff + MSG_q_OFFSET, q, q_LEN);
          writeBigEndian(buff + MSG_D_OFFSET, D_MESG, D_LEN);
          memcpy(buff + MSG_C_OFFSET, C, n);
          quark_hashUpdate(H, &ctx, buff, MSG_MSG_OFFSET(n));
        }
        quark_hashUpdate(H, &ctx, message, messageLen);
        quark_hashFinal(H, &ctx, Q);

        /* Step 2: compute checksum and write it to to the end of the hash */
        otsComputeChecksum(&Q[n], Q, n, w, ls);

        /* Step 3: Compute the Kc value in a staggered fashion where we generate Z[i] */
        /*         values and then mix them into the final calculation of Kc as they  */
        /*         become available so that we don't need to allocate a lot of        */
        /*         memory.  Store the result context in ctx, and use iterCtx to track */
        /*         the loop computations                                              */

        /* Setup the outer (result) context and hash its prefix, taking care to       */
        /* use the same tmp buffer as we'll use for the Z[i] hashing                  */
        quark_hashInit(H, &ctx);
        memcpy(tmp + OTS_I_OFFSET, I, I_LEN);
        writeBigEndian(tmp + OTS_q_OFFSET, q, q_LEN);
        writeBigEndian(tmp + OTS_D_OFFSET, D_PBLC, D_LEN);
        quark_hashUpdate(H, &ctx, tmp, OTS_Z_OFFSET);

        /* Compute the Z[i] component and mix it into the outer context*/
        maxDigit = (1 << w) - 1;
        for (uint32_t i = 0; i < p; i++) {
          /* Compute Z[i], using the fact we don't need to reload the start of the */
          /* tmp buffer since it is the same ( I || q ) as what we setup before.   */
          writeBigEndian(tmp + OTS_i_OFFSET, i, i_LEN);
          memcpy(tmp + OTS_TMP_OFFSET, Y + i * n, n);
          uint32_t a = otsCoeff(Q, i, w);
          for (uint32_t j = a; j < maxDigit; j++) {
            union hash_ctx iterCtx;
            tmp[OTS_j_OFFSET] = j;
            quark_hash(H, &iterCtx, tmp + OTS_TMP_OFFSET, tmp, OTS_OFFSET(n));
          }

          /* Mix Z[i] into the computation of Kc */
          quark_hashUpdate(H, &ctx, tmp + OTS_TMP_OFFSET, n);
        }

        /* Complete the Kc computation */
        quark_hashFinal(H, &ctx, computedKc);
        retVal = SIG_OK;
      }
    }
  } else {
    retVal = SIG_INVALID_PARAM;
  }

  return retVal;
}


/**
 * Extracts the specified base-w digit from the given source array S which is a byte array that
 * we interpret as a little-endian sequence of base-w digits.
 *
 * @param[in] S  Pointer to source byte array that we'll interpret as a base-w digit array.
 * @param[in] i  Position of base-w digit that will be returned.
 * @param[in] w  Base to use to interpret the value of S.
 *
 * @return base-w digit stored at base-w index i of the source byte array.
 */
uint32_t otsCoeff(const uint8_t* S,
                  uint32_t i,
                  uint32_t w) {
  uint32_t byteOffset = (i * w) >> 3;
  uint32_t digitsPerByte = 8 / w;
  uint32_t shiftOffset = w * (~i & (digitsPerByte - 1));
  uint32_t digitMask = (1 << w) - 1;

  return ((S[byteOffset] >> shiftOffset) & digitMask);
}


/**
 * Computes a checksum over the given value array.
 *
 * @param[out] dst       Pointer to byte array where the checksum will be written as a 
 *                       byte array.
 * @param[in]  value     Pointer to the byte array that we'll interpret as a base-w digit
 *                       array and compute a checksum over.
 * @param[in]  valueLen  Length in bytes of the value byte array.
 * @param[in]  w         Base to use to interpret the value array.
 * @param[in]  ls        Number of bits to left shift checksum result by in order to 
 *                       properly align its value.
 *
 * @return void
 */
void otsComputeChecksum(uint8_t* dst,
                        uint8_t* value,
                        uint32_t valueLen,
                        uint32_t w,
                        uint32_t ls) {
  /* No need to validate inputs as function is only ever called with validated inputs */
  uint16_t sum = 0;
  uint32_t iters = (8 * valueLen) / w;
  uint32_t maxVal = (1 << w) - 1;

  /* Compute the checksum by scanning it one w-bit digit at a time */
  for (uint32_t i = 0; i < iters; i++) {
    sum += maxVal - otsCoeff(value, i, w);
  }

  /* Align checksum result */
  sum <<= ls;

  /* Write checksum result (big-endian) */
  writeBigEndian(dst, sum, 2);
}


/**
 * Uses the given OTS type value to initialize all non-NULL parameters
 * to their expected values for the given type.
 *
 * @param[in]  otsType  Value representing the given OTS signature's type.
 * @param[out] H        Pointer to where the given OTS signature's corresponding
 *                      hash function type should be written.
 * @param[out] n        Pointer to where the given OTS signature's corresponding
 *                      n value should be written.
 * @param[out] w        Pointer to where the given OTS signature's corresponding
 *                      w value should be written.
 * @param[out] p        Pointer to where the given OTS signature's corresponding
 *                      p value should be written.
 * @param[out] ls       Pointer to where the given OTS signature's corresponding
 *                      ls value should be written.
 *
 * @return SIG_OK iff the given OTS type value was known, SIG_INVALID_OTS_TYPE
 *         otherwise
 */
sig_retcode_t otsParameterLookup(param_set_t otsType,
                                 uint32_t* H,
                                 uint32_t* n,
                                 uint32_t* w,
                                 uint32_t* p,
                                 uint32_t* ls) {
  sig_retcode_t retVal = SIG_OK;
  uint32_t tmpH;
  uint32_t tmpN;
  uint32_t tmpW;
  uint32_t tmpP;
  uint32_t tmpShift;

  switch (otsType) {
    case LMOTS_SHA256_N32_W1:
      tmpH = HASH_SHA256;
      tmpN = 32;
      tmpW = 1;
      tmpP = 265;
      tmpShift = 7;
      break;
    case LMOTS_SHA256_N32_W2:
      tmpH = HASH_SHA256;
      tmpN = 32;
      tmpW = 2;
      tmpP = 133;
      tmpShift = 6;
      break;
    case LMOTS_SHA256_N32_W4:
      tmpH = HASH_SHA256;
      tmpN = 32;
      tmpW = 4;
      tmpP = 67;
      tmpShift = 4;
      break;
    case LMOTS_SHA256_N32_W8:
      tmpH = HASH_SHA256;
      tmpN = 32;
      tmpW = 8;
      tmpP = 34;
      tmpShift = 0;
      break;
    default:
      /* Unknown type */
      retVal = SIG_INVALID_OTS_TYPE;
  }

  if (SIG_OK == retVal) {
    /* Assign results to non-NULL pointers */
    if (H) *H = tmpH;
    if (n) *n = tmpN;
    if (w) *w = tmpW;
    if (p) *p = tmpP;
    if (ls) *ls = tmpShift;
  }

  return retVal;
}


/**
 * Uses the given LMS type value to initialize all non-NULL parameters
 * to their expected values for the given type.
 *
 * @param[in]  lmsType  Value representing the given LMS signature's type.
 * @param[out] H        Pointer to where the given LMS signature's corresponding
 *                      hash function type should be written.
 * @param[out] m        Pointer to where the given LMS signature's corresponding
 *                      m value should be written.
 * @param[out] h        Pointer to where the given LMS signature's corresponding
 *                      h value should be written.
 *
 * @return SIG_OK iff the given LMS type value was known, SIG_INVALID_LMS_TYPE
 *         otherwise
 */
sig_retcode_t lmsParameterLookup(param_set_t lmsType,
                                 uint32_t* H,
                                 uint32_t* m,
                                 uint32_t* h) {
  sig_retcode_t retVal = SIG_OK;
  uint32_t tmpH;
  uint32_t tmpM;
  uint32_t tmpHeight;

  switch (lmsType) {
    case LMS_SHA256_M32_H5:
      tmpH = HASH_SHA256;
      tmpM = 32;
      tmpHeight = 5;
      break;
    case LMS_SHA256_M32_H10:
      tmpH = HASH_SHA256;
      tmpM = 32;
      tmpHeight = 10;
      break;
    case LMS_SHA256_M32_H15:
      tmpH = HASH_SHA256;
      tmpM = 32;
      tmpHeight = 15;
      break;
    case LMS_SHA256_M32_H20:
      tmpH = HASH_SHA256;
      tmpM = 32;
      tmpHeight = 20;
      break;
    case LMS_SHA256_M32_H25:
      tmpH = HASH_SHA256;
      tmpM = 32;
      tmpHeight = 25;
      break;
    default:
      /* Unknown type */
      retVal = SIG_INVALID_LMS_TYPE;
  }

  if (SIG_OK == retVal) {
    /* Assign results to non-NULL pointers */
    if (H) *H = tmpH;
    if (m) *m = tmpM;
    if (h) *h = tmpHeight;
  }

  return retVal;
}
