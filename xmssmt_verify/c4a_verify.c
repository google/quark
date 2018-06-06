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
 *  Description : HSS verification methods and supporting functions
 */

/**
 * @file
 * All functions related to computation of XMSS/XMSS-MT signature verifications.
 *
 * Includes all functions needed to perform XMSS/XMSS-MT signature verificiation
 * other than endian handling and core SHA256 computations.  This file contains
 * two variants of the computation, one that assumes an emulated flash-based
 * interface for storing the signature in a virtual flash and utilizes a scratch
 * memory pool that gets allocated at initialization and passed in for storing
 * larger data structures (e.g., arrays, stacks, etc.).
 */
#include "c4a_verify.h"

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
int nlflash_read(nlflash_id_t flash_id, uint32_t from, size_t len, size_t *retlen, uint8_t *buf, nlloop_callback_fp callback)
{
    int retVal = -1;

    if ( retlen && buf && g_flashBuff )
    {
        if ( C4A_FLASH_SIZE < ( len + from ) )
        {
            len = C4A_FLASH_SIZE - from;
        }

        /* Dummy out the FLASH read operation using memcpy( ) to push data to buf[] and update *retLen */
        memcpy( buf, &g_flashBuff[from], len );
        *retlen = len;
        g_flashBytesRead += len;
        g_flashCnt++;

        retVal = 0;
    }

    return retVal;
}


#ifdef C4A_USE_FLASH_CACHE
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
sig_retcode_t flashcpy_cached( uint8_t *buf, uint32_t offset, size_t len )
{
    sig_retcode_t retVal = SIG_FLASH_READ_ERROR;
    size_t        retlen;

    /* Check if requested element is in the cache in which case we can just */
    /* memcpy it to the destination                                         */
    if ( ( offset >= g_cacheStart ) &&
         ( ( offset + len ) <= g_cacheEnd ) )
    {
        memcpy( buf, g_cache + (offset - g_cacheStart), len );
        retVal = SIG_OK;
    }
    /* If we can fit this item in the cache then replace the cache contents */
    /* with the flash data starting at the given offset                     */
    else if ( len <= C4A_CACHE_SIZE )
    {
        /* Initiate the flash read and check if it was able to read         */
        /* anything back                                                    */
        if ( 0 != nlflash_read( DEFAULT_FLASH,
                                offset,
                                C4A_CACHE_SIZE,
                                &retlen,
                                g_cache,
                                NULL ) )
        {
            g_cacheStart = 0;
            g_cacheEnd   = 0;
        }
        /* We got something so check if it's enough or signal an error      */
        else if ( retlen < len )
        {
            g_cacheStart = offset;
            g_cacheEnd   = offset + retlen;
        }
        /* Item is now in the cache so memcpy it out to the destination     */
        else
        {
            g_cacheStart = offset;
            g_cacheEnd   = offset + retlen;
            memcpy( buf, g_cache + (offset - g_cacheStart), len );
            retVal = SIG_OK;
        }
    }

    return retVal;
}

#else /* C4A_USE_FLASH_CACHE */

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
    if ( ( 0 != nlflash_read( DEFAULT_FLASH, offset, len, &retlen, buf, NULL ) ) ||
         ( retlen != len ) )
    {
        retVal = SIG_FLASH_READ_ERROR;
    }

    return retVal;
}
#endif /* C4A_USE_FLASH_CACHE */


/**
 * Converts the uint32_t ADRS array into a big-endian formatted byte array
 *
 * @param[out  dst     Pointer to destination uint8_t buffer where byte array will be written.
 * @param[in]  ADRS    Pointer to uint32_t-based ADRS data structure that will be converted into a
 *                     byte array.
 *
 * @return SIG_OK iff the ADRS array was converted successfully, relevant error code otherwise
 */
sig_retcode_t convertAdrsToBytes( uint8_t  *dst,
                                  uint32_t *ADRS )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( dst && ADRS )
    {
        for ( int i = 0; i < ADRS_WORD_COUNT; i++ )
        {
            writeBigEndian( dst + 4*i, ADRS[i], 4 );
        }

        retVal = SIG_OK;
    }

    return retVal;
}


/**
 * Extracts the specified base-w digit from the given source array S which is a byte array that
 * we interpret as a little-endian sequence of base-w digits.
 *
 * @param[in] S      Pointer to source byte array that we'll interpret as a base-w digit array.
 * @param[in] i      Position of base-w digit that will be returned.
 * @param[in] log2w  Size of base-w digit in bits (e.g., 1 = base-2, 2 = base-4, 4 = base-16, etc.).
 *
 * @return base-w digit stored at base-w index i of the source byte array.
 */
uint32_t otsCoeff( const uint8_t *S,
                   uint32_t       i,
                   uint32_t       log2w )
{
    uint32_t byteOffset    = (i * log2w) >> 3;
    uint32_t digitsPerByte = (8 / log2w);
    uint32_t shiftOffset   = log2w * (~i & (digitsPerByte - 1) );
    uint32_t digitMask     = (1 << log2w) - 1;

    return( (S[byteOffset] >> shiftOffset) & digitMask );
}


/**
 * Computes a checksum over the given value array.
 *
 * @param[out] dst     Pointer to byte array where the checksum will be written as a p2Bytes element
 *                     byte array.
 * @param[in]  value   Pointer to the byte array that we'll interpret as a base-w digit array and compute
 *                     a checksum over.
 * @param[in]  params  Pointer to a data structure containing the pertinent XMSS/XMSS-MT parameters.
 *
 * @return SIG_OK iff checksum was computed successfully, relevant error code othewise
 */
sig_retcode_t otsComputeChecksum( uint8_t               *dst,
                                  const uint8_t         *value,
                                  const xmssmt_params_t *params )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( dst && value && params )
    {
        uint32_t sum = 0;
        uint32_t max = 0;

        /* Compute checksum by scanning it one log2w-bit digit at a time */
        for ( uint32_t i = 0; i < params->p1; i++ )
        {
            sum += params->w - 1 - otsCoeff( value, i, params->log2w );
            max += params->w - 1;
        }

        /* Align checksum result */
        sum <<= params->ls;

        /* Write checksum result (big-endian) */
        writeBigEndian( dst, sum, params->p2Bytes );

        retVal = SIG_OK;
    }

    return retVal;
}


/**
 * Reads an OID byte array which for some reason is stored as a little-endian value (unlike
 * all other values that are stored big-endian...)
 *
 * @param[in] oid     Pointer to the byte array where the little-endian formatted OID value is stored.
 * @param[in] oidLen  Length of the OID vector in bytes that will be converted to a value.
 *
 * @return Value of the OID stored in the oid byte array of the specified length.
 */
uint32_t readOidBytes( const uint8_t *oid,
                       uint32_t       oidLen )
{
    uint32_t retVal = 0;

    /* Validate parameters */
    if ( oid )
    {
        /* For some reason they chose to store OIDs as little endian */
        /* values so we need to create a new function to deal with   */
        /* this fact!                                                */
        for ( uint32_t i = 0; i < oidLen; i++ )
        {
            retVal |= (oid[i] << 8*i);
        }
    }

    return retVal;
}


/**
 * Converts a string representing an OID (as defined in the IETF proposal) to an OID value
 * that can be used to configure a given XMSS/XMSS-MT parameter set.
 *
 * @param[in]  oid  Pointer to a null-terminated string that specifies the desired OID.
 * @param[out] val  Pointer to where the corresponding OID value will be written.
 *
 * @return SIG_OK iff OID was determined to be supported, relevant error code othewise
 */
sig_retcode_t readOid( const char *oid,
                       uint32_t   *val )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( oid && val )
    {
        retVal = SIG_OK;

        /* Map the OID string to the appropriate value */
        if ( !strcmp( oid, XMSSMT_SHA2_20_2_256_STR ) )
            *val = XMSSMT_SHA2_20_2_256;
        else if ( !strcmp( oid, XMSSMT_SHA2_20_4_256_STR ) )
            *val = XMSSMT_SHA2_20_4_256;
        else if ( !strcmp( oid, XMSSMT_SHA2_40_2_256_STR ) )
            *val = XMSSMT_SHA2_40_2_256;
        else if ( !strcmp( oid, XMSSMT_SHA2_40_4_256_STR ) )
            *val = XMSSMT_SHA2_40_4_256;
        else if ( !strcmp( oid, XMSSMT_SHA2_40_8_256_STR ) )
            *val = XMSSMT_SHA2_40_8_256;
        else if ( !strcmp( oid, XMSSMT_SHA2_60_3_256_STR ) )
            *val = XMSSMT_SHA2_60_3_256;
        else if ( !strcmp( oid, XMSSMT_SHA2_60_6_256_STR ) )
            *val = XMSSMT_SHA2_60_6_256;
        else if ( !strcmp( oid, XMSSMT_SHA2_60_12_256_STR ) )
            *val = XMSSMT_SHA2_60_12_256;
        else if ( !strcmp( oid, XMSS_SHA2_10_256_STR ) )
            *val = XMSS_SHA2_10_256;
        else if ( !strcmp( oid, XMSS_SHA2_16_256_STR ) )
            *val = XMSS_SHA2_16_256;
        else if ( !strcmp( oid, XMSS_SHA2_20_256_STR ) )
            *val = XMSS_SHA2_20_256;
        else
            /* Invalid oid */
            retVal = SIG_UNSUPPORTED_OID;
    }

    /* If you get here then at least one parameter is invalid */
    return retVal;
}


/**
 * Parses a given OID value to generate a XMSS-MT parameter set as per the technique used in
 * the reference implementation.
 *
 * @param[out] params  Pointer to XMSS/XMSS-MT data structure where the required configuration will
 *                     be written.
 * @param[in]  oidVal  OID value (as defined in the current IETF draft) describing the desired XMSS-MT
 *                     configuration.
 *
 * @return SIG_OK iff OID was supported and parameter set updated, relevant error code othewise
 */
sig_retcode_t parseXmssMtOid( xmssmt_params_t *params,
                              uint32_t         oidVal )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( params )
    {
        retVal = SIG_OK;

        /* Parse OID string, converting it into a value */
        params->n         = 32;
        params->w         = 16;
        params->log2w     = 4;
        params->p1        = (8 * params->n) / params->log2w;
        /* floor(log2(p1 * (w-1)) / log2w) + 1 = 3 for all possible n = {32, 64} */
        params->p2        = 3;
        params->p2Bytes   = (3 * params->log2w + 7 ) / 8;
        params->ls        = 8 - ( (params->p2 * params->log2w) & 0x7 );
        params->p         = params->p1 + params->p2;
        params->otsSigLen = params->p * params->n;
        params->d         = 1;
        params->pubKeyLen = XMSS_OID_LEN + 2*params->n;

        switch ( oidVal )
        {
        case XMSSMT_SHA2_20_2_256:
            params->h      = 10;
            params->d      = 2;
            params->hTotal = 20;
            params->idxLen = IDX_LEN(params->hTotal);
            break;
        case XMSSMT_SHA2_20_4_256:
            params->h      = 5;
            params->d      = 4;
            params->hTotal = 20;
            params->idxLen = IDX_LEN(params->hTotal);
            break;
        case XMSSMT_SHA2_40_2_256:
            params->h      = 20;
            params->d      = 2;
            params->hTotal = 40;
            params->idxLen = IDX_LEN(params->hTotal);
            break;
        case XMSSMT_SHA2_40_4_256:
            params->h      = 10;
            params->d      = 4;
            params->hTotal = 40;
            params->idxLen = IDX_LEN(params->hTotal);
            break;
        case XMSSMT_SHA2_40_8_256:
            params->h      = 5;
            params->d      = 8;
            params->hTotal = 40;
            params->idxLen = IDX_LEN(params->hTotal);
            break;
        case XMSSMT_SHA2_60_3_256:
            params->h      = 20;
            params->d      = 3;
            params->hTotal = 60;
            params->idxLen = IDX_LEN(params->hTotal);
            break;
        case XMSSMT_SHA2_60_6_256:
            params->h      = 10;
            params->d      = 6;
            params->hTotal = 60;
            params->idxLen = IDX_LEN(params->hTotal);
            break;
        case XMSSMT_SHA2_60_12_256:
            params->h      = 5;
            params->d      = 12;
            params->hTotal = 60;
            params->idxLen = IDX_LEN(params->hTotal);
            break;
        default:
            /* Unknown OID */
            retVal = SIG_UNSUPPORTED_OID;
        }
        params->xmssSigLen = ( params->idxLen +
                               params->n +
                               params->d * params->otsSigLen +
                               params->hTotal * params->n );
    }

    return retVal;
}


/**
 * Parses a given OID value to generate a XMSS parameter set as per the technique used in
 * the reference implementation.
 *
 * @param[out] params  Pointer to XMSS/XMSS-MT data structure where the required configuration will
 *                     be written.
 * @param[in]  oidVal  OID value (as defined in the current IETF draft) describing the desired XMSS
 *                     configuration.
 *
 * @return SIG_OK iff OID was supported and parameter set updated, relevant error code othewise
 */
sig_retcode_t parseXmssOid( xmssmt_params_t *params,
                            uint32_t         oidVal )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( params )
    {
        retVal = SIG_OK;

        /* Parse OID string, converting it into a value */
        params->n         = 32;
        params->w         = 16;
        params->log2w     = 4;
        params->p1        = (8 * params->n) / params->log2w;
        /* floor(log2(p1 * (w-1)) / log2w) + 1 = 3 for all possible n = {32, 64} */
        params->p2        = 3;
        params->p2Bytes   = (3 * params->log2w + 7 ) / 8;
        params->ls        = 8 - ( (params->p2 * params->log2w) & 0x7 );
        params->p         = params->p1 + params->p2;
        params->otsSigLen = params->p * params->n;
        params->idxLen    = 4;
        params->pubKeyLen = XMSS_OID_LEN + 2*params->n;

        /* Baseline XMSS is XMSS-MT with d = 1 */
        params->d         = 1;

        switch ( oidVal )
        {
        case XMSS_SHA2_10_256:
            params->h      = 10;
            params->hTotal = params->h;
            break;
        case XMSS_SHA2_16_256:
            params->h      = 16;
            params->hTotal = params->h;
            break;
        case XMSS_SHA2_20_256:
            params->h      = 20;
            params->hTotal = params->h;
            break;
        default:
            /* Unknown OID */
            retVal = SIG_UNSUPPORTED_OID;
        }
        params->xmssSigLen = ( params->idxLen +
                               params->n +
                               params->d * params->otsSigLen +
                               params->hTotal * params->n );
    }

    return retVal;
}


/**
 * Computes H(key, m) = SHA256( 1[n-1:0] || key[n-1:0] || m[2*n-1:0] ) as defined in the current IETF draft,
 * where "1[n-1:0]" is the value 0x1 represented as a n-byte big-endian value
 *
 * @param[out] out     Pointer to XMSS/XMSS-MT data structure where the required configuration will
 *                     be written.
 * @param[in]  key     Pointer to n-byte value required for the computation
 * @param[in]  m       Pointer to the 2n-byte value required for the computation
 * @param[in]  params  Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t computeH( uint8_t               *out,
                        const uint8_t         *key,
                        const uint8_t         *m,
                        const xmssmt_params_t *params )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( out && key && m && params )
    {
        C4A_SHA256_CTX ctx;

        /* Initialixe context as per H( ) definition */
        c4a_sha256_init( &ctx );
        ctx.Nl = 256;
        ctx.num = params->n;
        memset( ctx.data, 0, params->n );
        ctx.data[params->n - 1] = 0x01;

        /* Complete the computation */
        c4a_sha256_update( &ctx, key, params->n );
        c4a_sha256_update( &ctx, m, 2*params->n );
        c4a_sha256_final( &ctx, out );

        retVal = SIG_OK;
    }

    return retVal;
}


/**
 * Computes Hmsg(key, m) = SHA256( 2[n-1:0] || key[3*n-1:0] || m[m-1:0] )
 *                       = SHA256( 2[n-1:0] || r[n-1:0] || root[n-1:0] || idx[n-1:0] || m[mLen-1:0] )
 * where "2[n-1:0]" is the value 0x2 represented as a n-byte big-endian value, and "idx[n-1:0]"
 * is the idx value represented as a n-byte big-endian value.  This implementation emulates scratch
 * memory pool and flash-based signature storage.
 *
 * @param[out] out          Pointer to where Hmsg result will be written.
 * @param[in]  r            Pointer to n-byte random value for the given signature.
 * @param[in]  root         Pointer to n-byte root value for the given signature.
 * @param[in]  idx          Signature index number.
 * @param[in]  m            Pointer to the mLen byte array containing the message that is to be hashed.
 * @param[in]  mLen         Length in bytes of the byte array pointed to by m.
 * @param[in]  scratchBuff  Pointer to scratch memory that is used to allocate temporary data structures.
 * @param[in]  scratchLen   Length in bytes of the scratch memory pool.
 * @param[in]  params       Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t computeHmsgFlash( uint8_t               *out,
                                const uint8_t         *r,
                                const uint8_t         *root,
                                const uint64_t         idx,
                                const uint8_t         *m,
                                const uint32_t         mLen,
                                uint8_t               *scratchBuff,
                                size_t                 scratchLen,
                                const xmssmt_params_t *params )
{
    /* Scratch Buffer allocation:                                                         */
    /*    uint8_t idxBuff[MAX_HASH_LEN]                                                   */
    /*    ... rest is unallocated at this level ...                                       */

    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( out && r && root && m && params )
    {
        C4A_SHA256_CTX ctx;
        uint8_t    *idxBuff;

        /* Allocate memory */
        if ( ( sizeof(C4A_SHA256_CTX) + MAX_HASH_LEN ) > scratchLen )
        {
            retVal = SIG_INSUFFICIENT_MEMORY;
        }
        else
        {
            /* Allocate the memory, don't bother updating scratchBuff or */
            /* scratchLen though as we don't call any other functions    */
            /* that might need to allocate from the scratch buffer       */
            idxBuff = scratchBuff;

            /* Initialixe context as per H( ) definition */
            c4a_sha256_init( &ctx );
            ctx.Nl = 256;
            ctx.num = params->n;
            memset( ctx.data, 0, params->n);
            ctx.data[params->n -1] = 0x02;

            /* Complete the computation */
            c4a_sha256_update( &ctx, r, params->n );
            c4a_sha256_update( &ctx, root, params->n );
            writeBigEndian( idxBuff, idx, params->n );
            c4a_sha256_update( &ctx, idxBuff, params->n );
            c4a_sha256_update( &ctx, m, mLen );
            c4a_sha256_final( &ctx, out );

            retVal = SIG_OK;
        }
    }

    return retVal;
}


/**
 * Computes Hmsg(key, m) = SHA256( 2[n-1:0] || key[3*n-1:0] || m[m-1:0] )
 *                       = SHA256( 2[n-1:0] || r[n-1:0] || root[n-1:0] || idx[n-1:0] || m[mLen-1:0] )
 * where "2[n-1:0]" is the value 0x2 represented as a n-byte big-endian value, and "idx[n-1:0]"
 * is the idx value represented as a n-byte big-endian value.
 *
 * @param[out] out     Pointer to where Hmsg result will be written.
 * @param[in]  r       Pointer to n-byte random value for the given signature.
 * @param[in]  root    Pointer to n-byte root value for the given signature.
 * @param[in]  idx     Signature index number.
 * @param[in]  m       Pointer to the mLen byte array containing the message that is to be hashed.
 * @param[in]  mLen    Length in bytes of the byte array pointed to by m.
 * @param[in]  params  Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t computeHmsg( uint8_t               *out,
                           const uint8_t         *r,
                           const uint8_t         *root,
                           const uint64_t         idx,
                           const uint8_t         *m,
                           const uint32_t         mLen,
                           const xmssmt_params_t *params )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( out && r && root && m && params )
    {
        C4A_SHA256_CTX ctx;
        uint8_t idxBuff[MAX_HASH_LEN];

        /* Initialixe context as per H( ) definition */
        c4a_sha256_init( &ctx );
        ctx.Nl = 256;
        ctx.num = params->n;
        memset( ctx.data, 0, params->n );
        ctx.data[params->n - 1] = 0x02;

        /* Complete the computation */
        c4a_sha256_update( &ctx, r, params->n );
        c4a_sha256_update( &ctx, root, params->n );
        writeBigEndian( idxBuff, idx, params->n );
        c4a_sha256_update( &ctx, idxBuff, params->n );
        c4a_sha256_update( &ctx, m, mLen );
        c4a_sha256_final( &ctx, out );

        retVal = SIG_OK;
    }

    return retVal;
}


/**
 * Computes Prf(key, m) = SHA256( 3[n-1:0] || key[n-1:0] || m[31:0] ) as defined in the current IETF draft,
 * where "3[n-1:0]" is the value 0x3 represented as a n-byte big-endian value.
 *
 * @param[out] out     Pointer to where the PRF result will be written.
 * @param[in]  key     Pointer to n-byte value key value.
 * @param[in]  m       Pointer to the 32-byte m value.
 * @param[in]  params  Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t computePrf( uint8_t               *out,
                          const uint8_t         *key,
                          const uint8_t         *m,
                          const xmssmt_params_t *params )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( out && key && m && params )
    {
        C4A_SHA256_CTX ctx;

        /* Initialize context as per PRF( ) definition */
        c4a_sha256_init( &ctx );
        ctx.Nl = 256;
        ctx.num = params->n;
        memset( ctx.data, 0, params->n );
        ctx.data[params->n - 1] = 0x3;

        /* Complete the computation */
        c4a_sha256_update( &ctx, key, params->n );
        c4a_sha256_update( &ctx, m, 32 );
        c4a_sha256_final( &ctx, out );

        retVal = SIG_OK;
    }

    return retVal;
}


/**
 * Computes randHash(out, left, right, SEED, ADRS) as defined in the current IETF draft,
 * where "3[n-1:0]" is the value 0x3 represented as a n-byte big-endian value.  This implementation
 * emulates scratch memory pool and flash-based signature storage.
 *
 * @param[out] out          Pointer to where randHash result will be written.
 * @param[in]  left         Pointer to byte array storing left branch value.
 * @param[in]  right        Pointer to byte array storing right branch value.
 * @param[in]  SEED         Pointer to byte array storing the SEED value for this signature.
 * @param[in]  ADRS         Pointer to uint32_t array storing the ADRS data structure for this signature.
 * @param[in]  scratchBuff  Pointer to scratch memory that is used to allocate temporary data structures.
 * @param[in]  scratchLen   Length in bytes of the scratch memory pool.
 * @param[in]  params       Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t randHashFlash( uint8_t               *out,
                             const uint8_t         *left,
                             const uint8_t         *right,
                             const uint8_t         *SEED,
                             uint32_t              *ADRS,
                             uint8_t               *scratchBuff,
                             size_t                 scratchLen,
                             const xmssmt_params_t *params )
{
    /* Scratch Buffer allocation:                                                         */
    /*    uint8_t key[MAX_HASH_LEN]                                                       */
    /*    uint8_t mask[2*MAX_HASH_LEN]                                                    */
    /*    uint8_t adrsBytes[sizeof(uint32_t)*ADRS_WORD_COUNT]                             */
    /*    ... rest is unallocated at this level ...                                       */

    sig_retcode_t retVal = SIG_INVALID_PARAM;
    uint8_t *key;
    uint8_t *mask;
    uint8_t *adrsBytes;

    /* Validate parameters */
    if ( out && left && right && SEED && ADRS && params )
    {
        if ( (3*MAX_HASH_LEN + sizeof(uint32_t)*ADRS_WORD_COUNT) > scratchLen )
        {
            retVal = SIG_INSUFFICIENT_MEMORY;
        }
        else
        {
            key       = scratchBuff;
            mask      = scratchBuff + MAX_HASH_LEN;
            adrsBytes = scratchBuff + 3*MAX_HASH_LEN;
            scratchBuff += 3*MAX_HASH_LEN + sizeof(uint32_t)*ADRS_WORD_COUNT;
            scratchLen  -= 3*MAX_HASH_LEN + sizeof(uint32_t)*ADRS_WORD_COUNT;

            /* Setup ADRS, convert it to bytes and perform PRF on the result to get key value */
            /* (no need to check return values of convertAdrsToBytes and computePrf as all    */
            /* of their inputs have been validated so its guaranteed to return SIG_OK)        */
            ADRS[ADRS_KEY_MASK] = 0;
            convertAdrsToBytes( adrsBytes, ADRS );
            computePrf( key, SEED, adrsBytes, params );

            /* Update ADRS' keyAndMask field, update that portion of the byte vector and */
            /* perform PRF on the result to get first half of the mask (no need to check */
            /* return value for computePrf as its guaranteed to be SIG_OK)               */
            ADRS[ADRS_KEY_MASK] = 1;
            writeBigEndian( adrsBytes + sizeof(uint32_t)*ADRS_KEY_MASK, ADRS[ADRS_KEY_MASK], 4 );
            computePrf( mask, SEED, adrsBytes, params );

            /* Repeat the above using another updated ADRS value (no need to check return */
            /* value for computePrf as its guaranteed to be SIG_OK)                       */
            ADRS[ADRS_KEY_MASK] = 2;
            writeBigEndian( adrsBytes + sizeof(uint32_t)*ADRS_KEY_MASK, ADRS[ADRS_KEY_MASK], 4 );
            computePrf( mask + params->n, SEED, adrsBytes, params );

            /* Mix in the left and right values to the mask and hash everything to get */
            /* the final result (no need to check return value for computeH as its     */
            /* guaranteed to be SIG_OK)                                                */
            for ( int i = 0; i < params->n; i++ )
            {
                mask[i            ] ^= left[i];
                mask[i + params->n] ^= right[i];
            }
            computeH( out, key, mask, params );

            retVal = SIG_OK;
        }
    }

    return retVal;
}


/**
 * Computes randHash(out, left, right, SEED, ADRS) as defined in the current IETF draft,
 * where "3[n-1:0]" is the value 0x3 represented as a n-byte big-endian value.
 *
 * @param[out] out          Pointer to where randHash result will be written.
 * @param[in]  left         Pointer to byte array storing left branch value.
 * @param[in]  right        Pointer to byte array storing right branch value.
 * @param[in]  SEED         Pointer to byte array storing the SEED value for this signature.
 * @param[in]  ADRS         Pointer to uint32_t array storing the ADRS data structure for this signature.
 * @param[in]  params  Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t randHash( uint8_t               *out,
                        const uint8_t         *left,
                        const uint8_t         *right,
                        const uint8_t         *SEED,
                        uint32_t              *ADRS,
                        const xmssmt_params_t *params )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( out && left && right && SEED && ADRS && params )
    {
        uint8_t key[MAX_HASH_LEN];
        uint8_t mask[2*MAX_HASH_LEN];
        uint8_t adrsBytes[sizeof(uint32_t)*ADRS_WORD_COUNT];

        /* Setup ADRS, convert it to bytes and perform PRF on the result to get key value */
        /* (no need to check return values of convertAdrsToBytes and computePrf as all    */
        /* of their inputs have been validated so its guaranteed to return SIG_OK)        */
        ADRS[ADRS_KEY_MASK] = 0;
        convertAdrsToBytes( adrsBytes, ADRS );
        computePrf( key, SEED, adrsBytes, params );

        /* Update ADRS' keyAndMask field, update that portion of the byte vector and */
        /* perform PRF on the result to get first half of the mask (no need to check */
        /* return value for computePrf as its guaranteed to be SIG_OK)               */
        ADRS[ADRS_KEY_MASK] = 1;
        writeBigEndian( adrsBytes + sizeof(uint32_t)*ADRS_KEY_MASK, ADRS[ADRS_KEY_MASK], 4 );
        computePrf( mask, SEED, adrsBytes, params );

        /* Repeat the above using another updated ADRS value (no need to check return */
        /* value for computePrf as its guaranteed to be SIG_OK)                       */
        ADRS[ADRS_KEY_MASK] = 2;
        writeBigEndian( adrsBytes + sizeof(uint32_t)*ADRS_KEY_MASK, ADRS[ADRS_KEY_MASK], 4 );
        computePrf( mask + params->n, SEED, adrsBytes, params );

        /* Mix in the left and right values to the mask and hash everything to get */
        /* the final result (no need to check return value for computeH as its     */
        /* guaranteed to be SIG_OK)                                                */
        for ( int i = 0; i < params->n; i++ )
        {
            mask[i            ] ^= left[i];
            mask[i + params->n] ^= right[i];
        }
        computeH( out, key, mask, params );

        retVal = SIG_OK;
    }

    return retVal;
}


/**
 * Computes F(key, m0, m1) = SHA256( 0[n-1:0] || key[n-1:0] || (m0[n-1:0] ^ m1[n-1:0]) )
 * where "0[n-1:0]" is the value 0x0 represented as a n-byte big-endian value.
 *
 * @param[out] out     Pointer to where F result will be written.
 * @param[in]  key     Pointer to n-byte key.
 * @param[in]  m0      Pointer to n-byte m0 value.
 * @param[in]  m1      Pointer to n-byte m1 value.
 * @param[in]  params  Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t computeF( uint8_t               *out,
                        const uint8_t         *key,
                        uint8_t               *m0,
                        const uint8_t         *m1,
                        const xmssmt_params_t *params )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( out && key && params && m0 && m1 )
    {
        C4A_SHA256_CTX ctx;

        /* Initialize context as per F( ) definition */
        c4a_sha256_init( &ctx );
        ctx.Nl = 256;
        ctx.num = params->n;
        memset( ctx.data, 0, params->n );

        /* Start performing the SHA256 computation */
        c4a_sha256_update( &ctx, key, params->n );

        /* Do XOR mixing in-place using m0 as the destination */
        for ( uint32_t i = 0; i < params->n; i++ )
        {
            m0[i] = m0[i] ^ m1[i];
        }

        c4a_sha256_update( &ctx, m0, params->n);

        /* Undo XOR mixing to revert m0 back to its original value */
        for ( uint32_t i = 0; i < params->n; i++ )
        {
            m0[i] = m0[i] ^ m1[i];
        }

        /* Complete SHA256 */
        c4a_sha256_final( &ctx, out );

        retVal = SIG_OK;
    }

    return retVal;
}


/**
 * Computes chaining function Y = chain(X, i, s, SEED, ADRS) as defined in the
 * current IETF draft.  Note that it foregoes recursion in favour of a loop-based
 * approach.  This implementation emulates scratch memory pool and flash-based
 * signature storage.
 *
 * @param[out] Y            Pointer to where result will be written.
 * @param[in]  Xoffset      Offset in bytes from the start of flash where X value resides.
 * @param[in]  i            Iteration start value.
 * @param[in]  s            Number of iterations that are to be performed.
 * @param[in]  SEED         Pointer to byte array storing the SEED value for this signature.
 * @param[in]  ADRS         Pointer to uint32_t array storing the ADRS data structure for
 *                          this signature.
 * @param[in]  scratchBuff  Pointer to scratch memory that is used to allocate temporary
 *                          data structures.
 * @param[in]  scratchLen   Length in bytes of the scratch memory pool.
 * @param[in]  params       Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t computeChainFlash( uint8_t               *Y,
                                 uint32_t               Xoffset,
                                 const uint32_t         i,
                                 const uint32_t         s,
                                 const uint8_t         *SEED,
                                 uint32_t              *ADRS,
                                 uint8_t               *scratchBuff,
                                 size_t                 scratchLen,
                                 const xmssmt_params_t *params )
{
    /* Scratch Buffer allocation:                                                         */
    /*    uint8_t key[MAX_HASH_LEN]                                                       */
    /*    uint8_t mask[MAX_HASH_LEN]                                                      */
    /*    uint8_t adrsBytes[sizeof(uint32_t)*ADRS_WORD_COUNT]                             */
    /*    ... rest is unallocated at this level ...                                       */

    sig_retcode_t retVal = SIG_INVALID_PARAM;
    uint8_t *key;
    uint8_t *mask;
    uint8_t *adrsBytes;

    /* Validate parameters */
    if ( Y && SEED && ADRS && params )
    {
        if ( (MAX_HASH_LEN + MAX_HASH_LEN + sizeof(uint32_t)*ADRS_WORD_COUNT) > scratchLen )
        {
            retVal = SIG_INSUFFICIENT_MEMORY;
        }
        else
        {
            key       = scratchBuff;
            mask      = scratchBuff + MAX_HASH_LEN;
            adrsBytes = scratchBuff + MAX_HASH_LEN + MAX_HASH_LEN;
            scratchBuff += MAX_HASH_LEN + MAX_HASH_LEN + (sizeof(uint32_t) * ADRS_WORD_COUNT);
            scratchLen  -= MAX_HASH_LEN + MAX_HASH_LEN + (sizeof(uint32_t) * ADRS_WORD_COUNT);

            /* Baseline operation is to set Y = X */
#ifdef C4A_USE_FLASH_CACHE
            retVal = flashcpy_cached( Y, Xoffset, params->n );
#else
            retVal = flashcpy( Y, Xoffset, params->n );
#endif
        }

        if ( SIG_OK == retVal )
        {
            /* Chaining requires us to iterate from i to (i + s), and  */
            /* stopping if (i + s) > (w - 1) as per Algorithm 2 in the */
            /* XMSS specification (no need to check return values for  */
            /* convertAdrsToBytes, computePrf, and computeF as they're */
            /* guaranteed to be SIG_OK)                                */
            for ( uint32_t j = i; j < (i + s) && j < params->w; j++ )
            {
                /* key  = PRF( SEED, ADRS ) */
                ADRS[ADRS_HASH_ADDR] = j;
                ADRS[ADRS_KEY_MASK]  = 0;
                convertAdrsToBytes( adrsBytes, ADRS );
                computePrf( key, SEED, adrsBytes, params );

                /* mask = PRF( SEED, ADRS ) */
                ADRS[ADRS_KEY_MASK]  = 1;
                convertAdrsToBytes( adrsBytes, ADRS );
                computePrf( mask, SEED, adrsBytes, params );

                /* Y = F( key, Y ^ mask ) */
                computeF( Y, key, Y, mask, params );
            }
        }
    }

    return retVal;
}


/**
 * Computes chaining function Y = chain(X, i, s, SEED, ADRS) as defined in the
 * current IETF draft.  Note that it foregoes recursion in favour of a loop-based
 * approach.
 *
 * @param[out] Y            Pointer to where result will be written.
 * @param[in]  X            Pointer to where X value resides.
 * @param[in]  i            Iteration start value.
 * @param[in]  s            Number of iterations that are to be performed.
 * @param[in]  SEED         Pointer to byte array storing the SEED value for this signature.
 * @param[in]  ADRS         Pointer to uint32_t array storing the ADRS data structure for
 *                          this signature.
 * @param[in]  params       Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t computeChain( uint8_t               *Y,
                            const uint8_t         *X,
                            const uint32_t         i,
                            const uint32_t         s,
                            const uint8_t         *SEED,
                            uint32_t              *ADRS,
                            const xmssmt_params_t *params )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( Y && X && SEED && ADRS && params )
    {
        uint8_t key[MAX_HASH_LEN];
        uint8_t mask[MAX_HASH_LEN];
        uint8_t adrsBytes[sizeof(uint32_t)*ADRS_WORD_COUNT];

        /* Baseline operation is to set Y = X */
        memcpy( Y, X, params->n );

        /* Chaining requires us to iterate from i to (i + s), and  */
        /* stopping if (i + s) > (w - 1) as per Algorithm 2 in the */
        /* XMSS specification (no need to check return values for  */
        /* convertAdrsToBytes, computePrf, and computeF as they're */
        /* guaranteed to be SIG_OK)                                */
        for ( uint32_t j = i; j < (i + s) && j < params->w; j++ )
        {
            /* key  = PRF( SEED, ADRS ) */
            ADRS[ADRS_HASH_ADDR] = j;
            ADRS[ADRS_KEY_MASK]  = 0;
            convertAdrsToBytes( adrsBytes, ADRS );
            computePrf( key, SEED, adrsBytes, params );

            /* mask = PRF( SEED, ADRS ) */
            ADRS[ADRS_KEY_MASK]  = 1;
            convertAdrsToBytes( adrsBytes, ADRS );
            computePrf( mask, SEED, adrsBytes, params );

            /* Y = F( key, Y ^ mask ) */
            computeF( Y, key, Y, mask, params );
        }

        retVal = SIG_OK;
    }

    return retVal;
}


/**
 * Computes OTS Pk[idx] value as defined in Algorithm 6 of the current IETF draft.
 * current IETF draft.  This implementation emulates scratch memory pool and
 * flash-based signature storage.
 *
 * @param[out] otsPk        Pointer to where result will be written.
 * @param[in]  otsSigOffset Offset in bytes from the start of flash where the OTS signature
 *                          is stored.
 * @param[in]  mVal         Base-w coefficient from message being signed that we use to 
 *                          determine the number of iterations to perform in the chain.
 * @param[in]  SEED         Pointer to byte array storing the SEED value for this signature.
 * @param[in]  ADRS         Pointer to uint32_t array storing the ADRS data structure for
 *                          this signature.
 * @param[in]  idx          Index of node in tree we're computing Pk for.
 * @param[in]  scratchBuff  Pointer to scratch memory that is used to allocate temporary
 *                          data structures.
 * @param[in]  scratchLen   Length in bytes of the scratch memory pool.
 * @param[in]  params       Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t computeOtsPkIFlash( uint8_t               *otsPk,
                                  uint32_t               otsSigOffset,
                                  const uint32_t         mVal,
                                  const uint8_t         *SEED,
                                  uint32_t              *ADRS,
                                  const uint32_t         idx,
                                  uint8_t               *scratchBuff,
                                  size_t                 scratchLen,
                                  const xmssmt_params_t *params )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( otsPk && SEED && ADRS && params )
    {
        ADRS[ADRS_CHAIN_ADDR] = idx;
        retVal = computeChainFlash( otsPk,
                                    otsSigOffset + idx*params->n,
                                    mVal,
                                    params->w - 1 - mVal,
                                    SEED,
                                    ADRS,
                                    scratchBuff,
                                    scratchLen,
                                    params );
    }

    return retVal;
}


/**
 * Computes OTS Pk[idx] value as defined in Algorithm 6 of the current IETF draft.
 * current IETF draft.
 *
 * @param[out] otsPk   Pointer to where result will be written.
 * @param[in]  otsSig  Pointer to where the OTS signature is stored.
 * @param[in]  mVal    Base-w coefficient from message being signed that we use to 
 *                     determine the number of iterations to perform in the chain.
 * @param[in]  SEED    Pointer to byte array storing the SEED value for this signature.
 * @param[in]  ADRS    Pointer to uint32_t array storing the ADRS data structure for
 *                     this signature.
 * @param[in]  idx     Index of node in tree we're computing Pk for.
 * @param[in]  params  Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t computeOtsPkI( uint8_t               *otsPk,
                             const uint8_t         *otsSig,
                             const uint32_t         mVal,
                             const uint8_t         *SEED,
                             uint32_t              *ADRS,
                             const uint32_t         idx,
                             const xmssmt_params_t *params )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( otsPk && otsSig && SEED && ADRS && params )
    {
        ADRS[ADRS_CHAIN_ADDR] = idx;
        retVal = computeChain( otsPk,
                               otsSig + idx*params->n,
                               mVal,
                               params->w - 1 - mVal,
                               SEED,
                               ADRS,
                               params );
    }

    return retVal;
}


/**
 * Generates a signing tree leaf node in a relatively small amount of storage via
 * on-demand generation of otsPk[i] values and a space-efficient tree compression
 * algorithm that utilizes a small stack.  This implementation emulates scratch
 * memory pool and flash-based signature storage.
 *
 * @param[out] computedLeaf Pointer to where result will be written.
 * @param[in]  message      Pointer to where the message we're computing the signature
 *                          verification on is stored.
 * @param[in]  sigOtsOffset Offset in bytes from the start of flash where the OTS signature 
 *                          is stored.
 * @param[in]  SEED         Pointer to byte array storing the SEED value for this signature.
 * @param[in]  adrsOts      Pointer to uint32_t array storing the ADRS data structure for
 *                          the OTS component of this signature verification.
 * @param[in]  adrsLtree    Pointer to uint32_t array storing the ADRS data structure for
 *                          the Ltree component of this signature verification.
 * @param[in]  scratchBuff  Pointer to scratch memory that is used to allocate temporary
 *                          data structures.
 * @param[in]  scratchLen   Length in bytes of the scratch memory pool.
 * @param[in]  params       Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t computeLeafFlash( uint8_t               *computedLeaf,
                                const uint8_t         *message,
                                uint32_t               sigOtsOffset,
                                const uint8_t         *SEED,
                                uint32_t              *adrsOts,
                                uint32_t              *adrsLtree,
                                uint8_t               *scratchBuff,
                                size_t                 scratchLen,
                                const xmssmt_params_t *params )
{
    /* Scratch Buffer allocation:                                                         */
    /*    uint8_t stack[STACK_DEPTH*MAX_HASH_LEN]                                         */
    /*    uint8_t treeIndex[STACK_DEPTH + 1]                                              */
    /*    uint8_t treeHeight[STACK_DEPTH]                                                 */
    /*    ... rest is unallocated at this level ...                                       */

    sig_retcode_t retVal = SIG_INVALID_PARAM;
    uint8_t chksumBytes[params->p2Bytes];

    /* Stack storage which we have to handle as a 1-D array since we're trying to allocate */
    /* it without using malloc( ) which causes us no end of grief casting.  The simplest   */
    /* way I've found to do this is to treat it as a 1-D array and convert references to   */
    /* stack[x][y] into stack[x*MAX_Y_DIM + y]... it's ugly but it works!                  */
    uint8_t *stack;

    /* Tracks where top of stack is, points to first available */
    /* location, and indicates current stack depth             */
    uint8_t stackIdx = 0;

    /* treeIndex[0] = index for pk[i]            */
    /* treeIndex[1] = index for treeHeight = 0   */
    /* ...                                       */
    /* treeIndex[i] = index for treeHeight = i-1 */
    uint8_t *treeIndex;

    /* treeHeight[i] = treeHeight of element stored at stack location i */
    uint8_t *treeHeight;

    /* Validate parameters */
    if ( computedLeaf && message && SEED && adrsOts && adrsLtree && params )
    {
        if ( ( (STACK_DEPTH * MAX_HASH_LEN) + (STACK_DEPTH + 1) + STACK_DEPTH ) > scratchLen )
        {
            retVal = SIG_INSUFFICIENT_MEMORY;
        }
        else
        {
            /* Allocate storage in scratchBuff[] */
            stack      = (uint8_t *)scratchBuff;
            treeIndex  = (uint8_t *)(scratchBuff + (STACK_DEPTH * MAX_HASH_LEN));
            treeHeight = (uint8_t *)(scratchBuff + (STACK_DEPTH * MAX_HASH_LEN) + (STACK_DEPTH + 1));
            scratchBuff += (STACK_DEPTH * MAX_HASH_LEN) + (STACK_DEPTH + 1) + STACK_DEPTH;
            scratchLen  -= (STACK_DEPTH * MAX_HASH_LEN) + (STACK_DEPTH + 1) + STACK_DEPTH;

            /* Need to initialize treeIndex[] to zero to begin */
            memset( treeIndex, 0, STACK_DEPTH + 1 );

            /* Compute the checksum and store it for future use (no need to check  */
            /* the return value from otsComputeChecksum as all inputs have already */
            /* been validated at this point so it's guaranteed to return SIG_OK)   */
            otsComputeChecksum( chksumBytes, message, params );

            /* Normally we'd push the first two otsPk[i] terms (otsPk[0] and    */
            /* otsPk[1]) onto the stack to initialize things but in this hybrid */
            /* approach we actually generate them on demand                     */

            /* Generate otsPk[0] and push it onto the stack */
            treeHeight[stackIdx] = 0;
            retVal = computeOtsPkIFlash( &stack[MAX_HASH_LEN * stackIdx++ + 0],
                                         sigOtsOffset,
                                         otsCoeff( message, treeIndex[0], params->log2w ),
                                         SEED,
                                         adrsOts,
                                         treeIndex[0],
                                         scratchBuff,
                                         scratchLen,
                                         params );
            /* Have to do the index increment outside of the parameter list as  */
            /* we found the index was incrementing in unexpected ways which led */
            /* to issues.                                                       */
            treeIndex[0]++;
        }

        if ( SIG_OK == retVal )
        {
            /* Generate otsPk[1] and push it onto the stack */
            treeHeight[stackIdx] = 0;
            computeOtsPkIFlash( &stack[MAX_HASH_LEN*stackIdx++ + 0],
                                sigOtsOffset,
                                otsCoeff( message, treeIndex[0], params->log2w ),
                                SEED,
                                adrsOts,
                                treeIndex[0],
                                scratchBuff,
                                scratchLen,
                                params );
            treeIndex[0]++;
        }

        if ( SIG_OK == retVal )
        {
            /* Perform L-tree compression until we've processed all of the public key elements */
            /* combining two distinct processing phases:                                       */
            /*    1) While all elements of public key haven't yet been processed               */
            /*    2) While combining all intermediate results to reach final value             */
            while ( ( treeIndex[0] < params->p ) ||
                    ( ( treeIndex[0] >= params->p ) && ( stackIdx > 1 ) ) )
            {
                /* Check if the two top-most elements of the stack have the same tree height,  */
                /* OR check if we've processed all of the public key elements and still have   */
                /* intermediate results on the stack to process to get the final result        */
                if ( ( ( treeIndex[0] <  params->p ) && ( stackIdx >= 2 ) && ( treeHeight[stackIdx - 1] == treeHeight[stackIdx - 2] ) ) ||
                     ( ( treeIndex[0] >= params->p ) && ( stackIdx >  1 ) ) )
                {
                    /* Pop off top two elements, perform RAND_HASH and then push result back onto */
                    /* the stack with updated treeHeight[] and treeIndex[] information            */

                    /* Setup ADRS.treeIndex using treeIndex[i+1], where i is the value stored */
                    /* in the treeHeight[] array for the elements (which should be the same)  */
                    adrsLtree[ADRS_TREE_INDEX]  = (uint32_t) treeIndex[treeHeight[stackIdx - 2] + 1]++;

                    /* Result written to [stackIdx - 2] so its height gets incremented */
                    adrsLtree[ADRS_TREE_HEIGHT] = (uint32_t) treeHeight[stackIdx - 2]++;

                    /* Perform RAND_HASH operation using top elements of the stack */
                    retVal = randHashFlash( &stack[MAX_HASH_LEN*(stackIdx - 2) + 0],
                                            &stack[MAX_HASH_LEN*(stackIdx - 2) + 0],
                                            &stack[MAX_HASH_LEN*(stackIdx - 1) + 0],
                                            SEED,
                                            adrsLtree,
                                            scratchBuff,
                                            scratchLen,
                                            params );

                    /* Update stack index to reflect that we consumed top two elements   */
                    /* and then wrote back result (i.e., net change is one less element) */
                    stackIdx = stackIdx - 1;
                }
                /* Need to generate next element onto the stack (if any still unprocessed) */
                /* where we're still processing elements of the message hash               */
                else if ( treeIndex[0] < params->p1 )
                {
                    treeHeight[stackIdx] = 0;
                    retVal = computeOtsPkIFlash( &stack[MAX_HASH_LEN*stackIdx++ + 0],
                                                 sigOtsOffset,
                                                 otsCoeff( message, treeIndex[0], params->log2w ),
                                                 SEED,
                                                 adrsOts,
                                                 treeIndex[0],
                                                 scratchBuff,
                                                 scratchLen,
                                                 params );
                    treeIndex[0]++;
                }
                /* Generating next element onto the stack where we're now processing */
                /* elements of the checksum                                          */
                else if ( treeIndex[0] < params->p )
                {
                    treeHeight[stackIdx] = 0;
                    retVal = computeOtsPkIFlash( &stack[MAX_HASH_LEN*stackIdx++ + 0],
                                                 sigOtsOffset,
                                                 otsCoeff( chksumBytes, treeIndex[0] - params->p1, params->log2w ),
                                                 SEED,
                                                 adrsOts,
                                                 treeIndex[0],
                                                 scratchBuff,
                                                 scratchLen,
                                                 params );
                    treeIndex[0]++;
                }
                if ( SIG_OK != retVal )
                {
                    break;
                }
            }

            if ( SIG_OK == retVal )
            {
                /* At this point our computed leaf value is sitting at the top of the */
                /* stack so copy it to the destination                                */
                memcpy( computedLeaf, &stack[MAX_HASH_LEN*0 + 0], params->n );
            }
        }
    }

    return retVal;
}


/**
 * Generates a signing tree leaf node in a relatively small amount of storage via
 * on-demand generation of otsPk[i] values and a space-efficient tree compression
 * algorithm that utilizes a small stack.  This implementation emulates scratch
 * memory pool and flash-based signature storage.
 *
 * @param[out] computedLeaf Pointer to where result will be written.
 * @param[in]  message      Pointer to where the message we're computing the signature
 *                          verification on is stored.
 * @param[in]  sigOts       Pointer to where the OTS signature is stored.
 * @param[in]  SEED         Pointer to byte array storing the SEED value for this signature.
 * @param[in]  adrsOts      Pointer to uint32_t array storing the ADRS data structure for
 *                          the OTS component of this signature verification.
 * @param[in]  adrsLtree    Pointer to uint32_t array storing the ADRS data structure for
 *                          the Ltree component of this signature verification.
 * @param[in]  params       Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t computeLeaf( uint8_t               *computedLeaf,
                           const uint8_t         *message,
                           const uint8_t         *sigOts,
                           const uint8_t         *SEED,
                           uint32_t              *adrsOts,
                           uint32_t              *adrsLtree,
                           const xmssmt_params_t *params )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( computedLeaf && message && sigOts && SEED && adrsOts && adrsLtree && params )
    {
        /* Stack storage */
        uint8_t stack[STACK_DEPTH][MAX_HASH_LEN];

        /* Tracks where top of stack is, points to first available */
        /* location, and indicates current stack depth             */
        uint8_t stackIdx = 0;

        /* treeIndex[0] = index for pk[i]            */
        /* treeIndex[1] = index for treeHeight = 0   */
        /* ...                                       */
        /* treeIndex[i] = index for treeHeight = i-1 */
        uint8_t treeIndex[STACK_DEPTH + 1] = { 0 };

        /* treeHeight[i] = treeHeight of element stored at stack location i */
        uint8_t treeHeight[STACK_DEPTH] = { 0 };

        /* Compute the checksum and store it for future use (no need to check  */
        /* the return value from otsComputeChecksum as all inputs have already */
        /* been validated at this point so it's guaranteed to return SIG_OK)   */
        uint8_t chksumBytes[params->p2Bytes];
        otsComputeChecksum( chksumBytes, message, params );

        /* Normally we'd push the first two otsPk[i] terms (otsPk[0] and    */
        /* otsPk[1]) onto the stack to initialize things but in this hybrid */
        /* approach we actually generate them on demand                     */

        /* Generate otsPk[0] and push it onto the stack */
        treeHeight[stackIdx] = 0;
        retVal = computeOtsPkI( &stack[stackIdx++][0],
                                sigOts,
                                otsCoeff( message, treeIndex[0], params->log2w ),
                                SEED,
                                adrsOts,
                                treeIndex[0],
                                params );
        /* Have to do the index increment outside of the parameter list as  */
        /* we found the index was incrementing in unexpected ways which led */
        /* to issues.                                                       */
        treeIndex[0]++;

        if ( SIG_OK == retVal )
        {
            /* Generate otsPk[1] and push it onto the stack */
            treeHeight[stackIdx] = 0;
            computeOtsPkI( &stack[stackIdx++][0],
                           sigOts,
                           otsCoeff( message, treeIndex[0], params->log2w ),
                           SEED,
                           adrsOts,
                           treeIndex[0],
                           params );
            treeIndex[0]++;
        }

        if ( SIG_OK == retVal )
        {
            /* Perform L-tree compression until we've processed all of the public key elements */
            /* combining two distinct processing phases:                                       */
            /*    1) While all elements of public key haven't yet been processed               */
            /*    2) While combining all intermediate results to reach final value             */
            while ( ( treeIndex[0] < params->p ) ||
                    ( ( treeIndex[0] >= params->p ) && ( stackIdx > 1 ) ) )
            {
                /* Check if the two top-most elements of the stack have the same tree height,  */
                /* OR check if we've processed all of the public key elements and still have   */
                /* intermediate results on the stack to process to get the final result        */
                if ( ( ( treeIndex[0] <  params->p ) && ( stackIdx >= 2 ) && ( treeHeight[stackIdx - 1] == treeHeight[stackIdx - 2] ) ) ||
                     ( ( treeIndex[0] >= params->p ) && ( stackIdx >  1 ) ) )
                {
                    /* Pop off top two elements, perform RAND_HASH and then push result back onto */
                    /* the stack with updated treeHeight[] and treeIndex[] information            */

                    /* Setup ADRS.treeIndex using treeIndex[i+1], where i is the value stored */
                    /* in the treeHeight[] array for the elements (which should be the same)  */
                    adrsLtree[ADRS_TREE_INDEX]  = (uint32_t) treeIndex[treeHeight[stackIdx - 2] + 1]++;

                    /* Result written to [stackIdx - 2] so its height gets incremented */
                    adrsLtree[ADRS_TREE_HEIGHT] = (uint32_t) treeHeight[stackIdx - 2]++;

                    /* Perform RAND_HASH operation using top elements of the stack */
                    retVal = randHash( &stack[stackIdx - 2][0],
                                       &stack[stackIdx - 2][0],
                                       &stack[stackIdx - 1][0],
                                       SEED,
                                       adrsLtree,
                                       params );

                    /* Update stack index to reflect that we consumed top two elements   */
                    /* and then wrote back result (i.e., net change is one less element) */
                    stackIdx = stackIdx - 1;
                }
                /* Need to generate next element onto the stack (if any still unprocessed) */
                /* where we're still processing elements of the message hash               */
                else if ( treeIndex[0] < params->p1 )
                {
                    treeHeight[stackIdx] = 0;
                    retVal = computeOtsPkI( &stack[stackIdx++][0],
                                            sigOts,
                                            otsCoeff( message, treeIndex[0], params->log2w ),
                                            SEED,
                                            adrsOts,
                                            treeIndex[0],
                                            params );
                    treeIndex[0]++;
                }
                /* Generating next element onto the stack where we're now processing */
                /* elements of the checksum                                          */
                else if ( treeIndex[0] < params->p )
                {
                    treeHeight[stackIdx] = 0;
                    retVal = computeOtsPkI( &stack[stackIdx++][0],
                                            sigOts,
                                            otsCoeff( chksumBytes, treeIndex[0] - params->p1, params->log2w ),
                                            SEED,
                                            adrsOts,
                                            treeIndex[0],
                                            params );
                    treeIndex[0]++;
                }
                if ( SIG_OK != retVal )
                {
                    break;
                }
            }

            if ( SIG_OK == retVal )
            {
                /* At this point our computed leaf value is sitting at the top of the */
                /* stack so copy it to the destination                                */
                memcpy( computedLeaf, &stack[0][0], params->n );
            }
        }
    }

    return retVal;
}


/**
 * Performs tree ascent algorithm defined in Algorithm 13 of the current IETF draft.
 * This implementation emulates scratch memory pool and flash-based signature storage.
 *
 * @param[out] computedRoot Pointer to where result will be written.
 * @param[in]  leaf         Pointer to where the leaf value is stored that we will use to
 *                          ascend the tree.
 * @param[in]  authOffset   Offset in bytes from the start of flash where the XMSS
 *                          signature authentication path data is stored.
 * @param[in]  SEED         Pointer to byte array storing the SEED value for this signature.
 * @param[in]  ADRS         Pointer to uint32_t array storing the ADRS data structure for
 *                          this signature.
 * @param[in]  idx          Leaf node index value.
 * @param[in]  scratchBuff  Pointer to scratch memory that is used to allocate temporary
 *                          data structures.
 * @param[in]  scratchLen   Length in bytes of the scratch memory pool.
 * @param[in]  params       Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t computeRootFlash( uint8_t               *computedRoot,
                                uint8_t               *leaf,
                                uint32_t               authOffset,
                                const uint8_t         *SEED,
                                uint32_t              *ADRS,
                                uint64_t               idx,
                                uint8_t               *scratchBuff,
                                size_t                 scratchLen,
                                const xmssmt_params_t *params )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( computedRoot && leaf && SEED && ADRS && params )
    {
        uint8_t auth[MAX_HASH_LEN];

        /* Initialize the tree index */
        ADRS[ADRS_TREE_INDEX] = idx;

        /* Traverse the tree from leaf to root, using the auth data from the     */
        /* signature and storing our progress in the node vector (randHash only  */
        /* updates the output at the very end so we can use the same vector for  */
        /* both an input and the output)                                         */
        for ( uint32_t i = 0; i < params->h; i++ )
        {
            ADRS[ADRS_TREE_HEIGHT] = i;
            ADRS[ADRS_TREE_INDEX] = ADRS[ADRS_TREE_INDEX] >> 1;
#ifdef C4A_USE_FLASH_CACHE
            retVal = flashcpy_cached( auth, authOffset + i*params->n, params->n );
#else
            retVal = flashcpy( auth, authOffset + i*params->n, params->n );
#endif
            if ( SIG_OK == retVal )
            {
                if ( ( idx >> i ) & 0x1 )
                {
                    retVal = randHashFlash( leaf,
                                            auth,
                                            leaf,
                                            SEED,
                                            ADRS,
                                            scratchBuff,
                                            scratchLen,
                                            params );
                }
                else
                {
                    retVal = randHashFlash( leaf,
                                            leaf,
                                            auth,
                                            SEED,
                                            ADRS,
                                            scratchBuff,
                                            scratchLen,
                                            params );
                }
            }
            if ( SIG_OK != retVal )
            {
                break;
            }
        }

        if ( SIG_OK == retVal )
        {
            /* Root node is stored in leaf so copy it to the destination */
//        memcpy( computedRoot, leaf, params->n );
        }
    }

    return retVal;
}


/**
 * Performs tree ascent algorithm defined in Algorithm 13 of the current IETF draft.
 *
 * @param[out] computedRoot Pointer to where result will be written.
 * @param[in]  leaf         Pointer to where the leaf value is stored that we will use to
 *                          ascend the tree.
 * @param[in]  auth         Pointer to where the XMSS signature authentication path data
 *                          is stored.
 * @param[in]  SEED         Pointer to byte array storing the SEED value for this signature.
 * @param[in]  ADRS         Pointer to uint32_t array storing the ADRS data structure for
 *                          this signature.
 * @param[in]  idx          Leaf node index value.
 * @param[in]  params       Pointer to the XMSS/XMSS-MT parameter data structure
 *
 * @return SIG_OK iff computation completed successfully, relevant error code othewise
 */
sig_retcode_t computeRoot( uint8_t               *computedRoot,
                           uint8_t               *leaf,
                           const uint8_t         *auth,
                           const uint8_t         *SEED,
                           uint32_t              *ADRS,
                           uint64_t               idx,
                           const xmssmt_params_t *params )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( computedRoot && leaf && auth && SEED && ADRS && params )
    {
        /* Initialize the tree index */
        ADRS[ADRS_TREE_INDEX] = idx;

        /* Traverse the tree from leaf to root, using the auth data from the     */
        /* signature and storing our progress in the node vector (randHash only  */
        /* updates the output at the very end so we can use the same vector for  */
        /* both an input and the output)                                         */
        for ( uint32_t i = 0; i < params->h; i++ )
        {
            ADRS[ADRS_TREE_HEIGHT] = i;
            ADRS[ADRS_TREE_INDEX] = ADRS[ADRS_TREE_INDEX] >> 1;
            if ( ( idx >> i ) & 0x1 )
            {
                retVal = randHash( leaf, auth + i*params->n, leaf, SEED, ADRS, params );
            }
            else
            {
                retVal = randHash( leaf, leaf, auth + i*params->n, SEED, ADRS, params );
            }
            if ( SIG_OK != retVal )
            {
                break;
            }
        }

        if ( SIG_OK == retVal )
        {
            /* Root node is stored in leaf so copy it to the destination */
            memcpy( computedRoot, leaf, params->n );
        }
    }

    return retVal;
}


/**
 * Performs XMSS signature verification.  This implementation emulates scratch
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
sig_retcode_t xmssVerifySignatureFlash( const void    *message,
                                        size_t         messageLen,
                                        uint32_t       signatureOffset,
                                        size_t         signatureLen,
                                        const uint8_t *publicKey,
                                        size_t         publicKeyLen,
                                        uint8_t       *scratchBuff,
                                        size_t         scratchLen )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( message && publicKey && scratchBuff )
    {
        uint32_t        oidVal;
        xmssmt_params_t params;

        /* Extract the OID and use it to configure the parameters struct */
        if ( XMSS_OID_LEN > publicKeyLen )
        {
            retVal = SIG_INVALID_XMSS_KEY_LEN;
        }
        else
        {
            oidVal = readOidBytes( publicKey + XMSS_PUB_OID_OFFSET, XMSS_OID_LEN );
            retVal = parseXmssOid( &params, oidVal );
        }

        if ( SIG_OK == retVal )
        {
            /* Perform signature validation which is the same as for XMSS-MT with d = 1, */
            /* which was set during parseXmssOid( )                                      */
            retVal = xmssMtVerifySignatureCoreFlash( message,
                                                     messageLen,
                                                     signatureOffset,
                                                     signatureLen,
                                                     publicKey,
                                                     publicKeyLen,
                                                     scratchBuff,
                                                     scratchLen,
                                                     &params );
        }
    }

    return retVal;
}


/**
 * Performs XMSS signature verification.
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
sig_retcode_t xmssVerifySignature( const void          *message,
                                   size_t               messageLen,
                                   const uint8_t       *signature,
                                   size_t               signatureLen,
                                   const uint8_t       *publicKey,
                                   size_t               publicKeyLen )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( message && signature && publicKey )
    {
        uint32_t        oidVal;
        xmssmt_params_t params;

        /* Extract the OID and use it to configure the parameters struct */
        if ( XMSS_OID_LEN > publicKeyLen )
        {
            retVal = SIG_INVALID_XMSS_KEY_LEN;
        }
        else
        {
            oidVal = readOidBytes( publicKey + XMSS_PUB_OID_OFFSET, XMSS_OID_LEN );
            retVal = parseXmssOid( &params, oidVal );
        }

        if ( SIG_OK == retVal )
        {
            /* Perform signature validation which is the same as for XMSS-MT with d = 1, */
            /* which was set during parseXmssOid( )                                      */
            retVal = xmssMtVerifySignatureCore( message, messageLen, signature, signatureLen, publicKey, publicKeyLen, &params );
        }
    }

    return retVal;
}


/**
 * Performs XMSS-MT signature verification.  This implementation emulates scratch
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
sig_retcode_t xmssMtVerifySignatureFlash( const void    *message,
                                          size_t         messageLen,
                                          uint32_t       signatureOffset,
                                          size_t         signatureLen,
                                          const uint8_t *publicKey,
                                          size_t         publicKeyLen,
                                          uint8_t       *scratchBuff,
                                          size_t         scratchLen )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( message && publicKey && scratchBuff )
    {
        uint32_t        oidVal;
        xmssmt_params_t params;

        /* Extract the OID and use it to configure the parameters struct */
        if ( XMSSMT_OID_LEN > publicKeyLen )
        {
            retVal = SIG_INVALID_XMSS_KEY_LEN;
        }
        else
        {
            oidVal = readOidBytes( publicKey + XMSSMT_PUB_OID_OFFSET, XMSSMT_OID_LEN );
            retVal = parseXmssMtOid( &params, oidVal );
        }

        if ( SIG_OK == retVal )
        {
            /* Perform signature validation */
            retVal = xmssMtVerifySignatureCoreFlash( message,
                                                     messageLen,
                                                     signatureOffset,
                                                     signatureLen,
                                                     publicKey,
                                                     publicKeyLen,
                                                     scratchBuff,
                                                     scratchLen,
                                                     &params );
        }
    }

    return retVal;
}


/**
 * Performs XMSS-MT signature verification.
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
sig_retcode_t xmssMtVerifySignature( const void    *message,
                                     size_t         messageLen,
                                     const uint8_t *signature,
                                     size_t         signatureLen,
                                     const uint8_t *publicKey,
                                     size_t         publicKeyLen )
{
    sig_retcode_t retVal = SIG_INVALID_PARAM;

    /* Validate parameters */
    if ( message && signature && publicKey )
    {
        uint32_t        oidVal;
        xmssmt_params_t params;

        /* Extract the OID and use it to configure the parameters struct */
        if ( XMSSMT_OID_LEN > publicKeyLen )
        {
            retVal = SIG_INVALID_XMSS_KEY_LEN;
        }
        else
        {
            oidVal = readOidBytes( publicKey + XMSSMT_PUB_OID_OFFSET, XMSSMT_OID_LEN );
            retVal = parseXmssMtOid( &params, oidVal );
        }

        if ( SIG_OK == retVal )
        {
            /* Perform signature validation */
            retVal = xmssMtVerifySignatureCore( message, messageLen, signature, signatureLen, publicKey, publicKeyLen, &params );
        }
    }

    return retVal;
}


/**
 * Performs the actual computation related to the XMSS/XMSS-MT signature verification.
 * This implementation emulates scratch memory pool and flash-based signature storage.
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
 * @param[in] params           Pointer to a data structure containing the pertinent
 *                             XMSS/XMSS-MT parameters.
 *
 * @return SIG_OK iff the signature is valid for the given {message, signature, key},
 *         relevant error code othewise
 */
sig_retcode_t xmssMtVerifySignatureCoreFlash( const void      *message,
                                              size_t           messageLen,
                                              uint32_t         signatureOffset,
                                              size_t           signatureLen,
                                              const uint8_t   *publicKey,
                                              size_t           publicKeyLen,
                                              uint8_t         *scratchBuff,
                                              size_t           scratchLen,
                                              xmssmt_params_t *params )
{
    sig_retcode_t  retVal = SIG_OK;
    uint32_t      *adrsOts;
    uint32_t      *adrsLtree;
    uint32_t      *adrsNode;
    uint8_t       *buff;
    uint8_t       *mhash;
    uint8_t       *leaf;
    uint8_t       *root;
    uint8_t       *r;
    uint64_t       idx;
    uint32_t       idxLeaf;
    const uint8_t *SEED;
    uint32_t       adrsSize = sizeof(uint32_t) * ADRS_WORD_COUNT;

    /* Scratch Buffer allocation:                                                         */
    /*    adrsOts[sizeof(uint32_t)*ADRS_WORD_COUNT]                                       */
    /*    adrsLtree[sizeof(uint32_t)*ADRS_WORD_COUNT]                                     */
    /*    adrsNode[sizeof(uint32_t)*ADRS_WORD_COUNT]                                      */
    /*    buff[MAX_HASH_LEN + MAX_IDX_LEN]                                                */
    /*    ... rest is unallocated at this level ...                                       */

    /* No need to validate inputs as this function is only ever called after they have    */
    /* already been validated                                                             */
    if ( ( 3*adrsSize + MAX_HASH_LEN + MAX_IDX_LEN ) > scratchLen )
    {
        retVal = SIG_INSUFFICIENT_MEMORY;
    }
    else
    {
        /* Allocate the scratch buffer memory and update the pointers/lengths */
        memset( scratchBuff, 0, 3*adrsSize );
        adrsOts   = (uint32_t *)scratchBuff;
        adrsLtree = (uint32_t *)(scratchBuff + adrsSize);
        adrsNode  = (uint32_t *)(scratchBuff + 2*adrsSize);
        buff      = scratchBuff + 3*adrsSize;
        mhash = buff;
        leaf  = buff;
        root  = buff;
        r     = buff;
        scratchBuff += 3*adrsSize + MAX_HASH_LEN + MAX_IDX_LEN;
        scratchLen  -= 3*adrsSize + MAX_HASH_LEN + MAX_IDX_LEN;

        /* Verify public key and signature lengths before we begin */
        if ( signatureLen != params->xmssSigLen )
        {
            retVal = SIG_INVALID_XMSSMT_SIG_LEN;
        }
        else if ( publicKeyLen != params->pubKeyLen )
        {
            retVal = SIG_INVALID_XMSSMT_KEY_LEN;
        }
        else
        {
#ifdef C4A_USE_FLASH_CACHE
            retVal = flashcpy_cached( r, signatureOffset, params->idxLen + params->n );
#else
            retVal = flashcpy( r, signatureOffset, params->idxLen + params->n );
#endif
        }

        if ( SIG_OK == retVal )
        {
            /* Verify the signature by computing the message hash, and then walking it back   */
            /* up the tree, one sub-tree at a time (d in all), until we get a root value that */
            /* we can compare to the root value in the XMSS-MT public key.                    */
            /*                                                                                */
            /* XMSS-MT Signature format:                                                      */
            /*   { idx, r, otsSig[0], otsAuth[0], ..., otsSig[d-1], otsAuth[d-1] }            */
            /*                                                                                */
            /* XMSS-MT Public Key format:                                                     */
            /*   { OID, root, seed }                                                          */
            idx = readBigEndian( r, params->idxLen );
            SEED = publicKey + XMSS_PUB_SEED_OFFSET( params->n );

            /* Compute the message hash to kick things off */
            retVal = computeHmsgFlash( mhash,
                                       r + params->idxLen,
                                       publicKey + XMSS_PUB_ROOT_OFFSET,
                                       idx,
                                       message,
                                       messageLen,
                                       scratchBuff,
                                       scratchLen,
                                       params );
        }

        if ( SIG_OK == retVal )
        {
            /* Cheat a bit by advancing the signature pointer to point to the first */
            /* otsSig/otsAuth pair so that we can just iterate through them         */
            signatureOffset += params->idxLen + params->n;

            /* Initialize the address blocks */
            adrsOts[ADRS_TYPE]   = ADRS_TYPE_OTS;
            adrsLtree[ADRS_TYPE] = ADRS_TYPE_LTREE;
            adrsNode[ADRS_TYPE]  = ADRS_TYPE_LEAF;

            /* Walk through the sub-trees starting at 0 and back up to the root */
            for ( int i = 0; i < params->d; i++ )
            {
                idxLeaf = idx & ( ( 1 << params->h ) - 1 );
                idx     = ( idx >> params->h );
                adrsOts[ADRS_LAYER] = adrsLtree[ADRS_LAYER] = adrsNode[ADRS_LAYER] = i;
                adrsOts[ADRS_TREE1] = adrsLtree[ADRS_TREE1] = adrsNode[ADRS_TREE1] = (idx >> 32) & 0xFFFFFFFF;
                adrsOts[ADRS_TREE0] = adrsLtree[ADRS_TREE0] = adrsNode[ADRS_TREE0] = idx & 0xFFFFFFFF;
                adrsOts[ADRS_OTS_ADDR] = adrsLtree[ADRS_LTREE_ADDR] = idxLeaf;
                retVal = computeLeafFlash( leaf,
                                           root,
                                           signatureOffset,
                                           SEED,
                                           adrsOts,
                                           adrsLtree,
                                           scratchBuff,
                                           scratchLen,
                                           params );
                if ( SIG_OK == retVal )
                {
                    retVal = computeRootFlash( root,
                                               leaf,
                                               signatureOffset + params->otsSigLen,
                                               SEED,
                                               adrsNode,
                                               idxLeaf,
                                               scratchBuff,
                                               scratchLen,
                                               params );
                }
                if ( SIG_OK != retVal )
                {
                    break;
                }

                /* Advance the signature pointer to the start of the next sub-tree's */
                /* otsSig and auth data                                              */
                signatureOffset += params->otsSigLen + ( params->h * params->n );
            }
        }

        if ( SIG_OK == retVal )
        {
            /* Check if the computed root matches the value in the public key */
            /* and return true iff they match                                 */
            retVal = ( 0 == memcmp( publicKey + XMSS_PUB_ROOT_OFFSET, root, params->n ) ) ? SIG_OK : SIG_INVALID_SIG;
        }
    }

    return retVal;
}


/**
 * Performs the actual computation related to the XMSS/XMSS-MT signature verification.
 *
 * @param[in] message       Pointer to the message (or fingerprint of the message)
 *                          that the signature corresponds to.
 * @param[in] messageLen    Length in bytes of the message.
 * @param[in] signature     Pointer to the signature that will be verified.
 * @param[in] signatureLen  Length in bytes of the signature.
 * @param[in] publicKey     Pointer to the public key corresponding to the given
 *                          signature.
 * @param[in] publicKeyLen  Length in bytes of the public key.
 * @param[in] params        Pointer to a data structure containing the pertinent
 *                          XMSS/XMSS-MT parameters.
 *
 * @return SIG_OK iff the signature is valid for the given {message, signature, key},
 *         relevant error code othewise
 */
sig_retcode_t xmssMtVerifySignatureCore( const void      *message,
                                         size_t           messageLen,
                                         const uint8_t   *signature,
                                         size_t           signatureLen,
                                         const uint8_t   *publicKey,
                                         size_t           publicKeyLen,
                                         xmssmt_params_t *params )
{
    sig_retcode_t  retVal = SIG_OK;
    uint32_t       adrsOts[ADRS_WORD_COUNT]   = { 0 };
    uint32_t       adrsLtree[ADRS_WORD_COUNT] = { 0 };
    uint32_t       adrsNode[ADRS_WORD_COUNT]  = { 0 };
    uint8_t        mhash[MAX_HASH_LEN];
    uint8_t        leaf[MAX_HASH_LEN];
    uint8_t       *root = mhash;
    uint64_t       idx;
    uint32_t       idxLeaf;
    const uint8_t *SEED;

    /* No need to validate inputs as this function is only ever called after they have    */
    /* already been validated                                                             */
    if ( signatureLen != params->xmssSigLen )
    {
        retVal = SIG_INVALID_XMSSMT_SIG_LEN;
    }
    else if ( publicKeyLen != params->pubKeyLen )
    {
        retVal = SIG_INVALID_XMSSMT_KEY_LEN;
    }

    if ( SIG_OK == retVal )
    {
        /* Verify the signature by computing the message hash, and then walking it back   */
        /* up the tree, one sub-tree at a time (d in all), until we get a root value that */
        /* we can compare to the root value in the XMSS-MT public key.                    */
        /*                                                                                */
        /* XMSS-MT Signature format:                                                      */
        /*   { idx, r, otsSig[0], otsAuth[0], ..., otsSig[d-1], otsAuth[d-1] }            */
        /*                                                                                */
        /* XMSS-MT Public Key format:                                                     */
        /*   { OID, root, seed }                                                          */
        idx = readBigEndian( signature, params->idxLen );
        SEED = publicKey + XMSS_PUB_SEED_OFFSET( params->n );

        /* Compute the message hash to kick things off */
        retVal = computeHmsg( mhash,
                              signature + params->idxLen,
                              publicKey + XMSS_PUB_ROOT_OFFSET,
                              idx,
                              message,
                              messageLen,
                              params );
    }

    if ( SIG_OK == retVal )
    {
        /* Cheat a bit by advancing the signature pointer to point to the first */
        /* otsSig/otsAuth pair so that we can just iterate through them         */
        signature += params->idxLen + params->n;

        /* Initialize the address blocks */
        adrsOts[ADRS_TYPE]   = ADRS_TYPE_OTS;
        adrsLtree[ADRS_TYPE] = ADRS_TYPE_LTREE;
        adrsNode[ADRS_TYPE]  = ADRS_TYPE_LEAF;

        /* Walk through the sub-trees starting at 0 and back up to the root */
        for ( int i = 0; i < params->d; i++ )
        {
            idxLeaf = idx & ( ( 1 << params->h ) - 1 );
            idx     = ( idx >> params->h );
            adrsOts[ADRS_LAYER] = adrsLtree[ADRS_LAYER] = adrsNode[ADRS_LAYER] = i;
            adrsOts[ADRS_TREE1] = adrsLtree[ADRS_TREE1] = adrsNode[ADRS_TREE1] = (idx >> 32) & 0xFFFFFFFF;
            adrsOts[ADRS_TREE0] = adrsLtree[ADRS_TREE0] = adrsNode[ADRS_TREE0] = idx & 0xFFFFFFFF;
            adrsOts[ADRS_OTS_ADDR] = adrsLtree[ADRS_LTREE_ADDR] = idxLeaf;
            retVal = computeLeaf( leaf,
                                  root,
                                  signature,
                                  SEED,
                                  adrsOts,
                                  adrsLtree,
                                  params );
            if ( SIG_OK == retVal )
            {
                retVal = computeRoot( root,
                                      leaf,
                                      signature + params->otsSigLen,
                                      SEED,
                                      adrsNode,
                                      idxLeaf,
                                      params );
            }
            if ( SIG_OK != retVal )
            {
                break;
            }

            /* Advance the signature pointer to the start of the next sub-tree's */
            /* otsSig and auth data                                              */
            signature += params->otsSigLen + ( params->h * params->n );
        }
    }

    if ( SIG_OK == retVal )
    {
        /* Check if the computed root matches the value in the public key */
        /* and return true iff they match                                 */
        retVal = ( 0 == memcmp( publicKey + XMSS_PUB_ROOT_OFFSET, root, params->n ) ) ? SIG_OK : SIG_INVALID_SIG;
    }

    return retVal;
}
