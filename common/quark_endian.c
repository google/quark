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
 *  Description : Endian-swapping related functions
 */

/**
 * @file
 * Endian-swapping related functions
 *
 * Implements the endian-swapping functions for reading/writing big endian
 * formatted data
 */
#include "quark_endian.h"


/**
 * Writes the given number of bytes of the given value to the destination array
 * in big endian format.
 *
 * @param[out] dst       A pointer to the byte array where the big-endian byte
 *                       array will be written.
 * @param[in]  value     A reference to storage for a 64-bit unsigned integer
 *                       to which the parsed value will be stored on success.
 * @param[in]  numBytes  Number of bytes of value that will be writen in big
 *                       endian format to the destination.
 *
 * @return void
 */
void writeBigEndian(void* dst, uint64_t value, size_t numBytes) {
  uint8_t* buff = dst;

  for (int i = numBytes - 1; i >= 0; i--) {
    buff[i] = value & 0xff;
    value >>= 8;
  }
}


/**
 * Reads the given number of bytes from the big endian formatted src byte 
 * array and returns the resulting unsigned value.
 *
 * @param[in] src       A pointer to the byte array where the big-endian byte
 *                      array will be read from.
 * @param[in] numBytes  Number of bytes of src array that will be read to create
 *                      the returned value.
 *
 * @return Value read from the src array
 */
uint64_t readBigEndian(const void* src, size_t numBytes) {
  const uint8_t* buff = src;
  uint64_t retVal = 0;

  for (uint32_t i = 0; i < numBytes; i++) {
    retVal = (retVal << 8) + buff[i];
  }

  return retVal;
}


/**
 * Zeroizes the first len bytes of the buff using a "secure" mechanism
 *
 * @param[out] buff  A pointer to the byte array that will be zeroized.
 * @param[in]  len   Number of bytes of buff that will be zeroized.
 *
 * @return void
 */
void zeroizeBuffer(void* buff, size_t len) {
#if defined( __STDC_LIB_EXT1__ )
  // "New" secure memset that won't be optimized out
  memset_s( buff, len, 0, len );
#else
  // A supposedly platform-independent variant if memset_s doesn't exist
  volatile uint8_t* p = buff;
  while (len--) *p = 0;
#endif
}
