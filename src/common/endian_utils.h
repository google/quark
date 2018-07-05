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

#ifndef _QUARK_ENDIAN_H_
#define _QUARK_ENDIAN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

void writeBigEndian(void* dst, uint64_t value, size_t numBytes);
uint64_t readBigEndian(const void* src, size_t numBytes);
void zeroizeBuffer(void* buff, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _QUARK_ENDIAN_H_ */
